#!/usr/bin/env bash
# Regression cases for the neutral-public-metadata rule (bash 3.2 / macOS compatible).
#
# The patterns are defined once, in scripts/hygiene-patterns.sh. This runs the REAL consumers,
# each sourcing that file, not a copy of their patterns:
#   - .githooks/pre-push                       (commit messages + added diff lines)
#   - .githooks/commit-msg                     (strips attribution lines)
#   - commit-lint.yml  "Validate PR commits"   (commit messages, server side)
#   - pr-hygiene.yml   job "hygiene"           (PR title/body + added diff lines)
#   - pr-hygiene.yml   job "comment"           (PR/issue comment bodies; gh is stubbed)
# against throwaway git repos, and asserts that every seeded leak is refused and every clean
# input passes. A gate that cannot fail is the defect this exists to catch. It also fails if an
# inline copy of a pattern reappears anywhere in the tree, or a consumer stops sourcing the file.
#
# The seeded keys are synthetic (ABC-12, …): the rule matches internal keys by shape, so no
# real project code needs to appear here. To check the actual project codes of a private
# tracker locally, without committing them, pass them in the environment:
#   NEUTRAL_METADATA_CODES="ABC DEF" scripts/test-neutral-metadata.sh
#
# Needs python3 with PyYAML (preinstalled on GitHub-hosted Ubuntu runners).
set -uo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
patterns="$root/scripts/hygiene-patterns.sh"
hook="$root/.githooks/pre-push"
commit_msg_hook="$root/.githooks/commit-msg"
commit_lint="$root/.github/workflows/commit-lint.yml"
pr_hygiene="$root/.github/workflows/pr-hygiene.yml"
zero='0000000000000000000000000000000000000000'
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
pass=0
fail=0

# extract <workflow> <job> <step-name> <run|env:NAME> — print a step's run script or one env value.
extract() {
  python3 - "$@" <<'PY'
import sys, yaml
wf, job, step, what = sys.argv[1:5]
for s in yaml.safe_load(open(wf))["jobs"][job]["steps"]:
    if s.get("name") == step:
        print(s["run"] if what == "run" else s["env"][what[4:]], end="")
        sys.exit(0)
sys.exit("step not found: " + step)
PY
}

lint_run="$(extract "$commit_lint" lint 'Validate PR commits' run)" || exit 2
hyg_step='PR text and diff must be neutral (no AI attribution, no internal keys)'
hyg_run="$(extract "$pr_hygiene" hygiene "$hyg_step" run)" || exit 2
com_run="$(extract "$pr_hygiene" comment 'Hide a comment carrying an AI-attribution marker or internal key' run)" || exit 2
# The workflows source the patterns from $GITHUB_WORKSPACE; here that is this checkout.
export GITHUB_WORKSPACE="$root"
own="$(bash -c '. "$1" && printf %s "$own_project"' _ "$patterns")" || exit 2
[ -n "$own" ] || { echo "own_project is empty in $patterns" >&2; exit 2; }

# A throwaway repo whose origin/main is one clean commit; prints its path.
new_repo() {
  local d
  d="$(mktemp -d "$work/repo.XXXXXX")"
  git -C "$d" init -q -b main
  git -C "$d" config user.email dev@example.com
  git -C "$d" config user.name Dev
  echo base > "$d/README"
  git -C "$d" add README
  git -C "$d" commit -q -m 'chore: base'
  git -C "$d" update-ref refs/remotes/origin/main HEAD
  printf '%s' "$d"
}

# commit_on <repo> <message> [<added line>] — one commit on top of main.
commit_on() {
  printf '%s\n' "${3:-clean change}" >> "$1/change.txt"
  git -C "$1" add change.txt
  git -C "$1" commit -q --no-verify -m "$2"
}

# expect <block|pass> <label> <command...> — exit 0 is pass, exit 1 is block, anything else
# (syntax error, missing command) is an error and never counts as a block.
expect() {
  local want="$1" label="$2" got rc
  shift 2
  "$@" >/dev/null 2>&1
  rc=$?
  case "$rc" in 0) got=pass ;; 1) got=block ;; *) got="error($rc)" ;; esac
  if [ "$got" = "$want" ]; then
    pass=$((pass + 1))
  else
    fail=$((fail + 1))
    echo "FAIL: $label — expected $want, got $got" >&2
  fi
}

run_pre_push() {
  local head
  head="$(git -C "$1" rev-parse HEAD)"
  (cd "$1" && printf 'refs/heads/topic %s refs/heads/topic %s\n' "$head" "$zero" | bash "$hook")
}
run_commit_lint() {
  (cd "$1" && BASE="$(git rev-parse origin/main)" HEAD="$(git rev-parse HEAD)" \
    bash -c "$lint_run")
}
run_hygiene() {  # <repo> <title> <body>
  (cd "$1" && TITLE="$2" BODY="$3" BASE="$(git rev-parse origin/main)" HEAD="$(git rev-parse HEAD)" \
    bash -c "$hyg_run")
}
# The comment job never fails the build: it hides the comment through gh. A stub gh records
# the call, so "block" here means "the comment would have been hidden".
run_comment() {
  local stub="$work/stub" log="$work/gh.log"
  mkdir -p "$stub"
  printf '#!/bin/sh\necho "$@" >> "%s"\n' "$log" > "$stub/gh"
  chmod +x "$stub/gh"
  rm -f "$log"
  PATH="$stub:$PATH" BODY="$1" NODE_ID=n HTML_URL=u ISSUE=1 REPO=o/r GH_TOKEN=t \
    bash -c "$com_run" || return 3
  [ -s "$log" ] && return 1
  return 0
}

# Message-surface case: pre-push and commit-lint must agree.
msg_case() {  # <block|pass> <label> <message>
  local r
  r="$(new_repo)"
  commit_on "$r" "$3"
  expect "$1" "pre-push message: $2" run_pre_push "$r"
  expect "$1" "commit-lint message: $2" run_commit_lint "$r"
}
# Text-surface case: PR body, PR title, comment body, and an added diff line.
text_case() {  # <block|pass> <label> <text>
  local r
  r="$(new_repo)"
  commit_on "$r" 'docs: neutral subject' "$3"
  expect "$1" "pr body: $2" run_hygiene "$r" 'docs: neutral title' "$3"
  expect "$1" "pr title: $2" run_hygiene "$(new_repo)" "$3" 'neutral body'
  expect "$1" "comment: $2" run_comment "$3"
  expect "$1" "pre-push diff: $2" run_pre_push "$r"
}

# --- leaks: every surface must refuse ---
for t in \
  'deliver ABC-12 decision record' \
  'closes XYZ9-7' \
  'planned for ABC-S4' \
  'see raw/abc-12.md' \
  'branch chore/abc-12 has it' \
  'abc-12.md was updated' \
  'note at file:///home/dev/notes/raw/ABC-12.md' \
  'app link obsidian://open?file=ABC-12' \
  'app link with an encoded slash obsidian://open?vault=v&file=raw%2FABC-12' \
  'right after an allowlisted token: SHA-256 ABC-12' \
  'after an allowlisted token and a comma: SHA-256,ABC-12' \
  'after a version: TLS-1.3 ABC-12' \
  'after a numbered record: ADR-0001 ABC-12' \
  'a sprint after a standard: ISO-8601 ABC-S4' \
  'one key after another: ABC-12 DEF-3' \
  'per ADR-ABC-003' \
  'tracked at example.atlassian.net' \
  "own code is no exemption: $own-57"; do
  msg_case block "$t" "docs: $t"
  text_case block "$t" "$t"
done
# a revert/merge subject is skipped by the prefix rule but not by the key rule
msg_case block 'revert quoting a key' 'Revert "feat: deliver ABC-12"'

# --- clean: every surface must pass ---
for t in \
  'neutral wording only' \
  "own decision record ADR-$own-004" \
  'numbered record ADR-0001' \
  'SHA-256 thumbprint, UTF-8, RFC-7636, CVE-2024-12345' \
  'bump surefire-3.5.6 and maven-compiler-plugin-3.15.0' \
  'see https://issues.apache.org/jira/browse/SUREFIRE-2000' \
  'non-404 responses, top-10 list, the 429/not-429 split' \
  'base image ubi9/openjdk-21' \
  'PKCE-S256 is the only code challenge method' \
  'see https://tracker.example.org/browse/ABC-12' \
  'character class [A-Z0-9]-[0-9]'; do
  msg_case pass "$t" "docs: $t"
  text_case pass "$t" "$t"
done

# --- a marker early in a large input: the case that exposes a pipe into grep -q under
# pipefail (grep exits on the first match, the writer dies of SIGPIPE, the pipeline reports
# 141 and the match reads as a pass). Small inputs never exercise it.
filler="$work/filler.txt"
i=0
while [ $i -lt 6000 ]; do
  echo "ordinary line $i of a large but neutral change, nothing to see in it"
  i=$((i + 1))
done > "$filler"                                    # ~400 KB on disk
big_body="$(head -c 100000 "$filler")"            # one env string must stay under 128 KiB
for marker in 'Co-Authored-By: Claude <noreply@example.com>' 'deliver ABC-12 first'; do
  r="$(new_repo)"
  { echo "$marker"; cat "$filler"; } > "$r/big.txt"
  git -C "$r" add big.txt
  git -C "$r" commit -q --no-verify -m 'docs: neutral subject'
  expect block "large diff, marker first: $marker" run_hygiene "$r" 'docs: neutral title' 'neutral body'
  expect block "pre-push large diff, marker first: $marker" run_pre_push "$r"
  expect block "large pr body, marker first: $marker" run_hygiene "$(new_repo)" 'docs: neutral title' "$marker"$'\n'"$big_body"
  expect block "large comment, marker first: $marker" run_comment "$marker"$'\n'"$big_body"
done
r="$(new_repo)"
cat "$filler" > "$r/big.txt"
git -C "$r" add big.txt
git -C "$r" commit -q --no-verify -m 'docs: neutral subject'
expect pass 'large neutral diff' run_hygiene "$r" 'docs: neutral title' "$big_body"
expect pass 'pre-push large neutral diff' run_pre_push "$r"

# --- attribution: a commit message is held to commit-lint's clause, a diff to pr-hygiene's.
# The hook used to refuse messages the gate accepts, and to pass a diff marker the gate refuses.
msg_case block 'attribution trailer' 'docs: neutral subject

Co-Authored-By: Claude <noreply@example.com>'
msg_case pass 'a message may describe an endpoint the text clause names' 'docs: call the api.anthropic.com endpoint'
text_case block 'the robot marker' 'made by 🤖'
text_case block 'an endpoint in free text' 'see anthropic.com'

# --- the commit-msg hook strips with commit-lint's clause, from the same file
msg="$work/COMMIT_EDITMSG"
printf 'docs: neutral subject\n\nbody line\n\nCo-Authored-By: Claude <noreply@example.com>\nClaude-Session: x\n' > "$msg"
expect pass 'commit-msg hook accepts a conventional subject' bash "$commit_msg_hook" "$msg"
expect block 'commit-msg hook strips every attribution line' grep -qiE 'co-authored-by|claude-session' "$msg"

# --- a missing patterns file stops the hooks; it must never make a check pass
orphan="$work/orphan"
mkdir -p "$orphan/.githooks"
cp "$hook" "$commit_msg_hook" "$orphan/.githooks/"
r="$(new_repo)"
commit_on "$r" 'docs: deliver ABC-12'
head="$(git -C "$r" rev-parse HEAD)"
(cd "$r" && printf 'refs/heads/topic %s refs/heads/topic %s\n' "$head" "$zero" | bash "$orphan/.githooks/pre-push") >/dev/null 2>&1
rc=$?
expect pass "pre-push without the patterns file exits 2 (got $rc)" test "$rc" = 2
printf 'docs: x\n' > "$msg"
expect block 'commit-msg without the patterns file refuses' bash "$orphan/.githooks/commit-msg" "$msg"

# --- one definition: every consumer sources the file, and no inline copy is left anywhere.
# The needles are split so that this file does not match itself.
for consumer in .githooks/pre-push .githooks/commit-msg; do
  expect pass "$consumer sources the patterns" grep -qF '. "$patterns" ||' "$root/$consumer"
done
for workflow in commit-lint.yml pr-hygiene.yml; do
  n="$(grep -cF '. "$GITHUB_WORKSPACE/scripts/hygiene-patterns.sh" ||' "$root/.github/workflows/$workflow")"
  want=1; [ "$workflow" = pr-hygiene.yml ] && want=2
  expect pass "$workflow sources the patterns in every job that checks ($n of $want)" test "$n" = "$want"
done
inline="$(cd "$root" && git grep -n -I -F \
  -e 'public_schemes''=' -e 'tok_re''=' -e 'has_internal_leak''() {' \
  -e 'co-authored-by:[[:space:]]*''(claude' -e 'co-authored-by:.*''(anthropic' \
  -e 'generated (with|by) \''[' -e '\.atlassian''\.net' -e 'own_project''=' -e 'OWN_PROJECT'':' \
  -- . ':(exclude)scripts/hygiene-patterns.sh' ':(exclude)scripts/test-neutral-metadata.sh' 2>/dev/null)"
[ -z "$inline" ] || printf 'inline copy outside scripts/hygiene-patterns.sh:\n%s\n' "$inline" >&2
expect pass 'no inline copy of a pattern outside scripts/hygiene-patterns.sh' test -z "$inline"

# --- optional: the real project codes of a private tracker, never committed ---
for code in ${NEUTRAL_METADATA_CODES:-}; do
  lower="$(printf '%s' "$code" | tr 'A-Z' 'a-z')"
  msg_case block "code #$((pass + fail)) upper" "docs: deliver $code-1"
  msg_case block "code #$((pass + fail)) lower path" "docs: see raw/$lower-1.md"
  text_case block "code #$((pass + fail)) upper" "deliver $code-1"
done

echo "neutral-metadata: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
