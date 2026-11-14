# shellcheck shell=bash
# The neutral-public-metadata rules, defined once (bash 3.2 / macOS compatible).
#
# Sourced, never executed, by every consumer:
#   - .githooks/pre-push                         commit messages and added diff lines
#   - .githooks/commit-msg                       strips attribution lines before the commit exists
#   - .github/workflows/commit-lint.yml          commit messages, server side
#   - .github/workflows/pr-hygiene.yml           PR title/body, added diff lines, comment bodies
# The rules used to be copied inline into each of them, and the copies drifted apart in both
# directions: one hook clause refused what the gate accepts, another let through what the gate
# refuses. scripts/test-neutral-metadata.sh fails if an inline copy reappears anywhere, and runs
# each consumer against the same corpus.
#
# A consumer must fail closed when this file cannot be read: a missing definition must never make
# a check pass. Source it as
#   . "<path>/scripts/hygiene-patterns.sh" || { echo "hygiene patterns not found" >&2; exit 2; }
#
# This file carries the patterns by design, so it is excluded from the diff scan below.

# This repo's own project code. Its ADR-<code>-… prefix names this project's own public decision
# records, not a leaked reference into someone else's internal space, so it is the one letter-coded
# ADR prefix the rules let through. Every other letter-coded ADR-<code>- prefix stays blocked, and
# this does NOT extend to the bare <code>-<digits> issue-key form: that still names a private
# backlog issue, and citing one in public text is a leak whatever this repo's own code is. Note
# that "IAM-002" is itself a substring of "ADR-IAM-002": has_internal_leak tells the two apart per
# occurrence rather than scanning each pattern separately over the whole text, otherwise an
# own-project ADR reference would trip the issue-key clause on its own tail.
own_project='IAM'

# AI-attribution and agent markers in free text: added diff lines, the PR title and body, comment
# bodies. Matched case-insensitively (grep -iE).
hygiene_ai_text='co-authored-by:[[:space:]]*(claude|anthropic)|claude-session:|claude\.ai/code|generated (with|by) \[?claude|authored (with|by)[^.]*claude|anthropic\.com|🤖'

# AI-attribution trailers in a commit message: commit-lint's gate, the pre-push hook's message
# check and the commit-msg hook's strip. Narrower than the text clause on purpose: a commit body may
# describe, say, an anthropic.com endpoint, and the hook must not refuse what the gate accepts.
# Matched case-insensitively (grep -iE).
hygiene_ai_commit='(co-authored-by:.*(anthropic|claude))|(claude-session:)|(claude\.ai/code)|(generated (with|by) \[claude)'

# The files that carry these patterns by design, so a change to them cannot be scanned for them.
# Pass to git diff after the pathspec: git diff ... -- . "${hygiene_diff_excludes[@]}"
hygiene_diff_excludes=(
  ':(exclude)scripts/hygiene-patterns.sh'
  ':(exclude)scripts/test-neutral-metadata.sh'
  ':(exclude).github/workflows/pr-hygiene.yml'
  ':(exclude).github/workflows/commit-lint.yml'
  ':(exclude).githooks/pre-push'
  ':(exclude).githooks/commit-msg'
  ':(exclude).githooks/pre-commit'
)

# Internal tracker keys are matched by SHAPE, not by a list of project codes: a literal list
# would itself publish the private project codes this gate keeps out of public metadata, and
# would silently miss every project added after it was written.
#   - upper-case KEY-123 / KEY-S4 anywhere outside an http(s) URL
#   - lower-case key-123 only as a path segment (dir/key-123) or a key-123.md file name, so
#     case-insensitive coverage does not flag hyphenated prose such as "non-404" or "top-10"
#   - ADR-<code>-<n> for any <code> but this repo's own (see own_project above)
#   - any *.atlassian.net tenant host
# http(s) URLs (other projects' public trackers; file:// and app links stay scanned), version strings (surefire-3.5.6) and the public
# identifier schemes that share the KEY-123 shape (SHA-256, UTF-8, RFC-7636 …) pass.
public_schemes='ADR|AES|CVE|CWE|ECMA|FIPS|GHSA|HTTP|IEC|IEEE|ISO|JDK|JEP|JSR|NIST|OQ|OWASP|PKCE|PKCS|RFC|SHA|TLS|UTF'
b='(^|[^A-Za-z0-9_-])'
# A token runs to the end of its word, so PKCE-S256 is read whole and then rejected by the
# number/sprint check below; the separator after it stays free to bound the next token.
e='[A-Za-z0-9_]*'
tok_re="${b}ADR-[A-Z][A-Z0-9]+-[0-9]+|${b}[A-Z][A-Z0-9]+-(S[0-9]{1,2}|[0-9]+)(\.[0-9]+)*${e}|[A-Za-z_]/[a-z][a-z0-9]+-(s[0-9]{1,2}|[0-9]+)(\.[0-9]+)*${e}|${b}[a-z][a-z0-9]+-(s[0-9]{1,2}|[0-9]+)\.md"
# has_internal_leak <text> — exit 0 when <text> carries an internal key, 1 when it is neutral.
has_internal_leak() {
  local tok key
  # Here-strings, not printf | grep -q: under pipefail an early-exiting grep can SIGPIPE the
  # writer and turn a match into a pass.
  grep -qiE '[a-z0-9-]+\.atlassian\.net' <<<"$1" && return 0
  while IFS= read -r tok; do
    tok=${tok%.md}
    [[ $tok =~ -[Ss]?[0-9]+\.[0-9] ]] && continue                  # version string
    key=$(printf '%s' "$tok" | sed -E 's#[^A-Za-z0-9]$##; s#^.*[^A-Za-z0-9-]##' | tr '[:lower:]' '[:upper:]')
    # a key ends in a number or a sprint id (S plus one or two digits): PKCE-S256 does not
    [[ $key =~ ^ADR- || $key =~ -(S[0-9]{1,2}|[0-9]+)(\.[0-9]+)*$ ]] || continue
    case "$key" in
      "") continue ;;
      "ADR-${own_project}-"*) continue ;;
      ADR-*-*) return 0 ;;
    esac
    [[ ${key%%-*} =~ ^($public_schemes)$ ]] && continue
    return 0
  done < <(sed -E 's#%2[Ff]#/#g; s#[Hh][Tt][Tt][Pp][Ss]?://[^[:space:]<>()"]*##g' <<<"$1" | grep -oE "$tok_re")
  return 1
}
