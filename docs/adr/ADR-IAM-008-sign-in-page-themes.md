# ADR-IAM-008 — Themes for the hosted sign-in page: CSS and static assets, chosen per client, shipped as a checked container layer

| Field | Value |
|---|---|
| Status | **Accepted** |
| Date | 2026-11-04 |
| Ratified | 2026-11-04 |
| Relates to | [ADR-IAM-004](ADR-IAM-004-end-user-session-and-consent.md) (session, login page), [ADR-IAM-006](ADR-IAM-006-standalone-provider-for-many-sites-and-agents.md) (many relying parties, hosted sign-in) |

---

## Background

Tessera hosts a server-rendered sign-in page with its own stylesheet and no script. The relying parties that use it want the page to look like their own site, and one deployment can serve many relying parties (ADR-IAM-006 D1).

A theme sits on a page with a password field, so it is a security surface, not a styling feature. CSS alone can leak typed input: a selector that matches a field's value can trigger a request for a remote background image. Script needs no such trick.

Facts the decisions rest on:
- The page's policy is `default-src 'none'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'`, plus `form-action 'self'` and the origin of the validated redirect URI. It has no `font-src` or `img-src`, so a theme's own fonts and images are blocked today.
- The client is known when the page renders, through the pending authorization request. The sign-in form model does not carry a theme yet.
- Row-level security forbids a read of `oauth_client` without a tenant, so nothing can list every client's theme at boot.

A local test supports D1 and D5. It used a page with the fields of the sign-in form, a hostile stylesheet and a logging server on another port. Without a policy, that server received five requests: an `@import`, a remote font, a remote background, a selector on the CSRF value, and a selector that fired once a password was typed. An inline script also ran. Under the policy with `font-src 'self'; img-src 'self'` it received none and the script was blocked, while same-origin fonts and images loaded and the form still posted. This shows the mechanism in Chromium only, and it was not tessera's own page.

## D1 — A theme is CSS and static assets

**Decision.** A theme is a directory holding a stylesheet, fonts and images. The HTML and any script stay tessera's.

**What it means.** A theme changes how the page looks, not what it does. Tessera documents the page's classes as a contract that themes build on.

**Consequences.**
1. A theme can still mislead on its own page, for example by hiding or relabelling a field. It cannot send anything off the origin. A theme is therefore treated as trusted deployment code: reviewed and pinned, not sanitised.
2. A change to the page's classes is a breaking change for themes and is released as one.
3. Theme files are public and readable by anyone, so a theme holds no secrets.

## D2 — The theme is chosen per client, with no deployment default

**Decision.** A client registration names its theme. Tessera reads the name from the registration of the pending request's client, never from a request parameter. A deployment has no default theme.

**What it means.** `oauth_client` gains a nullable theme column, filled at registration. The column falls under the table's existing row-level security.

**Consequences.**
1. No misconfiguration can show one site's look on another site's sign-in page, because a site's theme appears only for clients that name it.
2. First boot does not overwrite existing rows, so an operator sets the theme of an existing client explicitly.
3. A page with no known client, such as the page for an unknown or expired request, is always the neutral page.
4. Today only the operator sets a client's theme, because clients come from first-boot provisioning. A later registration API must not let a tenant name any theme in the image, or a tenant could show another site's look on its own client.

**Why.** A deployment default is the failure this decision avoids: forgetting to set a theme would show the wrong brand on a password page.

## D3 — A client with no theme gets tessera's neutral page by default

**Decision.** What a client gets when it names no theme, or names one the image lacks, is a tessera configuration setting. By default it gets tessera's neutral page.

**What it means.** The neutral page is tessera's own unbranded page, not a site's theme, so it does not reopen D2.

**Consequences.**
1. A client naming a theme the image lacks is found only when the page renders, because nothing can list client themes at boot. The page must still work in that case.

## D4 — A theme reaches the page as a checked layer in the container

**Decision.** Themes arrive in a layer built on top of the tessera image, which is pinned by digest. The layer is built only by the operator's CI, CI checks every theme, and the digest that gets deployed comes from that build.

**What it means.** A theme pack passes these checks before the layer is built:
- Only `.css`, `.woff2`, `.png`, `.webp` and `.avif` files, with no SVG, HTML or JavaScript.
- No remote or `data:` URLs and no `@import` in the CSS.
- No symbolic links and no path that leaves the pack.
- A size budget.
- The pack's name is the name of its directory.
- The base image is pinned by digest.

**Consequences.**
1. Tessera fetches nothing at runtime, and a theme changes only through a new image with a new digest.
2. One more build step sits between a tessera release and a deployment.
3. On a shared instance the layer holds several sites' themes, so whoever operates the instance builds it.
4. The checks hold only if CI is the sole route to the deployed digest. Each operator has to make it so.

## D5 — The sign-in page's policy allows same-origin fonts and images, and stays the second line of defence

**Decision.** The policy of the sign-in pages gains `font-src 'self'; img-src 'self'`. Everything else in it stays as it is. It applies whatever the theme, and CI's checks do not replace it.

**Threat model.**
- **Credentials stolen through CSS:** selectors and font tricks need a request to leave the origin. The policy allows none.
- **Remote assets, server-side request forgery, mixed content:** no remote URL is allowed, and tessera fetches nothing for a theme.
- **Clickjacking:** `frame-ancestors 'none'` does not depend on the theme.
- **Tenant isolation:** themes come from the operator, and a request cannot choose one.
- **Path traversal:** a theme name comes from the registration, is checked against a fixed pattern, and only files inside the pack are served.
- **Malicious theme author:** accepted. The author can mislead on the page but cannot send anything elsewhere.

**Consequences.**
1. The policy stops script from starting, but would not fully contain script that ran. `connect-src` falls back to `'none'`, yet an injected form could post to the client's origin, which `form-action` lists, and the policy does not restrict top-level navigation. That is why D1 keeps script out of a theme and D4 keeps script files out of a pack.
2. A browser extension is out of the server's reach.
3. A real-browser test against tessera's own page keeps these claims true. It covers a hostile theme, an inline and a same-origin script, and the HTML escaping of the transaction id and CSRF token.

## Rejected alternatives

- **Tokens only, with tessera generating the stylesheet.** The smallest surface, but a theme could only look as tessera's CSS allows, and a site's design would have to be built into a public, multi-brand product.
- **Replaceable templates.** The theme would own the password field, the CSRF field and every error state, and each release could break it.
- **One theme per deployment, or named themes with a deployment default.** Both can show one site's look on another site's page.
- **Themes inside the tessera repository.** Puts relying parties' brands into a public product.
- **Mounting themes from a bucket at runtime.** Whoever can write to the bucket changes the password page, nothing is pinned by digest, and startup gains a dependency.
- **Uploading themes through an admin API.** Needs an admin surface and sanitising, and no customer is asking for it.

## Open items

- The D3 setting's name, its other values, and how a misconfiguration is reported.
