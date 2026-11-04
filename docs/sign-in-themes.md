# Sign-in page themes

A theme changes how tessera's hosted sign-in page looks for one client. The decision and its threat model are in [ADR-IAM-008](adr/ADR-IAM-008-sign-in-page-themes.md).

## What a theme is

A theme is a directory named after the theme. Its name uses lower-case letters, digits and hyphens, starts with a letter or digit, and is at most 63 characters.

```
themes/
  acme/
    theme.css        required; the page links this file
    fonts/acme.woff2
    mark.png
```

Only `.css`, `.woff2`, `.png`, `.webp` and `.avif` files are allowed. A link, any other file type, a theme with no `theme.css`, or a directory with an invalid name stops tessera from starting.

Tessera reads the directory once, at boot, and serves the files from memory under `/assets/themes/<name>/`. Refer to a theme's own files with relative URLs, such as `url(fonts/acme.woff2)`.

The page's policy allows styles, fonts and images from tessera's own origin only. Remote URLs and `data:` URLs do not load, and nothing runs script.

## Turning a theme on

1. Set `TESSERA_SIGNIN_THEMES_DIRECTORY` to the directory holding the themes.
2. Name the theme on the client's registration, in `oauth_client.sign_in_theme`. First-boot provisioning sets it from `TESSERA_BOOTSTRAP_CLIENT_SIGN_IN_THEME`, only when it creates the row. For an existing client, update the row.

A request cannot choose a theme, and a deployment has no default theme.

## A client with no theme

`TESSERA_SIGNIN_THEMES_UNTHEMED` decides what a client gets when it names no theme, or names one the directory lacks:

| Value | Result |
|---|---|
| `neutral` (default) | Tessera's own unbranded page |
| `refuse` | No form: the page says sign-in is unavailable and answers `503` |

Client registrations cannot be read at boot, so a missing theme is found when a page renders. Tessera logs a warning naming the theme, once per theme name per instance.

## The contract a theme builds on

`theme.css` loads after tessera's neutral stylesheet, so it can override any rule there. These are stable, and a change to them is a breaking change:

| Selector | What it is |
|---|---|
| `body` | The page background; put a backdrop image here |
| `main` | The card holding the form |
| `h1` | The heading |
| `.error` | The message after a failed sign-in, shown with `role="alert"` |
| `form` | The form |
| `label`, `input` | The fields; `#username` and `#password` name each one |
| `button` | The submit button |

The neutral stylesheet's custom properties can also be overridden on `:root`: `--bg`, `--card`, `--text`, `--muted`, `--border`, `--accent`, `--accent-text` and `--error`. It sets `color-scheme: light dark` and different values under `prefers-color-scheme: dark`, so a theme that sets colours should cover both.

A theme can hide or relabel what the page shows. It is reviewed and pinned like code, not sanitised.
