# Changelog

## 0.3.0-alpha.15

- The bundled sign-in page is styled again: its CSP named a `style` directive that browsers ignore, so `default-src 'none'` blocked the page's own `<style>`. It now allows exactly that style block by its hash.
- Failed sign-ins and store writes log why, next to the correlation id: each error's name, stable code, OAuth `error` and HTTP status along its cause chain (for example `OidcValidationError OIDC_AZP_MISMATCH`, `ResponseBodyError OAUTH_RESPONSE_BODY_ERROR error=invalid_grant status=400`, `TypeError <- Error ECONNREFUSED`), never error messages, URLs or tokens. A missing client secret is `OIDC_CLIENT_SECRET_UNAVAILABLE`.
- `localPerson` no longer takes a request whose `Host` is the public host name for local, so a route on a same-host proxy that skips the gate can't reach `/api` as the local person. A browser on the DSH host keeps working when it opens DSH by its listen address; the Caddy, Traefik and nginx examples forward the public `Host` and are unaffected. The real-stack acceptance run now sets `localPerson` and checks both sides.
- An `allowedSubjects` entry whose `issuer` isn't exactly the configured `issuer` (a trailing slash, another provider) now stops the plugin at startup instead of silently refusing everyone.
- A logout whose client disconnects mid-body gets an answer instead of a request left waiting.

## 0.3.0-alpha.14

- The Web UI can be installed as an app again behind the gate. Browsers fetch the web app manifest and icons without cookies (WebKit always does for the `apple-touch-icon`), so they got 401 and iPhone's Add to Home Screen and Android's install broke. A GET or HEAD of a path in the new `publicPaths` (`DSH_OIDC_PUBLIC_PATHS`) now needs no session, in both modes. The default is DSH's `/manifest.webmanifest`, the icons it lists and `/apple-touch-icon.png`; entries must be exact static manifest or image file paths outside `/api`, `/plugins`, `/auth`, `/connect` and `/_dsh-oidc`, and `[]` turns it off. With forward-auth, `/auth/check` reads `X-Forwarded-Method` and `X-Forwarded-Uri` from a trusted proxy only; the nginx example now sets them, and the Traefik example trusts loopback forwarded headers on its check hop.
- Breaking: `gatewayPublicPaths` (`DSH_OIDC_GATEWAY_PUBLIC_PATHS`) is gone, with its prefix patterns. `publicPaths` replaces it in both modes, exact paths only, and WebSocket upgrades always need a session. The gateway now fetches public files from DSH without DSH's cookie.
- The Caddy and gateway acceptance runs read the manifest and icons from DSH's real frontend build and expect each to load without cookies, while everything else, a spoofed `X-Forwarded-Uri` included, stays 401.

## 0.3.0-alpha.13

- Add `localPerson` (`DSH_OIDC_LOCAL_PERSON`), unset by default: a request from the DSH host itself (its TCP peer is one of the host's own addresses and it carries no `X-Dsh-Oidc-Client-Ip` header) that has DSH's cookie but no OIDC session passes the `/api` guard and is identified as that person through `requestIdentity` (`provider: 'local'`). Without it such requests stay refused. The gateway now always sets the client address header on what it forwards, so gated traffic is never taken for local.

## 0.3.0-alpha.12

- Add gateway mode (`mode: gateway`, `DSH_OIDC_MODE`): the plugin opens its own listener (`gatewayListen`, optionally with its own TLS certificate) and is the only way into DSH, which moves to loopback; the plugin refuses to start otherwise. Every request and WebSocket upgrade needs a live session except the sign-in routes and `gatewayPublicPaths`. The gateway mints and keeps DSH's own cookie itself, so browsers never get it or the launch token, and it closes a session's WebSockets and event streams when the session signs out, is revoked or expires. `forward-auth` stays the default.
- The acceptance suite gains a run with no proxy at all: Chromium talks to the gateway's own TLS listener in front of a real DSH, checks that every cookieless path and upgrade is refused, signs in, and revokes one browser's session from another to see its WebSocket close.

## 0.3.0-alpha.11

- Add a **Sign-in** page to DSH's Settings: every signed-in session (this device first, then your other sessions, then everyone else's) with the person, browser and system, address, and when it signed in, was last active and expires. Each can be signed out from there, and "Sign out my other sessions" ends the rest of yours. Since everyone signed in is a full DSH owner, anyone can end anyone's session; the page says so. Below that, a read-only summary of the provider, who may sign in, lifetimes and which fields the `DSH_OIDC_*` environment sets, and the recent audit events.
- New owner-only endpoints behind DSH's `/api` admission and the plugin's own session check: `GET /api/dsh-oidc/status`, `GET /api/dsh-oidc/sessions`, `POST /api/dsh-oidc/sessions/revoke` (`{ "id" }` or `{ "others": true }`, JSON, same-origin). The startup check now also wants `ctx.connection.fetch.register`.

## 0.3.0-alpha.10

- `/api` now also wants a live OIDC session: a listener in DSH's `connection/request` hook answers 401 to any `/api` HTTP request without one, so DSH's own 30-day cookie alone (from a browser that signed out, or copied off a device) gets no RPC. On by default; `requireSessionOnApi: false` (`DSH_OIDC_REQUIRE_SESSION_ON_API`) turns it off for API clients that use DSH's token directly.
- Add an audit log of sign-ins, policy denials, sign-outs and revoked sessions, with the client address and User-Agent. Kept 90 days (`auditRetentionDays`) up to 5000 events (`maxAuditEvents`); with `persistSessions` it is stored in `storages/dsh_oidc_audit.json`. Each event is also emitted as the Cordis event `dsh-oidc/audit`.
- Sessions now carry a random public id, their kind, and the client address and User-Agent at sign-in, for the coming sessions list. Records stored by earlier releases keep working and get an id on the first restart.
- Published to npm as `@soffits/dsh-oidc`.

## 0.3.0-alpha.9

- Add the `requestIdentity` service: inside an authenticated `/api` request, `ctx.requestIdentity.current()` returns the person whose OIDC session made it (`{ provider: 'oidc', issuer, id: <sub>, name }`) or `null`, so other plugins can check who is calling their own `/api` routes. The interface is provider-neutral; see [Request identity for other plugins](README.md#request-identity-for-other-plugins).

## 0.3.0-alpha.8

- `senderContext` now only records metadata: the sender on the prompt's `source.principal` and the time DSH admitted it on `source.envelope.sentAt` (Unix ms). The plugin no longer adds its own `oidc-sender` notice line; install [dsh-message-context](https://github.com/soffits/dsh-message-context) to show the model who wrote each message, the same way for every channel. `timeZone` (`DSH_OIDC_TIME_ZONE`) is gone, since the renderer formats times.

## 0.3.0-alpha.7

- The `senderContext` line now says when the prompt was sent: `[Web message from alice (oidc sub ...), sent Mon 2026-03-02 09:41 UTC+01:00]`, taken when DSH admits the prompt, so a model can tell how much time passed between messages. The new `timeZone` (`DSH_OIDC_TIME_ZONE`) sets the zone; without it the browser's reported zone is used, else the process zone. An unknown zone stops the plugin at startup.

## 0.3.0-alpha.6

- With `senderContext`, a Web prompt's source also records its sender as `principal` (`{ kind: 'oidc-user', channel: 'web', id: <sub>, name, issuer }`), so session readers get the sender as data instead of parsing the notice line. The notice and the prompt's text are unchanged.

## 0.3.0-alpha.5

- Add `persistSessions` (`DSH_OIDC_PERSIST_SESSIONS`), off by default: sessions are also kept in DSH's storage (`storages/dsh_oidc_sessions.json`, mode 0600, keyed by the SHA-256 of the cookie value), so a DSH restart no longer signs everyone out. Restored sessions keep the configured absolute and idle limits, logout deletes the record before answering, and a changed issuer, client or allow policy drops every stored session.

## 0.3.0-alpha.4

- Add `senderContext` (`DSH_OIDC_SENDER_CONTEXT`), off by default: each Web prompt reaches the model after a `[Web message from <name> (oidc sub <sub>)]` notice taken from the verified OIDC session of the `/api` request that admitted it. Other channels, scheduled jobs and agent-to-agent messages get none.
- Add nginx (`examples/nginx.conf`) and Traefik (`examples/traefik/`) proxy examples with the same routing and header rules as the Caddyfile. Traefik needs the included local plugin to set the client address header and cannot mark the native cookie `Secure`. Both were tested against a stub DSH; CI still runs only the Caddy example.
- Cache provider discovery and its JWKS in memory: reused for an hour, and kept for up to 24 hours when rediscovery fails, so a provider hiccup no longer fails every login. Without a usable copy sign-in still fails closed.

## 0.3.0-alpha.3

- The project moved to [soffits/dsh-oidc](https://github.com/soffits/dsh-oidc). The package is renamed from `@lumysia/dsh-oidc` to `@soffits/dsh-oidc` and its Cordis row and plugin name from `lumysia-oidc` to `soffits-oidc`; the browser half's CSS classes, style id and locale namespace use the `soffits-` prefix. The old names have no alias. Existing profiles must replace `@lumysia/dsh-oidc` with `@soffits/dsh-oidc` (dependency and `dsh.profile.bundles` entry, installed from the new release tarball `soffits-dsh-oidc-<version>.tgz`) and change any `- id: lumysia-oidc` override in their `cordis.patch.yml` to `- id: soffits-oidc`; an override with the old id matches no row and is skipped. See the deployment guide.

## 0.3.0-alpha.2

- Add `allowAnyUser` (`DSH_OIDC_ALLOW_ANY_USER`) for deployments that restrict access at the provider. Without it an empty policy still refuses to start.
- Ship as a DSH bundle: the package's own `cordis.patch.yml` adds the `lumysia-oidc` row and turns off the startup bearer-URL print, `locale/en.json` and `locale/zh.json` give it a title and description, and `icon.svg` an icon. It shows on the Plugins page with a switch. Profiles must drop their hand-written row and `web-runtime` override (see the deployment guide).
- Read site values from `DSH_OIDC_*` in DSH's environment (`ISSUER`, `CLIENT_ID`, `PUBLIC_ORIGIN`, `CLIENT_SECRET_REF`, `ALLOWED_SUBJECTS`, `ALLOWED_EMAILS`, `ALLOWED_GROUPS`, `TRUSTED_PROXIES`, `DIRECT_LOGIN`). A set variable wins over the row config for that field. Without the required values the plugin refuses to start and registers no route.
- Add the sidebar account button: the signed-in user's picture or initials and name in DSH's `settings.launcher` seat, with Settings and Sign out. It reads the new `GET /_dsh-oidc/session` (display claims and the logout CSRF value for a live same-origin session, guarded by the proxy like the app) and signs out through the existing CSRF-protected POST.
- Keep `email`, `preferred_username` and an HTTPS `picture` from the validated ID token in the in-memory session for that button.
- Remove `examples/cordis.patch.yml`; the bundle layer replaces it.
- Fix: after a real provider's consent page the browser arrived at DSH cross-site, so DSH's `SameSite=Strict` cookie was set but never sent and the user saw "authentication required". The callback now answers with a small same-origin page that continues to DSH's token exchange, making that hop same-site.
- Add `directLogin`: signed-out browser navigations go straight to the provider instead of the bundled sign-in page. Off by default.
- Fix: compare the ID token `iss` with the issuer exactly as configured. A bare-origin issuer such as `https://id.example` was normalized to `https://id.example/` and every login was denied.

## 0.3.0-alpha.0 - Unreleased

First release of the Lumysia/dsh-oidc fork. The OIDC, session, policy, and proxy design from Senti100/dsh-oidc is unchanged.

- Rename the package to `@lumysia/dsh-oidc` and the Cordis plugin to `lumysia-oidc`. Existing profiles must update the `name` and `id` in their patch.
- Support the DSH 0.2 line instead of exactly 0.2.0-rc.2: DSH peers are `>=0.2.1-rc.1 <0.3.0-0`, Cordis `^4.0.5`. Tested with DSH 0.2.1-rc.1 and 0.2.2-rc.1. DSH 0.2.2 refuses plugins whose DSH peers do not match the running release, so the old exact pins no longer load.
- Replace the startup version check with an API check: the plugin refuses to start only when `ctx.effect`, `webServer.register`, `connection.authenticatedUrl`, or `credentials.resolve` is missing, and names it.
- Add `trustedProxies` (IPs or CIDR ranges) for the proxy allowed to set `X-Dsh-Oidc-Client-Ip`. Default stays loopback only. Needed when Caddy reaches DSH from another container.
- Fix the example patch: a DSH patch row replaces the whole config, so `web-runtime: { printUrl: false }` also dropped `openBrowser` and made DSH ignore `--no-open`. The row now restates upstream's config.
- Require Node 24.9 or newer (DSH 0.2.2 requires it).
- Acceptance test installs the newest DSH release with `dsh plugin add` and boots the shipped example patch; CI also runs it weekly.
- Remove the pinned pnpm fixture, override-count checks, the separate public-install and Office scripts, and the 0.2.0-rc.2 seam fixtures; see the PR for reasons.
- Document that sessions are in memory and a DSH restart signs everyone out.

## 0.2.1-alpha.0 - Released

- Add a bundled self-contained sign-in page at `/auth/signin` (strict CSP, inline HTML, no external assets).
- Make `/auth/check` navigation-aware: browser navigations receive `303 -> /auth/signin` (which Caddy's `forward_auth` subrequest copies through verbatim); `fetch`/XHR/WebSocket subrequests keep the plain `401`. This gives human users a real sign-in entry point without any reverse-proxy configuration change.
- Document the sign-in flow and the five-route `/auth` matcher in the README, deployment guide, and shipped `examples/Caddyfile`.
- **Tested with DSH `0.2.0-rc.2`** (the current release): full-profile acceptance against a real DSH `0.2.0-rc.2` Web profile + Caddy 2.10.2 (synthetic OIDC, native-cookie `Secure`, WebSocket, upload), the separate `web-oidc` public-install gate, and a live deployment verified through Caddy 2.11.3 (sign-in redirect, login chain to the provider with PKCE S256, API-client 401 preservation). The compatibility pin to `0.2.0-rc.2` package interfaces is unchanged.

## 0.2.0-alpha.0 - Released

- Isolated exact DSH 0.2.0-rc.2 / Cordis 4.0.4 compatibility candidate with clean locked runtime closure.
- Inspect upstream native-bootstrap, PeerAdmission, API waterfall, and readiness-gated WebSocket changes without replacing the native Connection or weakening the proxy boundary.
- Add mixed-old-peer rejection, real denied-identity and revoked-cookie replay coverage, stronger browser cookie assertions, and isolated TLS listener/trust handling.
- Document pinned clean-home staging and paired application/home rollback; no in-place migration or production/provider change is implied.

## 0.1.0-alpha.0 - Unreleased

- Initial local candidate: provider-neutral OIDC Authorization Code + PKCE admission.
- Host-only exact auth routes with opaque bounded sessions, CSRF logout, exact claim policy, DSH native-cookie bootstrap, and mandatory reverse-proxy gate documentation.
- Exact DSH 0.1.5-rc.1 compatibility pin.
