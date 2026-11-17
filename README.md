# @soffits/dsh-oidc

Provider-neutral OpenID Connect sign-in for the DeepSeek Harness (DSH) Web profile. It uses Authorization Code + PKCE through `openid-client`, then hands a successful browser to DSH's unchanged native Connection plugin.

This is a maintained fork of [Senti100/dsh-oidc](https://github.com/Senti100/dsh-oidc). Senti100 wrote the original design and code; this fork keeps that design and follows current DSH releases instead of one pinned release. MIT licensed, see [LICENSE](LICENSE).

## Security architecture

This package is a DSH bundle with a Host plugin and a small browser half. The Host plugin registers `/auth/login`, `/auth/callback`, `/auth/check`, `/auth/signin`, `/auth/logout`, the profile read `/_dsh-oidc/session`, and three `/api/dsh-oidc/*` endpoints for its settings page; it does **not** replace or copy `@deepseek-ai/dsh-client-connection`. After validating the ID token and admission policy, it creates a short-lived opaque session (in memory, or also persisted with `persistSessions`) and redirects through `ctx.connection.authenticatedUrl(publicOrigin)` so DSH mints its own native browser cookie.

A reverse proxy is a mandatory part of the security boundary. It must send **only** `/auth/login`, `/auth/callback`, `/auth/check`, `/auth/signin`, and `/auth/logout` directly to DSH, deny unmatched `/auth/*`, and guard **every other path** (root, static assets, `/api`, uploads, SSE/streams, WebSocket upgrades, and `/_dsh-oidc/session`) with `forward_auth /auth/check`, which passes only the app manifest and icons in [`publicPaths`](#installing-as-an-app) without a session. Strip `Connection` and `Upgrade` on the auth-check subrequest only, preserving the application proxy's WebSocket upgrade. Before proxying, Caddy strips browser-supplied authorization, proxy-authorization, identity aliases, and `X-Dsh-Oidc-Client-Ip`, then sets that dedicated header from its connection-observed `{remote_host}`. A stale native DSH cookie is not sufficient after the OIDC session is removed. DSH must be reachable only by the proxy. For a strictly HTTPS-only origin, do not expose HTTP port 80 at the address; an automatic redirect or HSTS cannot protect an already-stored non-`Secure` native cookie before its first HTTP request. The proxy example marks **new** native cookies `Secure`, but cannot repair cookies already stored by a browser. [`examples/nginx.conf`](examples/nginx.conf) and [`examples/traefik/`](examples/traefik/) apply the same rules for nginx and Traefik; Traefik cannot add `Secure`. See the [deployment guide](docs/deployment.md).

### Trusted proxies

The plugin uses `X-Dsh-Oidc-Client-Ip` for the login rate limit. It believes the header only when the TCP peer of the request is listed in `trustedProxies`, and then only if it holds exactly one valid IP; otherwise `/auth/login` answers 403. The default is loopback (`127.0.0.0/8` and `::1`), which fits Caddy on the same host.

When Caddy reaches DSH from another container (for example over a Docker network), set `trustedProxies` to Caddy's address or its network, such as `["172.18.0.0/16"]`. The list replaces the default, so include `127.0.0.0/8` too if loopback callers also need it. Entries are IPv4/IPv6 addresses or CIDR ranges; IPv4-mapped IPv6 peers match their IPv4 entry; `/0` and empty lists are rejected. List only addresses that nothing but your proxy can connect from, and keep the DSH port unreachable from anywhere else, because any peer in the list can choose the address the rate limit sees.

DSH has one process-wide operator. Every admitted user shares the same DSH home, sessions, workspaces, credentials, tools, approvals, and event stream. Groups control admission only; they do not create internal roles or isolation. Run one DSH home/process per user when isolation is required.

### Sidebar account button

In the sidebar's lower slot (`settings.launcher`, which DSH's built-in DeepSeek account menu occupies), the browser half places the signed-in user's name and picture—or initials if the provider supplies no image. It borrows DSH's Menu component, the sidebar row tokens, and collapsed-rail geometry. Since this slot replaces the Settings control that DSH itself provides, its menu retains **Settings** and also includes **Sign out**. It is registered before the DeepSeek account menu, so when both are enabled this is the one displayed. Its labels track the UI language (English and Chinese).

The button reads `GET /_dsh-oidc/session`; that endpoint responds only for a live OIDC session originating from the same origin. From the validated ID token it returns `name`, `username`, `email`, and `picture` (HTTPS only), along with the CSRF value used for logout in that session. Nothing—token, subject, issuer, or group—is sent outside the Host. This route is not among the five paths that the proxy bypasses; therefore the proxy's `forward_auth` protects it in the same way as the application. **Sign out** issues the same CSRF-guarded form POST to `/auth/logout` that the confirmation page relies on. This is a form navigation rather than `fetch`, so the browser includes `Origin` and then follows the provider's end-session redirect.

### Installing as an app

Phones and desktop browsers fetch a web app's manifest and icons without cookies: Chromium and WebKit fetch the manifest that way unless the page opts in with `crossorigin="use-credentials"`, and WebKit always fetches the `apple-touch-icon` that way. Behind a sign-in gate those requests would get 401, so iPhone's **Add to Home Screen** and Android's install end up with no name or icon, or no app at all, and with them web push.

So a GET or HEAD of a path in `publicPaths` needs no session, in both modes. The default is exactly what DSH's index links for this: `/manifest.webmanifest`, the icons it lists (`/icon-192.png`, `/icon-512.png`, `/icon-maskable-512.png`) and `/apple-touch-icon.png`. DSH's manifest holds only the app name, colours and those icon paths. Entries are exact paths, never patterns, and must name a plain `.webmanifest`, `.png`, `.svg`, `.ico` or `.webp` file outside `/api`, `/plugins`, `/auth`, `/connect` and `/_dsh-oidc`; anything else stops the plugin at start. Set `[]` to make nothing public. WebSocket upgrades always need a session, and a service worker such as a notification inbox's stays behind sign-in: the signed-in page registers it with its cookies.

With forward-auth the check reads the original request from the proxy's `X-Forwarded-Method` and `X-Forwarded-Uri`, and only from a peer in `trustedProxies`. Caddy's `forward_auth` and Traefik's `forwardAuth` (with `trustForwardHeader: false`) set both themselves; the nginx example sets them in the check location, and the Traefik example trusts loopback forwarded headers on its check hop so they arrive. A proxy that passes a client's own `X-Forwarded-Uri` through would let that client choose what the check sees, so set these from the proxy, never from the request. In gateway mode the gateway decides on the path it forwards, and fetches public files from DSH without DSH's cookie, as an anonymous browser would.

### Turning it off

A switch for the bundle appears on the **Plugins** page, and its `soffits-oidc` row has a separate one. Disabling either switch unregisters all `/auth/*` routes. `/auth/check` then returns 404 to Caddy's `forward_auth`, which it interprets as denial; as a result, every application path through the proxy answers 404, including stale native cookies: the gate defaults to closed on failure. The real-stack test verifies this. DSH could be reopened only by a reconfigured proxy, something the plugin cannot control. For another sign-in, re-enable it from a shell that runs on the DSH host: either restore `@soffits/dsh-oidc` to `dsh.profile.bundles` in the profile's `package.json`, or delete the `soffits-oidc` `disabled: true` override from the profile's `cordis.patch.yml`; then restart DSH (or allow HMR to pick it up).

## Compatibility

| Plugin                    | DSH                   | Node     |
| ------------------------- | --------------------- | -------- |
| 0.3.x (this fork)         | `>=0.2.1-rc.1 <0.3.0` | `>=24.9` |
| 0.2.x (Senti100/dsh-oidc) | exactly `0.2.0-rc.2`  | 22       |

The DSH peers are a range over the 0.2 line, so new 0.2.x releases work without a new plugin release. DSH checks that range itself when the plugin is installed and at startup. On load the plugin also checks that the DSH APIs it calls exist (`ctx.effect`, `webServer.register`, `connection.authenticatedUrl`, `credentials.resolve`) and refuses to start, naming what is missing, if a release removed or renamed one. CI runs the real-stack acceptance test against the newest DSH release on every push and weekly, so an upstream break shows up as a red build. DSH 0.3 will need a deliberate range bump after that test passes.

## Configuration

Values for the site are supplied by the environment of the DSH process. Any variable that is present with a non-empty value takes precedence over the matching field from the row config: it substitutes for that field instead of merging with it. Consequently, no profile patch is able to broaden a proxy list or an allowlist configured by the environment. Fields left unset by the environment may use the row config as their source. If neither source provides a value, the plugin will not start, no route is registered, and the proxy rejects all traffic.

| Variable                          | Field                 | Format                                                                   |
| --------------------------------- | --------------------- | ------------------------------------------------------------------------ |
| `DSH_OIDC_ISSUER`                 | `issuer`              | URL, required                                                            |
| `DSH_OIDC_CLIENT_ID`              | `clientId`            | string, required                                                         |
| `DSH_OIDC_PUBLIC_ORIGIN`          | `publicOrigin`        | URL, required                                                            |
| `DSH_OIDC_CLIENT_SECRET_REF`      | `clientSecretRef`     | credential reference name; omit for a public PKCE client                 |
| `DSH_OIDC_ALLOWED_SUBJECTS`       | `allowedSubjects`     | JSON array of `{ "issuer", "subject" }`, or of subjects under the issuer |
| `DSH_OIDC_ALLOWED_EMAILS`         | `allowedEmails`       | JSON array of strings                                                    |
| `DSH_OIDC_ALLOWED_GROUPS`         | `allowedGroups`       | JSON array of strings                                                    |
| `DSH_OIDC_TRUSTED_PROXIES`        | `trustedProxies`      | JSON array of IPs or CIDR ranges                                         |
| `DSH_OIDC_DIRECT_LOGIN`           | `directLogin`         | `true` or `false`                                                        |
| `DSH_OIDC_ALLOW_ANY_USER`         | `allowAnyUser`        | `true` or `false`                                                        |
| `DSH_OIDC_SENDER_CONTEXT`         | `senderContext`       | `true` or `false`                                                        |
| `DSH_OIDC_PERSIST_SESSIONS`       | `persistSessions`     | `true` or `false`                                                        |
| `DSH_OIDC_REQUIRE_SESSION_ON_API` | `requireSessionOnApi` | `true` or `false`                                                        |
| `DSH_OIDC_MODE`                   | `mode`                | `forward-auth` (default) or `gateway`                                    |
| `DSH_OIDC_GATEWAY_LISTEN`         | `gatewayListen`       | `host:port` or `[v6]:port`, IP literal                                   |
| `DSH_OIDC_GATEWAY_TLS_CERT`       | `gatewayTlsCertFile`  | PEM file path                                                            |
| `DSH_OIDC_GATEWAY_TLS_KEY`        | `gatewayTlsKeyFile`   | PEM file path                                                            |
| `DSH_OIDC_PUBLIC_PATHS`           | `publicPaths`         | JSON array of exact paths; `[]` makes nothing public                     |
| `DSH_OIDC_LOCAL_PERSON`           | `localPerson`         | a name such as `helper` (letters, digits, `.`, `_`, `-`, `@`)            |

A malformed value stops the plugin with a message naming the variable, never the value. At startup the log names which fields came from the environment.

DSH's Plugins page edits only fields a plugin declares volatile, and this plugin declares none, because a change to any of them must restart the routes. So the page shows the bundle, its switch and the row, but no editable form; there is nothing in the UI that could override an environment value. The remaining fields (session lifetimes, scopes, group mode, required claims and so on) are ordinary row config: add them under `config:` in an override of the `soffits-oidc` row in the profile patch. Extra allow categories there still apply, since categories are ANDed and can only narrow admission.

| Field                                     | Meaning                                                                                                                                                                    |
| ----------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `issuer`                                  | Exact HTTPS issuer identifier used for discovery and token validation.                                                                                                     |
| `clientId`                                | Exact OIDC client identifier.                                                                                                                                              |
| `clientSecretRef`                         | Optional DSH credential reference name. The secret value is resolved for each login/callback/logout operation and is never configuration. Omit for a public client.        |
| `publicOrigin`                            | Fixed HTTPS origin, path `/`; never derived from `Host` or forwarded headers.                                                                                              |
| `allowedSubjects`                         | Exact `{ issuer, subject }` tuples.                                                                                                                                        |
| `allowedEmails`                           | Exact email values as an additional policy category, never identity; admission also requires literal boolean `email_verified: true`.                                       |
| `allowedGroups`                           | Exact case-sensitive values from `groupsClaim`.                                                                                                                            |
| `groupMode`                               | `any` or `all` for configured allowed groups.                                                                                                                              |
| `requiredClaims`                          | Exact allowed values per required claim; categories are ANDed.                                                                                                             |
| `sessionMaxAgeSeconds`                    | Absolute local OIDC-session lifetime (default 8 hours).                                                                                                                    |
| `sessionIdleTimeoutSeconds`               | Idle expiry (default 30 minutes). Provider policy changes do not invalidate an already-issued session before these limits.                                                 |
| `trustedProxies`                          | Socket peers (IPs or CIDR ranges) allowed to set `X-Dsh-Oidc-Client-Ip`. Default `["127.0.0.0/8", "::1"]`. See [Trusted proxies](#trusted-proxies).                        |
| `directLogin`                             | Send signed-out browser navigations straight to the provider instead of the bundled sign-in page (default `false`).                                                        |
| `allowAnyUser`                            | Admit every account the provider signs in, when access is already restricted at the provider (an application group, for example). Default `false`.                         |
| `senderContext`                           | Tell the model who wrote each Web prompt (see [Sender context](#sender-context)). Default `false`.                                                                         |
| `persistSessions`                         | Keep sign-ins and the audit log across DSH restarts (see [Session persistence](#session-persistence)). Default `false`.                                                    |
| `requireSessionOnApi`                     | Refuse `/api` requests that carry DSH's cookie but no live OIDC session (see [The /api guard](#the-api-guard)). Default `true`.                                            |
| `auditRetentionDays`                      | How long audit events are kept (see [Audit log](#audit-log)). Default 90.                                                                                                  |
| `maxAuditEvents`                          | Most audit events kept; the oldest go first. Default 5000.                                                                                                                 |
| `mode`                                    | `forward-auth` (a proxy asks `/auth/check`) or `gateway` (see [Gateway mode](#gateway-mode)). Default `forward-auth`.                                                      |
| `gatewayListen`                           | Address the gateway listens on, such as `0.0.0.0:3080`. Required in gateway mode.                                                                                          |
| `gatewayTlsCertFile`, `gatewayTlsKeyFile` | PEM certificate and key for the gateway to serve HTTPS itself; leave both out behind a TLS proxy.                                                                          |
| `publicPaths`                             | Static files that load without a session, so the Web UI can be installed as an app (see [Installing as an app](#installing-as-an-app)). Default: DSH's manifest and icons. |
| `localPerson`                             | Who a request from this machine itself, without a session, is taken to be (see [Local access](#local-access)). Unset by default, which refuses such requests on `/api`.    |

At least one allow category is mandatory unless `allowAnyUser` is `true`; it cannot be switched on by an empty list or a missing value. Every configured category is ANDed; values within subject, email, and `any` group categories are ORed. Match comparison is byte-exact with no case folding or substring behavior. Explicit empty policy lists are invalid. Group claims must be nonempty bounded arrays of unique nonempty bounded strings; scalar groups always deny. Custom required claims may be one bounded nonempty string or the same bounded unique-string array shape.

### Sender context

DSH treats every signed-in browser as the same owner, so a model has no way to tell two people apart. With `senderContext: true` each prompt typed into the Web UI records the person whose OIDC session sent it, and when, on the prompt's source. The prompt's text is unchanged. To have the model see it, install [dsh-message-context](https://github.com/soffits/dsh-message-context), which shows a line like this before the prompt:

```text
[Web message from alice (oidc sub 0b3c9f4e-...), sent Mon 2026-03-02 09:41 UTC+01:00]
```

The sender goes in `principal`, the field DSH uses for the caller behind a user message, and the time in `envelope.sentAt` (Unix milliseconds, taken when DSH admitted the prompt, so one sent during a running turn keeps its own time):

```json
{
  "principal": {
    "kind": "oidc-user",
    "channel": "web",
    "id": "<sub>",
    "name": "alice",
    "issuer": "https://id.example"
  },
  "envelope": { "sentAt": 1772440872000 }
}
```

The name is `preferred_username`, then `name`, then `email`, with anything that could fake a line removed; the `sub` is the stable part to key on.

`channel` and `id` are the fields to key on; `id` is unique within `issuer`. DSH itself writes `principal` only for callers other than the owner, and every OIDC browser is admitted as the owner, so the field is otherwise empty on Web prompts. It is attribution only: DSH authorizes requests by the connection, never by a message source.

Only the server-side session decides: the plugin looks up its own HttpOnly session cookie on the `/api` request that admits the prompt (DSH's `connection/request` hook) and reads nothing else the browser sends. Prompts from anywhere else (other channel plugins, scheduled jobs, subagents, messages an agent sends to another session) get no sender, including work that a Web request started but that runs after it. This is recognition, not isolation: everyone signed in still shares one DSH. With a renderer installed, the name goes to the session's model provider with the prompt, which is why it is off by default.

### Request identity for other plugins

DSH admits every signed-in browser as the same owner, so a plugin's own `/api` routes can't tell who is calling either. This plugin provides a small `requestIdentity` service for them. Inside any authenticated `/api` request (a Fetch route registered with `ctx.connection.fetch.register`, or an RPC handler on the shared `/api` channel), `current()` returns the person whose OIDC session made the request, or `null`:

```ts
interface RequestIdentityService {
  current(): RequestIdentity | null
}

interface RequestIdentity {
  provider: string // 'oidc'
  issuer: string // the OIDC issuer
  id: string // the OIDC sub, unique within issuer
  name?: string // preferred_username, then name, then email; display only
}
```

```js
ctx.connection.fetch.register({
  path: '/api/example/whoami',
  methods: ['GET'],
  requestBody: 'buffered',
  fetch: async () => {
    const who = ctx.get('requestIdentity')?.current() ?? null
    return Response.json({ id: who?.id ?? null })
  },
})
```

The service is always on; it reads only this plugin's own session cookie, the same check as `senderContext`. It is `null` outside a request, for a request without an OIDC session (an API client with DSH's own token, when the [/api guard](#the-api-guard) is off), and in work a request started that keeps running after the request has settled, such as an agent turn. Routes registered straight on the web server (`ctx.webServer.register`) are outside `/api` and see `null`.

The name and shape aren't tied to OIDC: another sign-in plugin can provide `requestIdentity` with the same interface, so consumers work with whichever one is installed. Read it with `ctx.get('requestIdentity')` at request time rather than injecting it, if your plugin should also work without it.

### Gateway mode

By default (`mode: forward-auth`) the plugin relies on a reverse proxy that asks `/auth/check` before every request. With `mode: gateway` the plugin opens its own listener (`gatewayListen`) and becomes the only way in: DSH's web server moves to loopback, and the plugin refuses to start if it isn't there, so no second door stays open. A proxy in front for TLS is still fine, it just makes no auth decision any more; or give the gateway its own certificate with `gatewayTlsCertFile` and `gatewayTlsKeyFile`.

Every request and WebSocket upgrade passes one check. The sign-in routes are answered by the gateway. GET and HEAD of the [`publicPaths`](#installing-as-an-app) files go through without a session. Everything else, every upgrade included, needs a live session: a signed-out navigation goes to the sign-in page, anything else gets 401, and `/connect` and unknown `/auth/*` paths get 404. The decision and the forwarded request use the same normalized path, so dot segments can't steer one past the other.

Allowed traffic is streamed to DSH's loopback origin with hop-by-hop headers removed and `Host`, `Origin` and `Sec-Fetch-*` kept, since DSH's own checks read them. The gateway trades DSH's launch token for DSH's browser cookie itself, at start and every six hours, adds that cookie to each request it forwards, drops any DSH cookie a client sends, and strips DSH's cookies from responses. Browsers never hold DSH's 30-day credential or see its launch token, so ending a session here is complete: the gateway also tracks each WebSocket and long response by session and closes them when the session signs out, is revoked or expires (checked every minute).

The client address comes from the socket peer, or from `X-Dsh-Oidc-Client-Ip` when the peer is in `trustedProxies`. If the gateway can't start (port taken, DSH won't mint its cookie), nothing answers on its address; recovery is on the host. Forward-auth stays the default for this release.

### Sign-in settings page

The browser half adds a **Sign-in** page to DSH's Settings. It lists every signed-in session, yours first, with the person, browser and system, the address it signed in from, and when it signed in, was last active and expires. Any session but the one you're using can be signed out from there, and **Sign out my other sessions** ends the rest of yours; the session is deleted for good, so its cookie stops working at once. Everyone signed in is a full owner of the same DSH, so anyone can end anyone's session; that's a convenience, not a permission boundary.

Below the list the page shows, read only, the provider, client, who may sign in, session lifetimes, whether `/api` needs a session, which fields come from the `DSH_OIDC_*` environment, and the recent [audit](#audit-log) events. The page reads `GET /api/dsh-oidc/status` and `GET /api/dsh-oidc/sessions` and signs sessions out with `POST /api/dsh-oidc/sessions/revoke`; all three are DSH Fetch routes, so DSH's own admission applies, and each also checks the caller's OIDC session.

### The /api guard

DSH admits `/api` with its own launch-token cookie, which lives 30 days and can't be revoked one browser at a time. With `requireSessionOnApi` (on by default) the plugin also asks for its own live session on every `/api` HTTP request, in DSH's `connection/request` hook, and answers 401 otherwise. So DSH's cookie alone, kept by a browser that signed out or copied off a device, no longer reaches RPC, and signing out or revoking a session cuts it off at once.

The hook covers `/api` HTTP only. The `/api/remote.mux` WebSocket, static assets, `/plugins` and other plugins' routes are outside it and still need the proxy gate in front of DSH. An API client that uses DSH's own token without signing in here is refused too; turn the guard off if you have one.

### Local access

Something on the DSH host itself, such as a browser on the same desktop, can reach DSH with DSH's own cookie and no OIDC session. By default the [/api guard](#the-api-guard) refuses it like anything else without a session. Set `localPerson` (`DSH_OIDC_LOCAL_PERSON`) to a name and such a request is let through and identified as that person: `requestIdentity` returns `{ provider: 'local', issuer: 'local', id: <localPerson> }`, and the Sign-in page works for it.

A request counts as local when its TCP peer is one of the host's own addresses (loopback, or an address of one of its network interfaces) and it has no `X-Dsh-Oidc-Client-Ip` header. A proxy in another container or on another machine connects from its own address and never matches, and the gateway always sets that header on what it forwards. Turn it on only when both hold: every process on the host is trusted with full DSH access (they can read DSH's home anyway), and every way in from outside goes through the sign-in gate. A proxy on the same host that forwards to DSH without forward-auth would make outside requests look local.

### Audit log

The plugin records sign-ins, sign-ins the allow policy refused, sign-outs and revoked sessions: what happened, when, whose session, who acted, the client address and User-Agent at sign-in. Addresses are kept as seen. Events are kept for `auditRetentionDays` (90) up to `maxAuditEvents` (5000); with `persistSessions` they survive restarts in `storages/dsh_oidc_audit.json`, otherwise they live in memory.

Each event is also emitted on the Cordis event `dsh-oidc/audit`, so another plugin can forward it, for example as a notification:

```ts
ctx.on('dsh-oidc/audit', (event) => {
  // { id, at, type: 'sign-in' | 'sign-in-denied' | 'sign-out' | 'session-revoked',
  //   person?: { issuer, subject, name? }, by?: { ... }, session?, ip?, userAgent? }
})
```

### Session persistence

By default sessions live only in process memory, so a DSH restart signs everyone out. With `persistSessions: true` they are also kept in DSH's own storage, in `storages/dsh_oidc_sessions.json` under the DSH home, which DSH writes atomically with mode `0600` in a `0700` directory. The routes register only after the stored sessions are loaded; if the store cannot be opened, nothing registers and the proxy keeps denying.

Each record is keyed by the SHA-256 digest of the 256-bit random cookie value, never the value itself, so a copy of the file cannot be turned into a working cookie. It holds the same display claims as the in-memory session, a random public id used to list and revoke it, the client address and User-Agent at sign-in, the logout CSRF value, its timestamps, and a fingerprint of the issuer, client ID and allow policy. On startup a record is dropped and deleted when that fingerprint differs (so narrowing the policy and restarting still signs out everyone admitted under the old rules), when it is past the absolute or idle limit as currently configured, or when it is beyond `maxSessions` (the most recently used are kept). Logout deletes the record before it answers. The last-use time is written at most once a minute, so after a restart a session can idle out up to a minute early, never late.

See the [deployment guide](docs/deployment.md), the bundle layer [`cordis.patch.yml`](cordis.patch.yml), [`examples/Caddyfile`](examples/Caddyfile), and [`.env.example`](.env.example). Before sign-in, the bare root returns 401 to API clients; a **browser navigation** is redirected to the bundled sign-in page at `/auth/signin`, whose Sign-in button starts OIDC at `/auth/login`. With `directLogin: true` the navigation goes straight to `/auth/login` and the provider instead. The redirect triggers only on `sec-fetch-mode: navigate` (or an HTML-only `Accept` when the header is absent); `fetch`/XHR/WebSocket subrequests keep the plain 401 because Caddy's `forward_auth` subrequest copies no such navigation signals. The page is self-contained inline HTML with a strict CSP and no external assets. The package is on npm as `@soffits/dsh-oidc`; GitHub releases carry the same tarball. The client secret value stays behind `ctx.credentials`; only its reference name is configuration.

## Protocol behavior

- OpenID Connect discovery over HTTPS with redirects rejected and a bounded request timeout. A validated discovery result (with its JWKS cache) is reused for an hour; if rediscovery then fails, the last validated result keeps being used for up to 24 hours, and after that sign-in fails closed. Restart DSH to drop it sooner.
- Authorization Code only, PKCE S256, independent random state/nonce/verifier/transaction/session/CSRF values.
- One-use five-minute transaction with a bound `Secure; HttpOnly; SameSite=Lax; Path=/` cookie.
- ID-token signature, issuer, audience, expiry, nonce, and optional `auth_time` validation by `openid-client`/`oauth4webapi`, followed by an exact `azp === clientId` check whenever `azp` exists and a mandatory `azp` for multi-valued audiences.
- `HEAD /auth/login` is a state-free readiness response: it creates no transaction, cookie, or provider request.
- Opaque hashed server-side sessions; no access token, refresh token, raw ID token, claims, secret, code, state, or nonce is retained in cookies or logs.
- GET logout only renders a confirmation form. POST requires exact Origin and session CSRF before local deletion. RP-initiated logout is optional and provider-advertised.

## Known limits

- **Sessions live in process memory by default.** Every DSH restart (upgrade, crash, host reboot) signs everyone out and fails logins in progress; users simply sign in again. `persistSessions: true` keeps finished sign-ins across restarts (logins in progress still fail). Either way this is a single DSH process: replicas would not share sessions.
- Provider-side account or group changes reach an existing session only at its idle or absolute expiry, or at restart (with `persistSessions`, only when the local allow policy changed too).
- Logout ends the outer session; DSH's native cookie cannot be revoked on its own. The [/api guard](#the-api-guard) stops it at `/api`, but the WebSocket, statics and plugin routes still rely on the proxy gate, which is why it is mandatory.

## Local development

Node 24.9 or newer.

```sh
npm ci
npm run check
```

`npm run check` runs formatting, lint, strict TypeScript, coverage-gated unit tests, build, package-content inspection, and a secret-pattern scan.

`npm run test:acceptance` is the real-stack test. It packs this repository, installs the newest DSH release (or `DSH_OIDC_DSH_VERSION`) in a temporary directory, adds the tarball with `dsh plugin --profile web add`, boots the Web profile with the bundle enabled, an empty profile patch and every site value in `DSH_OIDC_*`, behind the shipped [`examples/Caddyfile`](examples/Caddyfile), and drives Chromium through a synthetic OIDC issuer: denied identities, sign-in, native cookie flags, root, API, upload, WebSocket, logout with stale-cookie replay, the `/api` guard against a bare DSH cookie, the sidebar account button (name, picture, menu, Settings, sign-out), the Sign-in settings page with this device's session, switching the row off failing closed through the proxy, no printed bearer URL, and a loopback-only listener. Set `DSH_OIDC_SCREENSHOT_DIR` to keep light and dark screenshots of the open account menu. It needs a Caddy v2 binary in `DSH_OIDC_CADDY_BIN` and Playwright's Chromium (`npx playwright install chromium`). It uses no live provider, real DSH home, DNS, or credentials.

## Non-goals

This package does not change DSH RPC methods, permissions, model credentials, workspace authorization, per-user ownership, or event delivery. It does not make exposing DSH directly to a network safe. It does not deploy or configure an identity provider, proxy, DNS, or DSH instance.
