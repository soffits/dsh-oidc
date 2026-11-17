import type { IncomingMessage } from 'node:http'
import type { IdentityEvents } from './identity.js'

/**
 * Refuse every authenticated `/api` HTTP request that carries no live OIDC
 * session of this plugin.
 *
 * DSH admits `/api` with its own launch-token cookie, which lives 30 days and
 * cannot be revoked one browser at a time. With this guard that cookie alone,
 * taken from a signed-out browser or copied off a device, no longer reaches
 * RPC: the request also needs the plugin's session, which logout and revoke
 * end at once. It runs in DSH's `connection/request` waterfall, after DSH's
 * own admission and before any `/api` handler, and answers 401 without
 * calling `next`.
 *
 * The waterfall covers `/api` HTTP only, not the `/api/remote.mux`
 * WebSocket, statics or other plugins' routes; those need a gate in front of
 * DSH (a proxy with forward-auth, or gateway mode).
 */
export function applyApiGuard(
  events: IdentityEvents,
  admitted: (request: IncomingMessage) => boolean,
): void {
  events.on('connection/request', async (request, response, next) => {
    if (admitted(request)) return next()
    response.writeHead(401, {
      'cache-control': 'no-store',
      'content-type': 'text/plain; charset=utf-8',
      'x-content-type-options': 'nosniff',
    })
    response.end('unauthorized\n')
  })
}
