import { AsyncLocalStorage } from 'node:async_hooks'
import type { IncomingMessage, ServerResponse } from 'node:http'
import type { Principal } from './policy.js'

/**
 * Request identity: tell other plugins which signed-in person made the
 * current Web request.
 *
 * DSH admits every browser as one shared owner Peer, so a plugin's `/api`
 * Fetch route or RPC handler cannot tell two people apart. This plugin can:
 * `connection/request` wraps every authenticated `/api` request, and the
 * request's own OIDC session names a verified principal. The rest of that
 * request runs inside an AsyncLocalStorage scope holding it, and
 * `ctx.requestIdentity.current()` reads it.
 *
 * The scope closes when the request settles. Work the request merely started
 * (an agent turn, a timer) inherits the store but finds it closed, so the
 * identity never leaks into a turn, a scheduled job or another channel.
 *
 * The service name and shape are provider-neutral: any plugin that verifies
 * who is behind a request can provide `requestIdentity` with the same
 * interface, and consumers need not know which one is installed.
 */

/** The service name under which the identity reader is provided. */
export const REQUEST_IDENTITY_SERVICE = 'requestIdentity'

/** The verified person behind the current request. */
export interface RequestIdentity {
  /** Kind of provider that verified it; `oidc` here. */
  readonly provider: string
  /** Who vouches for `id`: the OIDC issuer here. */
  readonly issuer: string
  /** Stable user id, unique within `issuer`: the OIDC `sub` here. */
  readonly id: string
  /** Display name for attribution only: preferred_username, then name, then email. */
  readonly name?: string
}

/** What `ctx.requestIdentity` offers. */
export interface RequestIdentityService {
  /** The verified person behind the request being handled, or null outside a verified request. */
  current(): RequestIdentity | null
}

declare module '@deepseek-ai/cordis' {
  interface Context {
    requestIdentity: RequestIdentityService
  }
}

/** The event surface this module listens on; a Cordis context satisfies it. */
export interface IdentityEvents {
  on(
    name: 'connection/request',
    listener: (
      request: IncomingMessage,
      response: ServerResponse,
      next: () => Promise<void>,
    ) => Promise<void>,
  ): unknown
}

interface IdentityScope {
  readonly identity: RequestIdentity
  open: boolean
}

/** The identity a verified principal presents to other plugins. */
export function identityOf(principal: Principal): RequestIdentity {
  const name = principal.username ?? principal.displayName ?? principal.email
  return Object.freeze({
    provider: 'oidc',
    issuer: principal.issuer,
    id: principal.subject,
    ...(name === undefined || name === '' ? {} : { name }),
  })
}

/**
 * Wrap every `/api` request that carries a live OIDC session in an identity
 * scope and return the reader. `principalOf` reads the request's own OIDC
 * session and returns undefined for anything else.
 */
export function applyRequestIdentity(
  events: IdentityEvents,
  principalOf: (request: IncomingMessage) => Principal | undefined,
): RequestIdentityService {
  const requests = new AsyncLocalStorage<IdentityScope>()
  events.on('connection/request', async (request, _response, next) => {
    const principal = principalOf(request)
    if (principal === undefined) return next()
    const scope: IdentityScope = { identity: identityOf(principal), open: true }
    try {
      await requests.run(scope, next)
    } finally {
      scope.open = false
    }
  })
  return Object.freeze({
    current(): RequestIdentity | null {
      const scope = requests.getStore()
      return scope?.open === true ? scope.identity : null
    },
  })
}
