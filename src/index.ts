import type { IncomingMessage } from 'node:http'
import type { Context } from '@deepseek-ai/cordis'
import type {} from '@deepseek-ai/dsh-client-connection'
import type {} from '@deepseek-ai/dsh-credentials'
import type { WebRoute } from '@deepseek-ai/dsh-host-webserver'
import { readFileSync } from 'node:fs'
import { OidcAdmission, clientAddress, setGatewayClientIp, wantsNavigation } from './admission.js'
import { Gateway, isLoopback } from './gateway.js'
import { applyApiGuard } from './api-guard.js'
import { AUDIT_EVENT, AUDIT_TABLE, AuditLog, auditDomain, type AuditTable } from './audit.js'
import { RuntimeCompatibilityError, assertRuntimeCompatibility } from './compatibility.js'
import { Config, resolveConfig, type Config as OidcConfig, type ResolvedConfig } from './config.js'
import { ENVIRONMENT_FIELDS, applyEnvironment, readEnvironment } from './env.js'
import { STATUS_AUDIT_EVENTS, sessionRoutes, statusView } from './sessions-api.js'
import { OpenIdClientProtocol } from './oidc.js'
import {
  SESSION_TABLE,
  policyFingerprint,
  sessionDomain,
  type SessionDomainFacility,
} from './persistence.js'
import { REQUEST_IDENTITY_SERVICE, applyRequestIdentity } from './identity.js'
import { applySenderContext } from './sender.js'
import type { SessionPersistence } from './state.js'

export { Config }
export type { OidcConfig as ConfigType }
export { authorizeClaims, type Principal } from './policy.js'
export { resolveConfig } from './config.js'
export { SESSION_DOMAIN, parsePersistedSession, policyFingerprint } from './persistence.js'
export { ENVIRONMENT_FIELDS, applyEnvironment, readEnvironment } from './env.js'
export { REQUIRED_SEAMS, RuntimeCompatibilityError } from './compatibility.js'
export { senderOf, senderPrincipal } from './sender.js'
export {
  AUDIT_DOMAIN,
  AUDIT_EVENT,
  AUDIT_TYPES,
  parseAuditEvent,
  type AuditEvent,
  type AuditPerson,
  type AuditType,
} from './audit.js'
export { applyApiGuard } from './api-guard.js'
export {
  REQUEST_IDENTITY_SERVICE,
  applyRequestIdentity,
  identityOf,
  type RequestIdentity,
  type RequestIdentityService,
} from './identity.js'
export const name = 'soffits-oidc'
export const inject = ['webServer', 'connection', 'credentials']

/** Same-origin profile read for the sidebar account button; guarded by the proxy like the app. */
export const SESSION_PATH = '/_dsh-oidc/session'

/**
 * Register Host-only OIDC routes alongside the unchanged native Connection plugin.
 * DSH_OIDC_* environment values win over the row config field by field; an
 * incomplete or invalid result throws, so no route registers and the proxy's
 * `/auth/check` subrequest fails closed.
 */
export async function apply(ctx: Context, rawConfig: OidcConfig | undefined): Promise<void> {
  const rowConfig = rawConfig ?? {}
  const environment = readEnvironment(process.env, rowConfig)
  const config = resolveConfig(applyEnvironment(rowConfig, environment))
  if (environment.fields.length > 0)
    ctx.logger.info(`dsh-oidc: from environment: ${environment.fields.join(', ')}`)
  assertRuntimeCompatibility(ctx)
  if (config.mode === 'gateway') assertGatewayHost(ctx)
  const pinned = Object.entries(ENVIRONMENT_FIELDS)
    .filter(([, field]) => environment.fields.includes(field))
    .map(([variable]) => variable)
  if (!config.persistSessions) {
    await serve(ctx, config, pinned)
    return
  }
  // Routes register only once the stored sessions are loaded, so until then
  // the proxy's `/auth/check` subrequest fails closed.
  ctx.inject(['storageDomain'], async (sub) => {
    const facility = member(sub, 'storageDomain') as SessionDomainFacility | undefined
    if (typeof member(facility, 'open') !== 'function')
      throw new RuntimeCompatibilityError([
        'ctx.storageDomain.open() (persistSessions session store)',
      ])
    const domain = await facility!.open(sessionDomain)
    sub.effect(() => () => domain.close(), 'dsh-oidc: session store')
    const audit = await facility!.open(auditDomain)
    sub.effect(() => () => audit.close(), 'dsh-oidc: audit store')
    await serve(
      sub,
      config,
      pinned,
      {
        table: domain.table(SESSION_TABLE),
        policy: policyFingerprint(config),
        onError: () => sub.logger.warn('dsh-oidc: session store write failed'),
      },
      audit.table(AUDIT_TABLE),
    )
  })
}

/**
 * Gateway mode is only a gate when it is the only way in, so DSH's own
 * listener must be on loopback; refuse to start otherwise.
 */
function assertGatewayHost(ctx: Context): void {
  if (typeof ctx.webServer.getOrigin !== 'function')
    throw new RuntimeCompatibilityError(['ctx.webServer.getOrigin() (gateway upstream)'])
  if (!isLoopback(ctx.webServer.host))
    throw new Error(
      `dsh-oidc: mode gateway needs DSH's web server on loopback (--host 127.0.0.1), not ${JSON.stringify(ctx.webServer.host)}, or a second door stays open`,
    )
}

function member(target: unknown, key: string): unknown {
  return typeof target === 'object' && target !== null
    ? (target as Record<string, unknown>)[key]
    : undefined
}

/**
 * Build the admission, load any persisted sessions, then register its routes,
 * the `requestIdentity` service and (when enabled) the sender metadata on `ctx`.
 */
async function serve(
  ctx: Context,
  config: ResolvedConfig,
  pinned: readonly string[],
  persistence?: SessionPersistence,
  auditTable?: AuditTable,
): Promise<void> {
  const audit = new AuditLog({
    retentionMilliseconds: config.auditRetentionDays * 86_400_000,
    maxEvents: config.maxAuditEvents,
    ...(auditTable === undefined ? {} : { table: auditTable }),
    onError: () => ctx.logger.warn('dsh-oidc: audit log write failed'),
    emit: (event) => {
      ctx.emit(AUDIT_EVENT, event)
    },
  })
  const admission = new OidcAdmission(
    config,
    ctx.credentials,
    ctx.connection,
    new OpenIdClientProtocol(config),
    ctx.logger,
    persistence,
    audit,
  )
  if (auditTable !== undefined) await audit.restore()
  if (persistence !== undefined) {
    const restored = await admission.restoreSessions()
    ctx.logger.info(`dsh-oidc: restored ${String(restored)} persisted session(s)`)
  }
  const routes: readonly WebRoute[] = [
    { kind: 'exact', path: '/auth/login', handler: (req, res) => admission.login(req, res) },
    { kind: 'exact', path: '/auth/callback', handler: (req, res) => admission.callback(req, res) },
    { kind: 'exact', path: '/auth/check', handler: (req, res) => admission.check(req, res) },
    {
      kind: 'exact',
      path: '/auth/signin',
      handler: (req, res) => admission.signin(req, res),
    },
    { kind: 'exact', path: SESSION_PATH, handler: (req, res) => admission.session(req, res) },
    {
      kind: 'exact',
      path: '/auth/logout',
      handler: (req, res) =>
        req.method === 'POST' ? admission.logout(req, res) : admission.logoutConfirmation(req, res),
    },
  ]
  for (const route of routes)
    ctx.effect(() => ctx.webServer.register(route), `dsh-oidc: ${route.path}`)
  if (config.gateway !== undefined) {
    const gatewayConfig = config.gateway
    const tls =
      gatewayConfig.tls === undefined
        ? undefined
        : {
            cert: readFileSync(gatewayConfig.tls.certFile),
            key: readFileSync(gatewayConfig.tls.keyFile),
          }
    const gateway = new Gateway(
      gatewayConfig,
      {
        routes: new Map(routes.map((route) => [route.path, route.handler])),
        session: (req) => admission.currentSession(req),
        signInPath: config.directLogin ? '/auth/login?nav=1' : '/auth/signin',
        wantsNavigation,
        clientIp: (req) => clientAddress(req, config.trustedProxies, true),
        markClientIp: setGatewayClientIp,
        onSessionEnd: (listener) => admission.sessions.onEnd(listener),
        sweep: () => {
          admission.sessions.sweep()
        },
        upstream: () => new URL(ctx.webServer.getOrigin()),
        authenticatedUrl: (base) => ctx.connection.authenticatedUrl(base),
        publicHost: config.publicOrigin.host,
      },
      ctx.logger,
      tls,
    )
    ctx.effect(() => {
      const state = { stopped: false }
      void (async () => {
        // DSH's own listener binds after plugins load; wait for it.
        for (let attempt = 0; !state.stopped; attempt += 1) {
          try {
            ctx.webServer.getOrigin()
            break
          } catch {
            await new Promise((resolve) => setTimeout(resolve, Math.min(2_000, 50 * 2 ** attempt)))
          }
        }
        if (state.stopped) return
        try {
          await gateway.start()
        } catch (error) {
          ctx.logger.warn(
            `dsh-oidc: gateway did not start, so nothing answers on its address: ${error instanceof Error ? error.message : String(error)}`,
          )
        }
      })()
      return () => {
        state.stopped = true
        void gateway.stop()
      }
    }, 'dsh-oidc: gateway listener')
  }
  const status = () =>
    statusView(config, pinned, admission.audit.recent(STATUS_AUDIT_EVENTS), config.mode)
  for (const route of sessionRoutes(admission, status))
    ctx.effect(() => ctx.connection.fetch.register(route), `dsh-oidc: ${route.path}`)
  const principalOf = (req: IncomingMessage) => admission.principalOf(req)
  if (config.requireSessionOnApi)
    applyApiGuard(ctx, (req) => admission.currentSession(req) !== undefined)
  ctx.provide(REQUEST_IDENTITY_SERVICE, applyRequestIdentity(ctx, principalOf))
  if (config.senderContext) applySenderContext(ctx, principalOf)
}
