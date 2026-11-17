import type { AuditEvent } from './audit.js'
import type { ResolvedConfig } from './config.js'
import type { Principal } from './policy.js'
import type { SessionKind, SessionSummary, SessionView } from './state.js'

/** Whoever makes a request: an OIDC session, or the configured local person. */
export interface Actor {
  /** The session's public id; empty for local access, which has no session. */
  readonly id: string
  readonly principal: Principal
}

/**
 * The plugin's own `/api` endpoints for its settings page: who is signed in
 * where, ending sessions, and a read-only summary of the configuration.
 *
 * They are DSH Fetch routes on the shared `/api` channel, so DSH's own
 * admission runs first (Host fence and launch-token cookie, owner Peers only),
 * then this plugin's `/api` guard, and each handler checks the caller's OIDC
 * session again. Every signed-in person is a full DSH owner, so anyone signed
 * in may end anyone's session; that is a convenience, not a privilege line.
 */
export const API_PREFIX = '/api/dsh-oidc'
export const STATUS_PATH = `${API_PREFIX}/status`
export const SESSIONS_PATH = `${API_PREFIX}/sessions`
export const REVOKE_PATH = `${API_PREFIX}/sessions/revoke`

/** How many audit events the status shows. */
export const STATUS_AUDIT_EVENTS = 50

/** The slice of the admission the endpoints use. */
export interface SessionAuthority {
  sessionFromCookie(cookie: string | null | undefined): SessionView | undefined
  listSessions(): SessionSummary[]
  revokeSession(id: string, actor: Actor): Promise<SessionSummary | undefined>
  readonly audit: { recent(limit: number): AuditEvent[] }
}

/** DSH's Fetch route shape (`ConnectionFetchRoute`), reduced to what this module sets. */
export interface FetchRoute {
  readonly path: string
  readonly methods: readonly ('GET' | 'HEAD' | 'POST')[]
  readonly requestBody: 'buffered'
  readonly fetch: (request: Request) => Promise<Response>
}

export interface SessionEntry {
  readonly id: string
  readonly kind: SessionKind
  readonly issuer: string
  readonly subject: string
  readonly name?: string
  readonly email?: string
  readonly userAgent?: string
  readonly ip?: string
  readonly issuedAt: number
  readonly lastUsedAt: number
  readonly expiresAt: number
  /** The session making this request. */
  readonly current: boolean
  /** Same person as the session making this request. */
  readonly mine: boolean
}

export interface StatusView {
  readonly mode: 'forward-auth' | 'gateway'
  readonly issuer: string
  readonly clientId: string
  readonly publicOrigin: string
  readonly policy: {
    readonly subjects: number
    readonly emails: readonly string[]
    readonly groups: readonly string[]
    readonly groupMode: 'any' | 'all'
    readonly requiredClaims: readonly string[]
    readonly anyUser: boolean
  }
  readonly sessionMaxAgeSeconds: number
  readonly sessionIdleTimeoutSeconds: number
  readonly persistSessions: boolean
  readonly requireSessionOnApi: boolean
  readonly senderContext: boolean
  readonly directLogin: boolean
  /** Who a request from this host itself is taken to be, when set. */
  readonly localPerson?: string
  /** `DSH_OIDC_*` variables that set a field; the profile can't change those. */
  readonly environment: readonly string[]
  readonly audit: readonly AuditEvent[]
}

const HEADERS = {
  'cache-control': 'no-store',
  'x-content-type-options': 'nosniff',
} as const

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...HEADERS, 'content-type': 'application/json; charset=utf-8' },
  })
}

function refuse(status: number, message: string): Response {
  return new Response(`${message}\n`, {
    status,
    headers: { ...HEADERS, 'content-type': 'text/plain; charset=utf-8' },
  })
}

/** Browsers mark cross-site requests; refuse those even though DSH's cookie is SameSite=Strict. */
function crossSite(request: Request): boolean {
  const site = request.headers.get('sec-fetch-site')
  return site !== null && site !== 'same-origin'
}

function samePerson(
  a: { issuer: string; subject: string },
  b: { issuer: string; subject: string },
) {
  return a.issuer === b.issuer && a.subject === b.subject
}

/** The sessions list as the caller sees it: their own first, then everyone else's. */
export function sessionEntries(sessions: readonly SessionSummary[], actor: Actor): SessionEntry[] {
  const entries = sessions.map((session): SessionEntry => {
    const { principal } = session
    const name = principal.username ?? principal.displayName ?? principal.email
    return {
      id: session.id,
      kind: session.kind,
      issuer: principal.issuer,
      subject: principal.subject,
      ...(name === undefined ? {} : { name }),
      ...(principal.email === undefined ? {} : { email: principal.email }),
      ...(session.userAgent === undefined ? {} : { userAgent: session.userAgent }),
      ...(session.ip === undefined ? {} : { ip: session.ip }),
      issuedAt: session.issuedAt,
      lastUsedAt: session.lastUsedAt,
      expiresAt: session.expiresAt,
      current: session.id === actor.id,
      mine: samePerson(principal, actor.principal),
    }
  })
  const rank = (entry: SessionEntry) => (entry.current ? 0 : entry.mine ? 1 : 2)
  return entries.sort((a, b) => rank(a) - rank(b) || b.lastUsedAt - a.lastUsedAt)
}

export function statusView(
  config: ResolvedConfig,
  environment: readonly string[],
  audit: readonly AuditEvent[],
  mode: StatusView['mode'] = 'forward-auth',
): StatusView {
  const { policy } = config
  const requiredClaims = [...policy.requiredClaims.keys()].sort()
  return {
    mode,
    issuer: config.issuerId,
    clientId: config.clientId,
    publicOrigin: config.publicOrigin.origin,
    policy: {
      subjects: policy.allowedSubjects.size,
      emails: [...policy.allowedEmails].sort(),
      groups: [...policy.allowedGroups].sort(),
      groupMode: policy.groupMode,
      requiredClaims,
      anyUser:
        policy.allowedSubjects.size === 0 &&
        policy.allowedEmails.size === 0 &&
        policy.allowedGroups.size === 0 &&
        requiredClaims.length === 0,
    },
    sessionMaxAgeSeconds: config.sessionMaxAgeSeconds,
    sessionIdleTimeoutSeconds: config.sessionIdleTimeoutSeconds,
    persistSessions: config.persistSessions,
    requireSessionOnApi: config.requireSessionOnApi,
    senderContext: config.senderContext,
    directLogin: config.directLogin,
    ...(config.localPerson === undefined ? {} : { localPerson: config.localPerson }),
    environment,
    audit,
  }
}

async function revokeBody(
  request: Request,
): Promise<{ id: string } | { others: true } | undefined> {
  const type = request.headers.get('content-type')?.split(';', 1)[0]?.trim().toLowerCase()
  if (type !== 'application/json') return undefined
  const text = await request.text()
  if (text.length > 1024) return undefined
  let body: unknown
  try {
    body = JSON.parse(text)
  } catch {
    return undefined
  }
  if (typeof body !== 'object' || body === null) return undefined
  const { id, others } = body as { id?: unknown; others?: unknown }
  if (others === true && id === undefined) return { others: true }
  if (typeof id === 'string' && /^[A-Za-z0-9_-]{22}$/u.test(id) && others === undefined)
    return { id }
  return undefined
}

/**
 * The Fetch routes; `status` builds the configuration summary on each call and
 * `localActor` names the local person for a request that came from this host.
 */
export function sessionRoutes(
  authority: SessionAuthority,
  status: () => StatusView,
  localActor: () => Actor | undefined = () => undefined,
): readonly FetchRoute[] {
  const actorOf = (request: Request): Actor | undefined =>
    authority.sessionFromCookie(request.headers.get('cookie')) ?? localActor()
  return [
    {
      path: STATUS_PATH,
      methods: ['GET'],
      requestBody: 'buffered',
      fetch: async (request) => {
        if (crossSite(request)) return refuse(403, 'forbidden')
        if (actorOf(request) === undefined) return refuse(401, 'unauthorized')
        return json(status())
      },
    },
    {
      path: SESSIONS_PATH,
      methods: ['GET'],
      requestBody: 'buffered',
      fetch: async (request) => {
        if (crossSite(request)) return refuse(403, 'forbidden')
        const actor = actorOf(request)
        if (actor === undefined) return refuse(401, 'unauthorized')
        return json({ sessions: sessionEntries(authority.listSessions(), actor) })
      },
    },
    {
      path: REVOKE_PATH,
      methods: ['POST'],
      requestBody: 'buffered',
      fetch: async (request) => {
        if (crossSite(request)) return refuse(403, 'forbidden')
        const actor = actorOf(request)
        if (actor === undefined) return refuse(401, 'unauthorized')
        const body = await revokeBody(request)
        if (body === undefined) return refuse(400, 'bad request')
        if ('id' in body) {
          // Ending your own session is signing out, which has its own CSRF-checked route.
          if (body.id === actor.id) return refuse(409, 'use sign out for this session')
          const revoked = await authority.revokeSession(body.id, actor)
          if (revoked === undefined) return refuse(404, 'no such session')
          return json({ revoked: [revoked.id] })
        }
        const targets = authority
          .listSessions()
          .filter(
            (session) => session.id !== actor.id && samePerson(session.principal, actor.principal),
          )
        const revoked: string[] = []
        for (const target of targets) {
          const ended = await authority.revokeSession(target.id, actor)
          if (ended !== undefined) revoked.push(ended.id)
        }
        return json({ revoked })
      },
    },
  ]
}
