/** The Sign-in settings page: provider summary, signed-in sessions with sign-out, recent activity. */
import { useCallback, useEffect, useState } from 'react'
import { Button, Tag } from '@deepseek-ai/dsh-client-ui-primitives'
import type { AccountKey } from './locales.js'
import {
  describeUserAgent,
  fetchSessions,
  fetchStatus,
  formatDuration,
  revokeSessions,
  type AuditEntry,
  type SessionEntry,
  type SignInStatus,
} from './sessions.js'
import { CLASS } from './styles.js'

export interface SignInApi {
  readonly status: () => Promise<SignInStatus>
  readonly sessions: () => Promise<SessionEntry[]>
  readonly revoke: (target: { id: string } | { others: true }) => Promise<string[]>
}

export const defaultApi: SignInApi = {
  status: () => fetchStatus(),
  sessions: () => fetchSessions(),
  revoke: (target) => revokeSessions(target),
}

export interface SignInSectionProps {
  readonly t: (key: AccountKey) => string
  readonly api: SignInApi
}

/** How often the open page refreshes the sessions list. */
export const REFRESH_MILLISECONDS = 30_000

const EVENT_LABEL: Record<string, AccountKey> = {
  'sign-in': 'eventSignIn',
  'sign-in-denied': 'eventSignInDenied',
  'sign-out': 'eventSignOut',
  'session-revoked': 'eventSessionRevoked',
}

function when(at: number): string {
  return new Date(at).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className={CLASS.row}>
      <dt>{label}</dt>
      <dd>{children}</dd>
    </div>
  )
}

function StatusList({ status, t }: { status: SignInStatus; t: SignInSectionProps['t'] }) {
  const { policy } = status
  const yesNo = (value: boolean) => (value ? t('yes') : t('no'))
  return (
    <dl className={CLASS.list}>
      <Row label={t('mode')}>
        {status.mode === 'gateway' ? t('modeGateway') : t('modeForwardAuth')}
      </Row>
      <Row label={t('issuer')}>{status.issuer}</Row>
      <Row label={t('client')}>{status.clientId}</Row>
      <Row label={t('origin')}>{status.publicOrigin}</Row>
      <Row label={t('allowed')}>
        {policy.anyUser ? (
          t('anyUser')
        ) : (
          <ul className={CLASS.plain}>
            {policy.subjects > 0 && (
              <li>
                {t('subjects')}: {policy.subjects}
              </li>
            )}
            {policy.emails.length > 0 && (
              <li>
                {t('emails')}: {policy.emails.join(', ')}
              </li>
            )}
            {policy.groups.length > 0 && (
              <li>
                {t('groups')} ({policy.groupMode === 'all' ? t('groupsAll') : t('groupsAny')}):{' '}
                {policy.groups.join(', ')}
              </li>
            )}
            {policy.requiredClaims.length > 0 && (
              <li>
                {t('claims')}: {policy.requiredClaims.join(', ')}
              </li>
            )}
          </ul>
        )}
      </Row>
      <Row label={t('lifetime')}>{formatDuration(status.sessionMaxAgeSeconds)}</Row>
      <Row label={t('idle')}>{formatDuration(status.sessionIdleTimeoutSeconds)}</Row>
      <Row label={t('persist')}>{yesNo(status.persistSessions)}</Row>
      <Row label={t('apiGuard')}>{yesNo(status.requireSessionOnApi)}</Row>
      <Row label={t('sender')}>{yesNo(status.senderContext)}</Row>
      {status.environment.length > 0 && (
        <Row label={t('environment')}>
          <span className={CLASS.code}>{status.environment.join(', ')}</span>
        </Row>
      )}
    </dl>
  )
}

function SessionRow({
  session,
  t,
  busy,
  onEnd,
}: {
  session: SessionEntry
  t: SignInSectionProps['t']
  busy: boolean
  onEnd: () => void
}) {
  const device = describeUserAgent(session.userAgent) ?? t('unknownDevice')
  return (
    <li className={CLASS.session} data-current={session.current}>
      <div className={CLASS.sessionText}>
        <div className={CLASS.sessionTitle}>
          <span>{session.name ?? session.subject}</span>
          {session.current && <Tag tone="info">{t('thisDevice')}</Tag>}
          {session.kind !== 'browser' && <Tag tone="neutral">{session.kind}</Tag>}
        </div>
        <div className={CLASS.muted}>
          {device}
          {session.ip === undefined ? '' : ` · ${session.ip}`}
        </div>
        <div className={CLASS.muted}>
          {t('signedIn')} {when(session.issuedAt)} · {t('lastActive')} {when(session.lastUsedAt)} ·{' '}
          {t('expires')} {when(session.expiresAt)}
        </div>
      </div>
      {!session.current && (
        <Button variant="outline" size="sm" disabled={busy} onClick={onEnd}>
          {t('end')}
        </Button>
      )}
    </li>
  )
}

function ActivityRow({ event, t }: { event: AuditEntry; t: SignInSectionProps['t'] }) {
  const label = EVENT_LABEL[event.type]
  const who = event.person?.name ?? event.person?.subject
  const by = event.by?.name ?? event.by?.subject
  return (
    <li className={CLASS.event}>
      <span className={CLASS.muted}>{when(event.at)}</span>
      <span>
        {label === undefined ? event.type : t(label)}
        {who === undefined ? '' : ` · ${who}`}
        {by === undefined || by === who ? '' : ` (${t('by')} ${by})`}
      </span>
      {event.ip !== undefined && <span className={CLASS.muted}>{event.ip}</span>}
    </li>
  )
}

export function SignInSection({ t, api }: SignInSectionProps) {
  const [status, setStatus] = useState<SignInStatus | undefined>(undefined)
  const [sessions, setSessions] = useState<SessionEntry[] | undefined>(undefined)
  const [failed, setFailed] = useState(false)
  const [busy, setBusy] = useState(false)
  const [actionFailed, setActionFailed] = useState(false)

  const load = useCallback(async () => {
    try {
      const [nextStatus, nextSessions] = await Promise.all([api.status(), api.sessions()])
      setStatus(nextStatus)
      setSessions(nextSessions)
      setFailed(false)
    } catch {
      setFailed(true)
    }
  }, [api])

  useEffect(() => {
    void load()
    const timer = setInterval(() => void load(), REFRESH_MILLISECONDS)
    return () => {
      clearInterval(timer)
    }
  }, [load])

  const end = async (target: { id: string } | { others: true }) => {
    setBusy(true)
    setActionFailed(false)
    try {
      await api.revoke(target)
    } catch {
      setActionFailed(true)
    }
    await load()
    setBusy(false)
  }

  if (status === undefined || sessions === undefined) {
    return (
      <section className={CLASS.section} data-dsh-oidc-settings="">
        <h2 className={CLASS.heading}>{t('nav')}</h2>
        {failed && (
          <p>
            {t('loadFailed')}{' '}
            <Button variant="ghost" size="sm" onClick={() => void load()}>
              {t('retry')}
            </Button>
          </p>
        )}
      </section>
    )
  }

  const mineElsewhere = sessions.some((session) => session.mine && !session.current)
  return (
    <section className={CLASS.section} data-dsh-oidc-settings="">
      <h2 className={CLASS.heading}>{t('nav')}</h2>

      <h3 className={CLASS.subheading}>{t('sessions')}</h3>
      <p className={CLASS.muted}>{t('sessionsHint')}</p>
      <ul className={CLASS.sessions}>
        {sessions.map((session) => (
          <SessionRow
            key={session.id}
            session={session}
            t={t}
            busy={busy}
            onEnd={() => void end({ id: session.id })}
          />
        ))}
      </ul>
      {mineElsewhere && (
        <Button
          variant="outline"
          size="sm"
          disabled={busy}
          onClick={() => void end({ others: true })}
        >
          {t('endOthers')}
        </Button>
      )}
      {actionFailed && <p role="alert">{t('actionFailed')}</p>}

      <h3 className={CLASS.subheading}>{t('provider')}</h3>
      <p className={CLASS.muted}>{t('readOnly')}</p>
      <StatusList status={status} t={t} />

      <h3 className={CLASS.subheading}>{t('activity')}</h3>
      {status.audit.length === 0 ? (
        <p className={CLASS.muted}>{t('noActivity')}</p>
      ) : (
        <ul className={CLASS.events}>
          {status.audit.map((event) => (
            <ActivityRow key={event.id} event={event} t={t} />
          ))}
        </ul>
      )}
    </section>
  )
}
