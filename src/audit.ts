import { randomBytes } from 'node:crypto'
import { isIP } from 'node:net'
import { MAX_USER_AGENT } from './state.js'

/**
 * Security audit trail: sign-ins, policy denials, sign-outs and revocations,
 * with who, when, from where and which session. Every event is also emitted
 * as the `dsh-oidc/audit` Cordis event so another plugin can turn it into a
 * notification.
 */
export const AUDIT_EVENT = 'dsh-oidc/audit'

export const AUDIT_TYPES = ['sign-in', 'sign-in-denied', 'sign-out', 'session-revoked'] as const

export type AuditType = (typeof AUDIT_TYPES)[number]

/** A person named in an event. */
export interface AuditPerson {
  readonly issuer: string
  readonly subject: string
  readonly name?: string
}

export interface AuditEvent {
  /** Sortable unique key: time, then random. */
  readonly id: string
  /** Unix milliseconds. */
  readonly at: number
  readonly type: AuditType
  /** Whose session or sign-in the event is about. */
  readonly person?: AuditPerson
  /** Who acted, when it is someone else (a revoke from another session). */
  readonly by?: AuditPerson
  /** Public id of the session involved. */
  readonly session?: string
  readonly ip?: string
  readonly userAgent?: string
}

export type AuditInput = Omit<AuditEvent, 'id' | 'at'>

declare module '@deepseek-ai/cordis' {
  interface Events {
    /**
     * A security event was recorded: sign-in, policy denial, sign-out or a
     * revoked session.
     */
    'dsh-oidc/audit'(event: AuditEvent): void
  }
}

/** The slice of a DSH storage-domain table the audit log uses. */
export interface AuditTable {
  entries(): Iterable<[string, AuditEvent]>
  put(key: string, value: AuditEvent): Promise<void>
  delete(key: string): Promise<boolean>
}

export interface AuditOptions {
  readonly retentionMilliseconds: number
  readonly maxEvents: number
  /** Durable store; without one the log lives in memory until restart. */
  readonly table?: AuditTable
  readonly onError: (error: unknown) => void
  /** Called with every new event, after it is in memory. */
  readonly emit: (event: AuditEvent) => void
}

const KEY = /^[0-9a-z]{9}-[A-Za-z0-9_-]{8}$/u

function key(at: number): string {
  return `${at.toString(36).padStart(9, '0')}-${randomBytes(6).toString('base64url')}`
}

export class AuditLog {
  /** Oldest first. */
  private events: AuditEvent[] = []

  constructor(private readonly options: AuditOptions) {}

  /** Load the durable log, dropping events past retention or the cap. */
  async restore(now = Date.now()): Promise<number> {
    const table = this.options.table
    if (table === undefined) return 0
    const loaded: AuditEvent[] = []
    const malformed: string[] = []
    for (const [id, event] of table.entries())
      if (KEY.test(id) && event.id === id) loaded.push(event)
      else malformed.push(id)
    this.events = loaded.sort((a, b) => (a.id < b.id ? -1 : 1))
    await this.prune(now, malformed)
    return this.events.length
  }

  record(input: AuditInput, now = Date.now()): AuditEvent {
    const event = Object.freeze({ id: key(now), at: now, ...clean(input) })
    this.events.push(event)
    void this.persist(event, now)
    try {
      this.options.emit(event)
    } catch (error) {
      this.options.onError(error)
    }
    return event
  }

  /** Newest first. */
  recent(limit: number): AuditEvent[] {
    return this.events.slice(-Math.max(0, limit)).reverse()
  }

  get size(): number {
    return this.events.length
  }

  private async persist(event: AuditEvent, now: number): Promise<void> {
    const table = this.options.table
    try {
      await table?.put(event.id, event)
    } catch (error) {
      this.options.onError(error)
    }
    await this.prune(now)
  }

  private async prune(now: number, extra: readonly string[] = []): Promise<void> {
    const cutoff = now - this.options.retentionMilliseconds
    let drop = 0
    while (
      drop < this.events.length &&
      (this.events[drop]!.at < cutoff || this.events.length - drop > this.options.maxEvents)
    )
      drop += 1
    const dropped = this.events.slice(0, drop).map(({ id }) => id)
    this.events = this.events.slice(drop)
    const table = this.options.table
    if (table === undefined) return
    for (const id of [...dropped, ...extra]) {
      try {
        await table.delete(id)
      } catch (error) {
        this.options.onError(error)
      }
    }
  }
}

function clean(input: AuditInput): AuditInput {
  const userAgent = input.userAgent?.slice(0, MAX_USER_AGENT)
  return {
    type: input.type,
    ...(input.person === undefined ? {} : { person: person(input.person) }),
    ...(input.by === undefined ? {} : { by: person(input.by) }),
    ...(input.session === undefined ? {} : { session: input.session }),
    ...(input.ip === undefined ? {} : { ip: input.ip }),
    ...(userAgent === undefined || userAgent === '' ? {} : { userAgent }),
  }
}

function person(value: AuditPerson): AuditPerson {
  return {
    issuer: value.issuer,
    subject: value.subject,
    ...(value.name === undefined ? {} : { name: value.name }),
  }
}

function invalid(): never {
  throw new Error('invalid dsh-oidc audit record')
}

function object(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) invalid()
  return value as Record<string, unknown>
}

function text(value: unknown, max = 4096): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > max) invalid()
  return value
}

function parsePerson(value: unknown): AuditPerson {
  const raw = object(value)
  return {
    issuer: text(raw.issuer),
    subject: text(raw.subject),
    ...(raw.name === undefined ? {} : { name: text(raw.name) }),
  }
}

/** Validate one stored audit record; DSH backs up and skips one that throws. */
export function parseAuditEvent(value: unknown): AuditEvent {
  const raw = object(value)
  const id = text(raw.id)
  if (!KEY.test(id)) invalid()
  const at = raw.at
  if (typeof at !== 'number' || !Number.isSafeInteger(at) || at < 0) invalid()
  const type = text(raw.type)
  if (!(AUDIT_TYPES as readonly string[]).includes(type)) invalid()
  const ip = raw.ip === undefined ? undefined : text(raw.ip)
  if (ip !== undefined && isIP(ip) === 0) invalid()
  return {
    id,
    at,
    type: type as AuditType,
    ...(raw.person === undefined ? {} : { person: parsePerson(raw.person) }),
    ...(raw.by === undefined ? {} : { by: parsePerson(raw.by) }),
    ...(raw.session === undefined ? {} : { session: text(raw.session, 64) }),
    ...(ip === undefined ? {} : { ip }),
    ...(raw.userAgent === undefined ? {} : { userAgent: text(raw.userAgent, MAX_USER_AGENT) }),
  }
}

export const AUDIT_DOMAIN = 'dsh_oidc_audit'
export const AUDIT_TABLE = 'events'

export const auditDomain = Object.freeze({
  name: AUDIT_DOMAIN,
  version: 1,
  layout: 'single',
  invalidRecords: 'backup-and-skip',
  tables: { [AUDIT_TABLE]: { valueSchema: { parse: parseAuditEvent } } },
} as const)
