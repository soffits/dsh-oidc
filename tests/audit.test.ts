import { Readable } from 'node:stream'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { describe, expect, it, vi } from 'vitest'
import { applyApiGuard } from '../src/api-guard.js'
import { AuditLog, parseAuditEvent, type AuditEvent, type AuditTable } from '../src/audit.js'

class MemoryAuditTable implements AuditTable {
  readonly rows = new Map<string, AuditEvent>()
  fail = false
  entries() {
    return this.rows.entries()
  }
  async put(key: string, value: AuditEvent) {
    if (this.fail) throw new Error('disk full')
    this.rows.set(key, value)
  }
  async delete(key: string) {
    return this.rows.delete(key)
  }
}

const settle = () => new Promise((resolve) => setImmediate(resolve))
const DAY = 86_400_000
const person = { issuer: 'https://id.example', subject: 'operator', name: 'op' }

function log(table?: MemoryAuditTable, maxEvents = 100, emit = vi.fn(), onError = vi.fn()) {
  return {
    audit: new AuditLog({
      retentionMilliseconds: 90 * DAY,
      maxEvents,
      ...(table === undefined ? {} : { table }),
      onError,
      emit,
    }),
    emit,
    onError,
  }
}

describe('audit log', () => {
  it('stores, emits and lists events newest first', async () => {
    const table = new MemoryAuditTable()
    const { audit, emit } = log(table)
    const first = audit.record({ type: 'sign-in', person, session: 's1', ip: '192.0.2.1' }, 1_000)
    const second = audit.record({ type: 'sign-out', person, session: 's1' }, 2_000)
    await settle()
    expect(emit).toHaveBeenCalledTimes(2)
    expect(emit).toHaveBeenNthCalledWith(1, first)
    expect(Object.isFrozen(first)).toBe(true)
    expect(audit.recent(10)).toEqual([second, first])
    expect(audit.recent(1)).toEqual([second])
    expect([...table.rows.values()].map(parseAuditEvent)).toEqual([first, second])
  })

  it('restores the durable log and drops events past retention, the cap, or malformed', async () => {
    const table = new MemoryAuditTable()
    const old = log(table).audit
    old.record({ type: 'sign-in', person }, 1_000)
    const kept = old.record({ type: 'sign-out', person }, 80 * DAY)
    await settle()
    table.rows.set('bad-key', kept)
    const { audit } = log(table)
    expect(await audit.restore(95 * DAY)).toBe(1)
    expect(audit.recent(10)).toEqual([kept])
    expect([...table.rows.keys()]).toEqual([kept.id])

    const capped = log(table, 2).audit
    await capped.restore(95 * DAY)
    capped.record({ type: 'sign-in', person }, 95 * DAY)
    capped.record({ type: 'sign-in', person }, 95 * DAY + 1)
    await settle()
    expect(capped.size).toBe(2)
    expect(table.rows.has(kept.id)).toBe(false)
  })

  it('keeps working in memory when the store or a listener fails', async () => {
    const table = new MemoryAuditTable()
    table.fail = true
    const emit = vi.fn(() => {
      throw new Error('listener bug')
    })
    const { audit, onError } = log(table, 100, emit)
    audit.record({ type: 'sign-in', person }, 1)
    await settle()
    expect(audit.size).toBe(1)
    expect(onError).toHaveBeenCalledTimes(2)
  })

  it('cuts long user agents and rejects malformed stored records', () => {
    const { audit } = log()
    const event = audit.record({ type: 'sign-in', userAgent: 'x'.repeat(2_000) }, 1)
    expect(event.userAgent).toHaveLength(512)
    const valid = { id: event.id, at: 1, type: 'sign-in' }
    expect(parseAuditEvent(valid)).toEqual(valid)
    for (const broken of [
      { ...valid, id: 'nope' },
      { ...valid, type: 'made-up' },
      { ...valid, at: -1 },
      { ...valid, ip: 'not-an-ip' },
      { ...valid, person: { issuer: 'x' } },
      null,
    ])
      expect(() => parseAuditEvent(broken)).toThrow('invalid dsh-oidc audit record')
  })
})

describe('/api session guard', () => {
  type Listener = (
    req: IncomingMessage,
    res: ServerResponse,
    next: () => Promise<void>,
  ) => Promise<void>

  function guard(admitted: boolean) {
    let listener: Listener | undefined
    applyApiGuard({ on: (_name, fn) => (listener = fn) }, () => admitted)
    const captured: { status?: number; body?: string | undefined } = {}
    const res = {
      writeHead(status: number) {
        captured.status = status
        return res
      },
      end(body?: string) {
        captured.body = body
        return res
      },
    } as unknown as ServerResponse
    const next = vi.fn(async () => undefined)
    return { run: () => listener!(Readable.from([]) as IncomingMessage, res, next), captured, next }
  }

  it('refuses a request without a live OIDC session and never reaches the handler', async () => {
    const { run, captured, next } = guard(false)
    await run()
    expect(captured).toEqual({ status: 401, body: 'unauthorized\n' })
    expect(next).not.toHaveBeenCalled()
  })

  it('passes a request with a live session through', async () => {
    const { run, captured, next } = guard(true)
    await run()
    expect(next).toHaveBeenCalledOnce()
    expect(captured).toEqual({})
  })
})
