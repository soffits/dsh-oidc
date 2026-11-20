import type { IncomingMessage } from 'node:http'
import { isIP } from 'node:net'
import { networkInterfaces } from 'node:os'
import { CLIENT_IP_HEADER } from './admission.js'
import type { RequestIdentity } from './identity.js'

/**
 * Local access: a request DSH admitted that came from this machine itself
 * rather than through the sign-in gate, such as a browser on the same host
 * that holds DSH's own cookie. With `localPerson` set, such a request is
 * identified as that person and passes the `/api` guard; without it, it is
 * refused like any other request without a session.
 *
 * A request counts as local when its TCP peer is one of this host's own
 * addresses (loopback or an address of one of its network interfaces), it
 * carries no `X-Dsh-Oidc-Client-Ip` header, and its `Host` names something
 * other than the public origin's host, such as the address DSH listens on.
 * A proxy on another host or in another container connects from its own
 * address and never matches; the gateway connects from loopback but always
 * sets the header; and a proxy on this same host forwards the public `Host`,
 * so outside traffic is not taken for local even on a route that skips the gate.
 */
export const LOCAL_PROVIDER = 'local'

const CACHE_MILLISECONDS = 30_000
let cached: { at: number; addresses: ReadonlySet<string> } | undefined

function unmapped(address: string): string {
  const lower = address.toLowerCase()
  return lower.startsWith('::ffff:') && isIP(lower.slice(7)) === 4 ? lower.slice(7) : lower
}

/** This host's own addresses, refreshed every 30 seconds. */
export function ownAddresses(
  now = Date.now(),
  read: typeof networkInterfaces = networkInterfaces,
): ReadonlySet<string> {
  if (cached !== undefined && now - cached.at < CACHE_MILLISECONDS) return cached.addresses
  const addresses = new Set<string>(['::1'])
  for (const entries of Object.values(read()))
    for (const entry of entries ?? []) addresses.add(unmapped(entry.address.split('%', 1)[0]!))
  cached = { at: now, addresses }
  return addresses
}

function hostname(host: string | undefined): string | undefined {
  if (host === undefined || host === '') return undefined
  try {
    return new URL(`http://${host}`).hostname.replace(/\.$/u, '')
  } catch {
    return undefined
  }
}

/** Whether the request came from this host and not through the gate or a proxy. */
export function isLocalRequest(
  req: IncomingMessage,
  publicHostname: string,
  addresses: ReadonlySet<string> = ownAddresses(),
): boolean {
  if (req.headers[CLIENT_IP_HEADER] !== undefined) return false
  const host = hostname(req.headers.host)
  if (host === undefined || host === hostname(publicHostname)) return false
  const peer = req.socket.remoteAddress
  if (peer === undefined) return false
  const address = unmapped(peer)
  if (isIP(address) === 4 && address.startsWith('127.')) return true
  return addresses.has(address)
}

/** The identity a local request carries. */
export function localIdentity(person: string): RequestIdentity {
  return Object.freeze({
    provider: LOCAL_PROVIDER,
    issuer: LOCAL_PROVIDER,
    id: person,
    name: person,
  })
}
