/**
 * Send times for the model: when a person sent a Web prompt, as weekday, date,
 * local time and UTC offset, so the agent can tell how much time has passed
 * between messages.
 */

/** The zone of this process. */
export function processTimeZone(): string {
  return new Intl.DateTimeFormat().resolvedOptions().timeZone
}

/**
 * A configured zone in the form this runtime uses for it.
 * @throws when the runtime does not know the zone.
 */
export function canonicalTimeZone(value: string): string {
  try {
    return new Intl.DateTimeFormat('en-US', { timeZone: value }).resolvedOptions().timeZone
  } catch {
    throw new Error(`dsh-oidc: timeZone ${JSON.stringify(value)} is not a known IANA time zone`)
  }
}

/** A zone name the runtime knows, or undefined (for a value a client reported). */
export function knownTimeZone(value: unknown): string | undefined {
  if (typeof value !== 'string' || value.trim() === '') return undefined
  try {
    return canonicalTimeZone(value)
  } catch {
    return undefined
  }
}

const formatters = new Map<string, Intl.DateTimeFormat>()

function formatterFor(timeZone: string): Intl.DateTimeFormat {
  let formatter = formatters.get(timeZone)
  if (formatter === undefined) {
    formatter = new Intl.DateTimeFormat('en-US', {
      timeZone,
      weekday: 'short',
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      hourCycle: 'h23',
      timeZoneName: 'longOffset',
    })
    formatters.set(timeZone, formatter)
  }
  return formatter
}

/**
 * A moment as the model reads it, such as `Mon 2026-03-02 09:41 UTC+01:00`.
 * @param epochMs - the moment, in milliseconds since the epoch.
 * @param timeZone - a zone the runtime knows.
 */
export function formatMoment(epochMs: number, timeZone: string): string {
  const parts: Record<string, string> = {}
  for (const part of formatterFor(timeZone).formatToParts(epochMs)) parts[part.type] = part.value
  const zoneName = parts.timeZoneName ?? 'GMT'
  const offset = zoneName === 'GMT' ? '+00:00' : zoneName.slice(3)
  return `${parts.weekday ?? ''} ${parts.year ?? ''}-${parts.month ?? ''}-${parts.day ?? ''} ${parts.hour ?? ''}:${parts.minute ?? ''} UTC${offset}`
}
