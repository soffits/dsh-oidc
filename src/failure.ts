const CODE = /^[A-Za-z0-9_.-]{1,64}$/u

function safeCode(value: unknown): string | undefined {
  return typeof value === 'string' && CODE.test(value) ? value : undefined
}

/**
 * Why an operation failed, for the log: each error's name, stable `code`
 * and the OAuth `error` and HTTP status a provider returned, along the cause chain.
 * Messages are left out, since provider and network errors can quote URLs,
 * codes or tokens.
 */
export function failureReason(error: unknown): string {
  const parts: string[] = []
  let current = error
  for (let depth = 0; depth < 6 && typeof current === 'object' && current !== null; depth += 1) {
    const record = current as Record<string, unknown>
    const name = current instanceof Error ? (safeCode(current.name) ?? 'Error') : 'object'
    const code = safeCode(record.code)
    const oauth = safeCode(record.error)
    parts.push(
      [
        name,
        ...(code === undefined ? [] : [code]),
        ...(oauth === undefined ? [] : [`error=${oauth}`]),
        ...(typeof record.status === 'number' ? [`status=${String(record.status)}`] : []),
      ].join(' '),
    )
    current = record.cause
  }
  return parts.length === 0 ? typeof error : parts.join(' <- ')
}
