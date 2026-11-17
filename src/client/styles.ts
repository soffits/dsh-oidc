/**
 * Sidebar account launcher geometry and colours. Adapted from DeepSeek
 * Harness's `@deepseek-ai/dsh-client-ui-settings-account` AccountMenu and
 * AccountAvatar stylesheets (MIT, see THIRD_PARTY_NOTICES.md) so the button
 * matches the launcher it replaces: the same sidebar row tokens, 44px signed-in
 * row, 24px avatar, 36px collapsed rail button and hover fill.
 */
export const STYLE_ID = 'soffits-dsh-oidc-account'

export const CLASS = {
  root: 'soffits-oidc-account',
  anchor: 'soffits-oidc-account-anchor',
  trigger: 'soffits-oidc-account-trigger',
  avatar: 'soffits-oidc-account-avatar',
  image: 'soffits-oidc-account-image',
  initials: 'soffits-oidc-account-initials',
  label: 'soffits-oidc-account-label',
  section: 'soffits-oidc-settings',
  heading: 'soffits-oidc-settings-heading',
  subheading: 'soffits-oidc-settings-subheading',
  muted: 'soffits-oidc-settings-muted',
  list: 'soffits-oidc-settings-list',
  row: 'soffits-oidc-settings-row',
  plain: 'soffits-oidc-settings-plain',
  code: 'soffits-oidc-settings-code',
  sessions: 'soffits-oidc-settings-sessions',
  session: 'soffits-oidc-settings-session',
  sessionText: 'soffits-oidc-settings-session-text',
  sessionTitle: 'soffits-oidc-settings-session-title',
  events: 'soffits-oidc-settings-events',
  event: 'soffits-oidc-settings-event',
} as const

export const CSS = `
.${CLASS.root} { flex: 1; min-width: 0; }
.${CLASS.root}[data-inset='true'] { margin-inline: 2px; }
.${CLASS.anchor} { width: 100%; }
.${CLASS.trigger} { user-select: none; display: flex; align-items: center; width: 100%; height: 44px; gap: 8px;
  padding: 6px; border: 0; box-sizing: border-box; border-radius: var(--dsw-radius-md); background: transparent;
  color: var(--dsw-alias-label-primary); font: inherit; font-size: 14px; cursor: pointer; }
.${CLASS.trigger}[data-collapsed='true'] { width: 36px; height: 36px; justify-content: center; gap: 0; padding: 0; }
@media (hover: hover) { .${CLASS.trigger}:hover { background-color: var(--dsw-alias-interactive-bg-hover); } }
.${CLASS.trigger}:focus-visible { outline: var(--dsw-focus-ring-width) solid var(--dsw-focus-ring-color, var(--dsw-alias-state-business-primary)); outline-offset: 1px; }
.${CLASS.avatar} { display: flex; align-items: center; justify-content: center; flex: none; width: 24px; height: 24px;
  border-radius: 50%; corner-shape: round; overflow: hidden; background: var(--dsw-alias-bg-skeleton);
  color: var(--dsw-alias-label-tertiary); }
.${CLASS.image} { display: block; width: 100%; height: 100%; border-radius: 50%; corner-shape: round; object-fit: cover; }
.${CLASS.initials} { font-size: 11px; font-weight: 500; line-height: 1; color: var(--dsw-alias-label-secondary); }
.${CLASS.label} { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.${CLASS.section} { display: flex; flex-direction: column; gap: 8px; color: var(--dsw-alias-label-primary); font-size: 14px; }
.${CLASS.heading} { margin: 0 0 4px; font-size: 18px; font-weight: 600; }
.${CLASS.subheading} { margin: 16px 0 0; font-size: 15px; font-weight: 600; }
.${CLASS.muted} { margin: 0; color: var(--dsw-alias-label-tertiary); font-size: 13px; }
.${CLASS.list} { margin: 0; display: flex; flex-direction: column; }
.${CLASS.row} { display: grid; grid-template-columns: minmax(120px, 30%) 1fr; gap: 12px; padding: 8px 0;
  border-bottom: 1px solid var(--dsw-alias-border-l2); }
.${CLASS.row} dt { color: var(--dsw-alias-label-secondary); }
.${CLASS.row} dd { margin: 0; overflow-wrap: anywhere; }
.${CLASS.plain} { margin: 0; padding: 0; list-style: none; }
.${CLASS.code} { font-family: ui-monospace, monospace; font-size: 12px; }
.${CLASS.sessions}, .${CLASS.events} { margin: 0; padding: 0; list-style: none; display: flex; flex-direction: column; }
.${CLASS.session} { display: flex; align-items: center; gap: 12px; padding: 10px 0; border-bottom: 1px solid var(--dsw-alias-border-l2); }
.${CLASS.sessionText} { flex: 1; min-width: 0; display: flex; flex-direction: column; gap: 2px; }
.${CLASS.sessionTitle} { display: flex; align-items: center; gap: 8px; font-weight: 500; }
.${CLASS.event} { display: flex; flex-wrap: wrap; gap: 4px 12px; padding: 6px 0; border-bottom: 1px solid var(--dsw-alias-border-l2); }
`

/**
 * Add the stylesheet once.
 * @returns disposer removing it again.
 */
export function installStyles(doc: Document = document): () => void {
  if (doc.getElementById(STYLE_ID) !== null) return () => undefined
  const tag = doc.createElement('style')
  tag.id = STYLE_ID
  tag.dataset.plugin = '@soffits/dsh-oidc'
  tag.textContent = CSS
  doc.head.appendChild(tag)
  return () => {
    tag.remove()
  }
}
