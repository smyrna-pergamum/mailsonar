// Which product / mail provider produced each imported file, with the reason.
import {t} from '../i18n.js';
import {tt} from './strings.js';
import {esc} from './agent-view.js';

const CONF = {high: 'ok', medium: 'warn', low: 'bad', none: 'bad'};

export function sourceRows(evidence) {
  return (evidence ?? []).map(file => ({
    file: file.source,
    records: file.events?.length ?? 0,
    primary: file.profile?.primary ?? null,
    breakdown: file.profile?.breakdown ?? [],
    platforms: Object.entries(file.profile?.message_platforms ?? {}),
    mixed: Boolean(file.profile?.mixed)
  }));
}

export function sourcesHtml(evidence) {
  const rows = sourceRows(evidence);
  if (!rows.length) return `<p class="empty">${tt('No evidence loaded yet.')}</p>`;
  return `<div class="tablewrap"><table class="ms-sources" data-no-translate><thead><tr>
      <th>${tt('File')}</th><th>${tt('Detected source')}</th><th>${tt('Log type')}</th><th>${tt('Confidence')}</th><th>${tt('Why')}</th></tr></thead><tbody>
    ${rows.map(r => {
      const p = r.primary ?? {vendor: '?', product: t('not analysed (re-import the file)'), log_type: '', confidence: 'none', reason: ''};
      const extra = r.mixed ? `<div class="ms-muted">${r.breakdown.map(b => `${esc(b.product)} (${esc(b.count)})`).join(' · ')}</div>` : '';
      const plat = r.platforms.length ? `<div class="ms-muted">${tt('Mail platforms')}: ${r.platforms.slice(0, 6).map(([k, n]) => `${esc(k)} ×${esc(n)}`).join(' · ')}</div>` : '';
      return `<tr><td><code>${esc(r.file)}</code><div class="ms-muted">${esc(r.records)} ${tt('records')}</div></td>
        <td><strong>${esc(p.product)}</strong><div class="ms-muted">${esc(p.vendor)}</div>${extra}${plat}</td>
        <td>${esc(p.log_type)}</td><td><span class="ms-badge ${CONF[p.confidence] ?? 'warn'}">${tt(p.confidence)}</span></td><td class="ms-muted">${esc(p.reason)}</td></tr>`;
    }).join('')}</tbody></table></div>`;
}

export function platformsHtml(platforms) {
  if (!platforms?.length) return '';
  return `<h4>${tt('Mail platforms')}</h4><ul>${platforms.map(p => `<li><strong>${esc(p.platform)}</strong> <span class="ms-badge">${tt(p.role)}</span> <span class="ms-muted">${esc(p.evidence)}</span></li>`).join('')}</ul>`;
}
