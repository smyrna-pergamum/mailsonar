// Which product / mail provider produced each imported file, with the reason.
import {t} from '../i18n.js';
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
  if (!rows.length) return `<p class="empty">${esc(t('No evidence loaded yet.'))}</p>`;
  return `<div class="tablewrap"><table class="ms-sources" data-no-translate><thead><tr>
      <th>${esc(t('File'))}</th><th>${esc(t('Detected source'))}</th><th>${esc(t('Log type'))}</th><th>${esc(t('Confidence'))}</th><th>${esc(t('Why'))}</th></tr></thead><tbody>
    ${rows.map(r => {
      const p = r.primary ?? {vendor: '?', product: t('not analysed (re-import the file)'), log_type: '', confidence: 'none', reason: ''};
      const extra = r.mixed ? `<div class="ms-muted">${r.breakdown.map(b => `${esc(b.product)} (${esc(b.count)})`).join(' · ')}</div>` : '';
      const plat = r.platforms.length ? `<div class="ms-muted">${esc(t('Mail platforms'))}: ${r.platforms.slice(0, 6).map(([k, n]) => `${esc(k)} ×${esc(n)}`).join(' · ')}</div>` : '';
      return `<tr><td><code>${esc(r.file)}</code><div class="ms-muted">${esc(r.records)} ${esc(t('records'))}</div></td>
        <td><strong>${esc(p.product)}</strong><div class="ms-muted">${esc(p.vendor)}</div>${extra}${plat}</td>
        <td>${esc(p.log_type)}</td><td><span class="ms-badge ${CONF[p.confidence] ?? 'warn'}">${esc(t(p.confidence))}</span></td><td class="ms-muted">${esc(p.reason)}</td></tr>`;
    }).join('')}</tbody></table></div>`;
}

export function platformsHtml(platforms) {
  if (!platforms?.length) return '';
  return `<h4>${esc(t('Mail platforms'))}</h4><ul>${platforms.map(p => `<li><strong>${esc(p.platform)}</strong> <span class="ms-badge">${esc(t(p.role))}</span> <span class="ms-muted">${esc(p.evidence)}</span></li>`).join('')}</ul>`;
}
