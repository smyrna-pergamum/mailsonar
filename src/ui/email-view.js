// E-mail forensics view: every imported EML/MBOX message with its deterministic
// header, Received-chain, authentication, URL and attachment analysis.
// Message content is untrusted: everything is rendered as escaped text.
import {t} from '../i18n.js';
import {esc} from './agent-view.js';
import {platformsHtml} from './sources-view.js';

export function emailRows(events) {
  return (events ?? [])
    .filter(e => e?.data?.email_analysis)
    .map(e => ({event: e, a: e.data.email_analysis, indicators: e.data.indicators ?? []}))
    .sort((x, y) => (y.a.risk_score ?? 0) - (x.a.risk_score ?? 0));
}

function badge(name, value) {
  const v = String(value || 'none').toLowerCase();
  const cls = v === 'pass' ? 'ok' : ['fail', 'softfail', 'permerror'].includes(v) ? 'bad' : 'warn';
  return `<span class="ms-badge ${cls}">${esc(name)}=${esc(v)}</span>`;
}

export function vt(kind, value) {
  if (!value) return '';
  return `<button type="button" class="ms-vt" data-vt="${esc(kind)}" data-v="${esc(value)}" title="${esc(t('Check manually on VirusTotal (opens your browser)'))}">VT ↗</button>`;
}

function riskClass(score) {
  return score >= 50 ? 'bad' : score >= 20 ? 'warn' : 'ok';
}

function detail(row) {
  const {event, a, indicators} = row;
  const h = a.header ?? {};
  const hops = (a.received_chain ?? []).map((hop, i) => `<tr><td>${i + 1}</td><td>${esc(hop.from)}</td><td>${esc(hop.ip)}</td><td>${esc(hop.by)}</td><td>${esc(hop.with)}</td><td>${esc(hop.date)}</td></tr>`).join('');
  const urls = (a.urls ?? []).map(u => `<tr class="${u.suspicious ? 'row-bad' : ''}"><td><code>${esc(u.url)}</code> ${vt('url', u.url)}</td><td>${esc(u.host)} ${vt('domain', u.host)}</td><td>${esc((u.flags ?? []).join('; ') || '—')}</td></tr>`).join('');
  const files = (a.attachments ?? []).map(f => `<tr class="${f.suspicious ? 'row-bad' : ''}"><td>${esc(f.filename)}</td><td>${esc(f.mime)} / ${esc(f.detected_type)}</td><td>${esc(f.size)}</td><td><code>${esc(f.sha256)}</code> ${vt('hash', f.sha256)}</td><td>${esc((f.flags ?? []).join('; ') || '—')}</td></tr>`).join('');
  return `<div class="ms-mail-detail" data-no-translate>
    <div class="ms-mail-top"><h3>${esc(h.subject || '(no subject)')}</h3><span class="ms-badge ${riskClass(a.risk_score)}">${esc(t('Risk'))} ${esc(a.risk_score ?? 0)}/100</span></div>
    <p>${badge('SPF', a.authentication?.spf)} ${badge('DKIM', a.authentication?.dkim)} ${badge('DMARC', a.authentication?.dmarc)}</p>
    <p class="ms-muted">${esc(a.authentication?.note ?? '')}</p>
    <table class="ms-kv"><tbody>
      <tr><th>From</th><td>${esc(h.from)} ${vt('domain', (event.sender.split('@')[1] ?? ''))}</td></tr><tr><th>Return-Path</th><td>${esc(h.return_path || '—')}</td></tr>
      <tr><th>Reply-To</th><td>${esc(h.reply_to || '—')}</td></tr><tr><th>To / Cc</th><td>${esc(h.to)} ${esc(h.cc)}</td></tr>
      <tr><th>Date</th><td>${esc(h.date)}</td></tr><tr><th>Message-ID</th><td>${esc(event.message_id)}</td></tr>
      <tr><th>Origin IP</th><td>${esc(a.origin_ip || '—')} ${vt('ip', a.origin_ip)}</td></tr><tr><th>X-Mailer</th><td>${esc(h.x_mailer || '—')}</td></tr>
    </tbody></table>
    ${platformsHtml(a.platforms)}
    ${(a.mismatches ?? []).length || (a.chain_flags ?? []).length ? `<h4>${esc(t('Anomalies'))}</h4><ul>${[...(a.mismatches ?? []), ...(a.chain_flags ?? [])].map(m => `<li>${esc(m)}</li>`).join('')}</ul>` : ''}
    <h4>Received <small class="ms-muted">${esc(t('(newest first; trust only your own hops)'))}</small></h4>
    <div class="tablewrap"><table><thead><tr><th>#</th><th>from</th><th>IP</th><th>by</th><th>with</th><th>date</th></tr></thead><tbody>${hops || '<tr><td colspan="6">—</td></tr>'}</tbody></table></div>
    <h4>URLs (${(a.urls ?? []).length}) <small class="ms-muted">${esc(t('never opened'))}</small></h4>
    <div class="tablewrap"><table><thead><tr><th>URL</th><th>host</th><th>flags</th></tr></thead><tbody>${urls || '<tr><td colspan="3">—</td></tr>'}</tbody></table></div>
    <h4>${esc(t('Attachments'))} (${(a.attachments ?? []).length}) <small class="ms-muted">${esc(t('hashed, never executed'))}</small></h4>
    <div class="tablewrap"><table><thead><tr><th>file</th><th>type</th><th>bytes</th><th>SHA-256</th><th>flags</th></tr></thead><tbody>${files || '<tr><td colspan="5">—</td></tr>'}</tbody></table></div>
    <p>${indicators.map(i => `<span class="ms-chip static">${esc(i)}</span>`).join(' ')}</p>
  </div>`;
}

export function mountEmailView({section, api}) {
  section.innerHTML = `<article><h2>${esc(t('E-mail forensics'))}</h2>
    <p class="ms-muted">${esc(t('Imported EML and MBOX messages, sorted by risk. Headers, Received chain, SPF/DKIM/DMARC, URLs and attachments are analysed statically; nothing is opened, executed or looked up online.'))}</p>
    <div class="ms-actions"><button type="button" class="primary ms-mail-ai">${esc(t('Analyse headers with HELM'))}</button></div>
    <div class="ms-mail-grid"><div class="ms-mail-list"></div><div class="ms-mail-pane"></div></div></article>`;
  const list = section.querySelector('.ms-mail-list');
  const pane = section.querySelector('.ms-mail-pane');
  section.querySelector('.ms-mail-ai').onclick = () => api.quickRun('email-header-forensics');
  let vtConfirmed = false;
  section.addEventListener('click', async event => {
    const b = event.target.closest('[data-vt]');
    if (!b) return;
    if (!vtConfirmed && !confirm(t('VirusTotal is a third-party service: the indicator you open becomes visible to VirusTotal and its customers. Continue?'))) return;
    vtConfirmed = true;
    try {
      await api.lookup(b.dataset.vt, b.dataset.v);
      api.status('Opened on VirusTotal: {value}', {value: b.dataset.v.slice(0, 80)});
    } catch (error) {
      api.status(String(error?.message ?? error));
    }
  });
  let selected = null;
  function render() {
    const rows = emailRows(api.getCase().events);
    list.replaceChildren();
    if (!rows.length) {
      list.innerHTML = `<p class="empty">${esc(t('No EML or MBOX messages imported yet. Load the sample case or import .eml / .mbox files.'))}</p>`;
      pane.replaceChildren();
      return;
    }
    if (!rows.some(r => r.event.id === selected)) selected = rows[0].event.id;
    for (const row of rows) {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = `ms-mail-item${row.event.id === selected ? ' active' : ''}`;
      button.innerHTML = `<span class="ms-badge ${riskClass(row.a.risk_score)}">${esc(row.a.risk_score ?? 0)}</span><span><strong>${esc(row.a.header?.subject || '(no subject)')}</strong><small>${esc(row.event.sender)} → ${esc(row.event.recipient)}</small></span>`;
      button.setAttribute('data-no-translate', '');
      button.onclick = () => {
        selected = row.event.id;
        render();
      };
      list.append(button);
    }
    pane.innerHTML = detail(rows.find(r => r.event.id === selected));
  }
  return {render};
}
