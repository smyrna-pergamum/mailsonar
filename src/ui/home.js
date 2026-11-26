// Start page: three steps (data -> AI model -> investigate) plus the attack-chain view.
import {t} from '../i18n.js';
import {tt} from './strings.js';
import {esc} from './agent-view.js';
import {describeProvider, getProvider, lastModel, onProvider, providerReady} from './provider.js';
import {sourcesHtml} from './sources-view.js';

export function chainHtml(chains) {
  if (!chains.length) return '';
  return chains.slice(0, 5).map(c => `<div class="ms-chain" data-no-translate>
    <div class="ms-chain-head"><span class="ms-badge ${c.severity === 'critical' ? 'bad' : 'warn'}">${esc(c.severity.toUpperCase())}</span> <strong>${esc(c.account)}</strong> <small>${c.chain.length}/4</small></div>
    <ol class="ms-chain-steps">${c.chain.map(s => `<li><span class="ms-chain-time">${esc(s.time.slice(11, 16))}</span><span class="ms-chain-label">${tt(s.label)}</span><button type="button" class="ms-evid" data-evidence="${esc(s.evidence)}">${esc(s.rule)}</button></li>`).join('')}</ol>
  </div>`).join('');
}

export function mountHome({section, api}) {
  section.innerHTML = `
    <div class="ms-hero"><h2>${tt('E-mail incident investigation in three steps')}</h2>
      <p class="ms-muted">${tt('Phishing, BEC, account takeover, malicious attachments and data leaks. Evidence stays on this PC; AI is optional.')}</p></div>
    <div class="ms-steps-grid">
      <article class="ms-step" data-step="1"><span class="ms-num">1</span><h3>${tt('Load evidence')}</h3>
        <p class="ms-muted">${tt('EML, MBOX, MSG, CSV, JSON, logs, EVTX, XLSX, ZIP.')}</p>
        <div class="ms-actions"><button type="button" class="primary" data-act="import">${tt('Import files')}</button><button type="button" data-act="sample">${tt('Load sample BEC case')}</button></div>
        <p class="ms-step-status" data-s="data"></p></article>
      <article class="ms-step" data-step="2"><span class="ms-num">2</span><h3>${tt('Connect an AI model')} <small class="ms-muted">${tt('optional')}</small></h3>
        <p class="ms-muted">${tt('Download a free local model from Hugging Face with one click, or use Ollama / a cloud API.')}</p>
        <div class="ms-actions"><button type="button" data-act="model">${tt('Choose AI model')}</button><button type="button" data-act="restart" hidden>${tt('Start last model')}</button></div>
        <p class="ms-step-status" data-s="ai"></p></article>
      <article class="ms-step" data-step="3"><span class="ms-num">3</span><h3>${tt('Investigate')}</h3>
        <p class="ms-muted">${tt('Review rule findings and the attack chain, then let HELM explain and verify.')}</p>
        <div class="ms-actions"><button type="button" class="primary" data-act="auto">${tt('Run AI triage')}</button><button type="button" data-act="findings">${tt('Show findings')}</button><button type="button" data-act="email">${tt('E-mail analysis')}</button></div>
        <p class="ms-step-status" data-s="inv"></p></article>
    </div>
    <article class="ms-sources-card"><h2>${tt('Log sources and mail providers')}</h2>
      <p class="ms-muted">${tt('Which system produced each file, detected from field names, product names, log line formats and e-mail headers. Verify against how the logs were exported.')}</p>
      <div class="ms-sources-host"></div></article>
    <article class="ms-chains-card"><h2>${tt('Attack chains')}</h2>
      <p class="ms-muted">${tt('Deterministic correlation per account: phishing received → suspicious sign-in → mailbox manipulation → fraud or exfiltration. Each stage still needs confirmation in its own log source.')}</p>
      <div class="ms-chains"></div></article>`;
  const $ = sel => section.querySelector(sel);
  section.addEventListener('click', event => {
    const evid = event.target.closest('[data-evidence]');
    if (evid) return api.inspect(evid.dataset.evidence);
    const act = event.target.closest('[data-act]')?.dataset.act;
    if (act === 'import') api.importFiles();
    if (act === 'sample') api.loadSample();
    if (act === 'model') api.tab('settings');
    if (act === 'restart') api.startModel(lastModel());
    if (act === 'auto') {
      api.tab('ai');
      api.quickRun('triage');
    }
    if (act === 'findings') api.tab('findings');
    if (act === 'email') api.tab('email');
  });
  function render() {
    const c = api.getCase();
    const chains = c.findings.filter(f => f.rule === 'COR-004');
    const high = c.findings.filter(f => ['critical', 'high'].includes(f.severity)).length;
    $('[data-s="data"]').textContent = c.events.length ? t('{files} files · {events} records · {findings} findings', {files: c.evidence.length, events: c.events.length, findings: c.findings.length}) : t('No evidence loaded yet.');
    $('[data-s="data"]').className = `ms-step-status ${c.events.length ? 'ok' : ''}`;
    const p = getProvider();
    $('[data-s="ai"]').textContent = describeProvider(p);
    $('[data-s="ai"]').className = `ms-step-status ${providerReady(p) ? 'ok' : ''}`;
    $('[data-act="restart"]').hidden = !(p.preset === 'embedded' && !p.key && lastModel());
    $('[data-s="inv"]').textContent = c.events.length ? t('{high} high-priority findings · {chains} attack chains', {high, chains: chains.length}) : '';
    $('.ms-sources-host').innerHTML = sourcesHtml(c.evidence);
    $('.ms-chains').innerHTML = chainHtml(chains) || `<p class="empty">${tt('No attack chain detected in the current evidence.')}</p>`;
  }
  onProvider(render);
  api.onLocale?.(render);
  render();
  return {render};
}
