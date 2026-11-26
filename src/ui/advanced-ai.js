// "Deep analysis" for analysts who want to send specific records straight to the
// model instead of letting HELM choose. Three clearly separated methods, guided
// record selection and a readable result view. The original handlers (ask_ai
// gateway, batch loop, two-stage review) are reused unchanged through their
// hidden controls, so privacy checks and limits stay exactly as before.
import {t} from '../i18n.js';
import {esc, markdown} from './agent-view.js';
import {confirmTransfer} from './helm-run.js';
import {getProvider, isLoopback, providerReady} from './provider.js';

const TEMPLATES = [
  ['Summarise what these records show and what is suspicious.', 'Summary'],
  ['Is this a phishing campaign? List senders, recipients, authentication results and evidence IDs.', 'Phishing?'],
  ['Do these records show an account takeover? Order the events in time and cite evidence IDs.', 'Account takeover?'],
  ['Build a timeline of these records and explain each step with evidence IDs.', 'Timeline'],
  ['Which of these findings are likely false positives, and why?', 'False positives?']
];

/** Normalise any stored AI output (text, batch array, two-stage object) for display. */
export function resultBlocks(raw) {
  let value;
  try {
    value = JSON.parse(raw);
  } catch {
    return raw ? [{title: '', text: raw}] : [];
  }
  const rows = Array.isArray(value) ? value : Array.isArray(value?.results) ? value.results : [value];
  return rows.map((row, i) => {
    if (row?.error) return {title: `#${row.batch ?? i + 1}`, error: row.error};
    const stages = [['', row]];
    if (row?.first || row?.review) stages.splice(0, 1, ['Triage', row.first], ['Independent review', row.review]);
    return {
      title: row?.batch ? `${t('Batch')} ${row.batch}` : `#${i + 1}`,
      stages: stages.filter(([, s]) => s).map(([name, s]) => ({
        name,
        text: typeof s === 'string' ? s : s.answer ?? s.text ?? '',
        accepted: s.validation?.accepted?.length ?? s.accepted?.length ?? 0,
        rejected: s.validation?.rejected?.length ?? s.rejected?.length ?? 0
      }))
    };
  });
}

export function mountAdvancedAi({details, api}) {
  const summary = details.querySelector('summary');
  summary.textContent = 'Deep analysis of selected records (advanced)';
  const legacy = document.createElement('div');
  legacy.hidden = true;
  for (const child of [...details.children]) if (child !== summary) legacy.append(child);
  // Exports are case outputs, not AI: move them to Case & report.
  const exports = document.createElement('article');
  exports.innerHTML = `<h2>${esc(t('Exports'))}</h2>`;
  for (const id of ['graphRC3', 'ocsfRC3']) {
    const button = legacy.querySelector(`#${id}`);
    if (button) exports.append(button, ' ');
  }
  document.getElementById('case')?.append(exports);

  const box = document.createElement('div');
  box.className = 'ms-deep';
  details.append(box, legacy);
  const $ = id => document.getElementById(id);
  const state = {mode: 'selected'};

  function selectionInfo() {
    const ids = api.selectedIds();
    return ids.length ? t('{count} of 25 records selected', {count: ids.length}) : t('No records selected yet.');
  }

  function render() {
    const c = api.getCase();
    const batches = Math.ceil(c.events.length / 25);
    const p = getProvider();
    box.innerHTML = `
      <p class="ms-muted">${esc(t('Use this when you want to decide exactly which records the model sees. For most questions the one-click analysis above (HELM) is easier and usually better: it searches the whole case itself.'))}</p>
      <p class="ms-muted">${esc(t('Records are always sent pseudonymised (entity aliases, no raw content), also to local models.'))}</p>
      <div class="ms-tabs" role="tablist">
        ${[['selected', '1 · Selected records', 'Up to 25 records you choose'], ['batch', '2 · Whole case in batches', `${c.events.length} records → ${batches} batches`], ['review', '3 · Two-stage review', 'Triage, then an independent check']]
          .map(([id, title, hint]) => `<button type="button" role="tab" class="ms-tab ${state.mode === id ? 'active' : ''}" data-mode="${id}"><strong>${esc(t(title))}</strong><small>${esc(id === 'batch' ? t('{count} records → {batches} batches', {count: c.events.length, batches}) : t(hint))}</small></button>`).join('')}
      </div>
      <div class="ms-tab-body">${body(c, batches)}</div>
      ${providerReady(p) ? '' : `<p class="ms-warn">${esc(t('Connect an AI model first (AI model page).'))}</p>`}
      <div class="ms-deep-result" data-no-translate></div>`;
    renderResult();
  }

  function body(c, batches) {
    const question = `<label>${esc(t('Question'))}<select class="ms-template"><option value="">${esc(t('Choose a template…'))}</option>${TEMPLATES.map(([q, label]) => `<option value="${esc(t(q))}">${esc(t(label))}</option>`).join('')}</select></label>
      <textarea class="ms-deep-q" rows="3">${esc($('question').value)}</textarea>`;
    if (state.mode === 'selected') {
      return `<div class="ms-step-box"><h4>${esc(t('Step 1 · Choose records'))}</h4>
          <p class="ms-sel-info">${esc(selectionInfo())}</p>
          <div class="ms-actions">
            <button type="button" data-pick="high">${esc(t('Evidence of high-priority findings'))}</button>
            <button type="button" data-pick="chain">${esc(t('Attack-chain evidence'))}</button>
            <button type="button" data-pick="explorer">${esc(t('Pick manually in Log explorer'))}</button>
            <button type="button" class="ms-link" data-pick="clear">${esc(t('Clear selection'))}</button>
          </div></div>
        <div class="ms-step-box"><h4>${esc(t('Step 2 · Ask'))}</h4>${question}
          <div class="ms-actions"><button type="button" class="primary" data-run="ask">${esc(t('Analyse selected records'))}</button></div></div>`;
    }
    if (state.mode === 'batch') {
      return `<div class="ms-step-box"><p>${esc(t('Sends every record in batches of 25 and collects the answers. Useful for a complete pass; slow with local CPU models (roughly 1–5 minutes per batch).'))}</p>
          <p class="ms-muted">${esc(t('{count} records → {batches} batches', {count: c.events.length, batches}))}</p>${question}
          <div class="ms-actions"><button type="button" class="primary" data-run="batch" ${c.events.length ? '' : 'disabled'}>${esc(t('Start batch analysis'))}</button><button type="button" data-run="stop">${esc(t('Stop after current batch'))}</button></div></div>`;
    }
    return `<div class="ms-step-box"><p>${esc(t('Stage 1 triages all records; stage 2 independently re-checks every claim against the cited evidence. Claims without valid evidence IDs are rejected.'))}</p>${question}
        <details><summary>${esc(t('Optional: reference notes (playbooks, known-good senders)'))}</summary>
          <p class="ms-muted">${esc(t('One note per line. Sent as written: no personal data.'))}</p>
          <textarea class="ms-notes" rows="4" placeholder="${esc(t('e.g. finans@ and it.destek@ are internal shared mailboxes'))}"></textarea></details>
        <div class="ms-actions"><button type="button" class="primary" data-run="review" ${c.events.length ? '' : 'disabled'}>${esc(t('Start two-stage review'))}</button><button type="button" data-run="stop">${esc(t('Stop'))}</button></div></div>`;
  }

  function renderResult() {
    const host = box.querySelector('.ms-deep-result');
    if (!host) return;
    const blocks = resultBlocks($('answer').textContent.trim());
    if (!blocks.length || /^AI output will appear here/.test($('answer').textContent)) {
      host.innerHTML = '';
      return;
    }
    const totals = blocks.flatMap(b => b.stages ?? []).reduce((acc, s) => ({ok: acc.ok + s.accepted, bad: acc.bad + s.rejected}), {ok: 0, bad: 0});
    host.innerHTML = `<h3>${esc(t('Result'))}</h3>
      <p><span class="ms-badge ok">✓ ${totals.ok} ${esc(t('claims with valid evidence'))}</span> <span class="ms-badge ${totals.bad ? 'bad' : ''}">✗ ${totals.bad} ${esc(t('rejected claims'))}</span></p>
      ${blocks.map(b => `<details class="ms-result-block" ${blocks.length === 1 ? 'open' : ''}><summary>${esc(b.title || t('Answer'))}${b.error ? ` · <span class="ms-warn">${esc(b.error)}</span>` : ''}</summary>
        ${b.text ? markdown(b.text) : ''}${(b.stages ?? []).map(s => `${s.name ? `<h4>${esc(t(s.name))}</h4>` : ''}${markdown(s.text)}<p class="ms-muted">✓ ${s.accepted} · ✗ ${s.rejected}</p>`).join('')}</details>`).join('')}
      <p class="ms-muted">${esc(t('AI output is unverified. Check every claim against the cited evidence.'))}</p>`;
  }

  function prepare() {
    const q = box.querySelector('.ms-deep-q').value.trim();
    if (q.length < 5) {
      api.status('Write a question first.');
      return false;
    }
    if (!providerReady(getProvider())) {
      api.status('Connect an AI model first (AI model page).');
      return false;
    }
    // Loopback stays on the device; remote providers get an explicit confirmation.
    if (!isLoopback(getProvider().endpoint) && !confirmTransfer(getProvider())) return false;
    $('question').value = q;
    $('consent').checked = true;
    return true;
  }

  box.addEventListener('change', event => {
    if (event.target.matches('.ms-template') && event.target.value) box.querySelector('.ms-deep-q').value = event.target.value;
  });
  box.addEventListener('click', event => {
    const b = event.target.closest('button');
    if (!b) return;
    const d = b.dataset;
    if (d.mode) {
      state.mode = d.mode;
      return render();
    }
    if (d.pick) {
      const c = api.getCase();
      if (d.pick === 'explorer') return api.tab('explorer');
      if (d.pick === 'clear') api.select([]);
      if (d.pick === 'high') api.select(c.findings.filter(f => ['critical', 'high'].includes(f.severity)).flatMap(f => f.evidence));
      if (d.pick === 'chain') api.select(c.findings.filter(f => f.rule === 'COR-004').flatMap(f => f.evidence));
      box.querySelector('.ms-sel-info').textContent = selectionInfo();
      return;
    }
    if (d.run === 'stop') return $('cancelBatch').click();
    if (d.run === 'ask') {
      if (!api.selectedIds().length) return api.status('Select evidence and authorize the request first.');
      if (prepare()) $('ask').click();
    }
    if (d.run === 'batch' && prepare()) $('batch').click();
    if (d.run === 'review' && prepare()) {
      const notes = box.querySelector('.ms-notes').value.split('\n').map(s => s.trim()).filter(Boolean);
      $('kbRC3').value = JSON.stringify(notes.map((text, i) => ({id: `note-${i + 1}`, text})));
      $('agentsRC3').click();
    }
  });
  new MutationObserver(renderResult).observe($('answer'), {childList: true, characterData: true, subtree: true});
  details.addEventListener('toggle', () => details.open && render());
  render();
  return {render};
}
