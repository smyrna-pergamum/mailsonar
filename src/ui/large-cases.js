// Large investigations: millions of events streamed into an on-disk store.
// Import with live progress (batches, EPS, duplicates, failures), overview,
// paged findings and records, log sources, HELM on the whole store and
// "copy to workspace" for subsets that need the in-memory tools.
import {t} from '../i18n.js';
import {createAgentPanel, esc} from './agent-view.js';
import {runHelm} from './helm-run.js';
import {PROFILES} from './quick-ai.js';
import {sourcesHtml} from './sources-view.js';

const PAGE = 100;
const fmt = n => Number(n ?? 0).toLocaleString();
const mb = b => `${(Number(b ?? 0) / 1048576).toFixed(1)} MB`;

export function mountLargeCases({section, api}) {
  const state = {list: [], current: '', overview: null, view: 'overview', progress: {}, running: new Set(), findings: null, fpage: 0, fsev: '', records: null, rpage: 0, q: '', field: '', deep: false, log: []};
  section.innerHTML = `<div class="ms-large">
    <article class="ms-large-list"><h2>${esc(t('Large investigations'))}</h2>
      <p class="ms-muted">${esc(t('For evidence beyond the 100,000-record workspace: files are streamed in batches into an on-disk store, with checkpoints, de-duplication and cross-batch correlation. Millions of events per investigation.'))}</p>
      <div class="ms-ask"><input class="ms-new-name" placeholder="${esc(t('Name, e.g. IR-2026-001'))}"><button type="button" class="primary" data-act="create">${esc(t('Create'))}</button></div>
      <div class="ms-inv-items"></div></article>
    <article class="ms-large-body"></article></div>`;
  const listHost = section.querySelector('.ms-inv-items');
  const body = section.querySelector('.ms-large-body');
  const helm = createAgentPanel({onEvidence: id => showRecord(id)});

  async function refreshList() {
    try {
      state.list = await api.backend('inv_list');
      state.running = new Set(await api.backend('inv_running'));
    } catch (error) {
      api.status(String(error?.message ?? error));
    }
    listHost.innerHTML = state.list.length ? state.list.map(i => `<button type="button" class="ms-inv ${i.id === state.current ? 'active' : ''}" data-open="${esc(i.id)}">
        <strong>${esc(i.name)}</strong><small>${fmt(i.events)} ${esc(t('records'))} · ${fmt(i.findings)} ${esc(t('findings'))} · ${mb(i.bytes)}${state.running.has(i.id) ? ` · ${esc(t('importing…'))}` : ''}</small></button>`).join('')
      : `<p class="empty">${esc(t('No large investigation yet.'))}</p>`;
  }

  async function open(id) {
    state.current = id;
    state.findings = null;
    state.records = null;
    await Promise.all([refreshList(), loadOverview()]);
  }

  async function loadOverview() {
    if (!state.current) return render();
    try {
      state.overview = await api.backend('inv_overview', {id: state.current});
    } catch (error) {
      api.status(String(error?.message ?? error));
    }
    render();
  }

  function progressHtml() {
    const p = state.progress[state.current];
    if (!p && !state.running.has(state.current)) return '';
    const pct = p?.bytes ? Math.min(100, Math.round((p.bytes_read / p.bytes) * 100)) : 0;
    return `<div class="ms-ingest">
      <div class="ms-ingest-head"><strong>${esc(t(p?.state ?? 'importing'))}</strong> <span class="ms-muted">${esc(p?.file ?? '')}</span>
        ${state.running.has(state.current) ? `<button type="button" data-act="cancel">${esc(t('Stop (resumable)'))}</button>` : ''}</div>
      <div class="download-bar"><span style="width:${pct}%"></span></div>
      <p class="ms-muted">${fmt(p?.records)} ${esc(t('records'))} · ${fmt(p?.inserted)} ${esc(t('new'))} · ${fmt(p?.duplicates)} ${esc(t('duplicates'))}${p?.failed ? ` · ${fmt(p.failed)} ${esc(t('failed'))}` : ''} · ${fmt(p?.eps)} ${esc(t('events/s'))}${p?.batch ? ` · ${esc(t('batch'))} ${p.batch} (${fmt(p.batch_size)})` : ''}</p>
      ${state.log.length ? `<details><summary>${esc(t('Import log'))}</summary><pre>${esc(state.log.slice(-30).join('\n'))}</pre></details>` : ''}
    </div>`;
  }

  function overviewHtml(o) {
    const sev = Object.fromEntries((o.severities ?? []).map(s => [s.severity, s.count]));
    const top = (title, rows) => `<div><h4>${esc(t(title))}</h4><ol class="ms-top">${(rows ?? []).map(r => `<li><button type="button" class="ms-link" data-search="${esc(r.value)}">${esc(r.value)}</button> <span class="ms-muted">${fmt(r.count)}</span></li>`).join('')}</ol></div>`;
    const max = Math.max(1, ...(o.timeline ?? []).map(x => x[1]));
    const bars = (o.timeline ?? []).slice(-240).map(([h, c]) => `<span title="${esc(new Date(h * 1000).toISOString().slice(0, 13))}h · ${c}" style="height:${Math.max(2, Math.round((c / max) * 60))}px"></span>`).join('');
    return `<div class="metrics">${[['Records', o.events], ['Findings', o.findings], ['Critical', sev.critical ?? 0], ['High', sev.high ?? 0], ['Cross-batch findings', o.global_findings], ['Failed records', o.failures]]
      .map(([l, v]) => `<div class="metric"><small>${esc(t(l))}</small><strong>${fmt(v)}</strong></div>`).join('')}</div>
      ${o.first ? `<p class="ms-muted">${esc(new Date(o.first * 1000).toISOString())} → ${esc(new Date(o.last * 1000).toISOString())}</p>` : ''}
      ${bars ? `<div class="ms-spark" aria-label="Events per hour">${bars}</div>` : ''}
      <h4>${esc(t('Top rules'))}</h4><div class="ms-chips">${(o.rules ?? []).slice(0, 20).map(r => `<button type="button" class="ms-chip" data-rule="${esc(r.rule)}">${esc(r.rule)} · ${esc(r.severity)} · ${fmt(r.count)}</button>`).join('')}</div>
      <div class="ms-top-grid">${top('Top senders', o.top_senders)}${top('Top recipients', o.top_recipients)}${top('Top IPs', o.top_ips)}${top('Top actions', o.top_actions)}</div>`;
  }

  function findingsHtml() {
    const f = state.findings;
    if (!f) return `<p class="ms-muted">${esc(t('Loading…'))}</p>`;
    return `<div class="ms-actions"><label>${esc(t('Severity'))} <select data-f="fsev">${['', 'critical', 'high', 'medium', 'low', 'info'].map(s => `<option value="${s}" ${s === state.fsev ? 'selected' : ''}>${esc(s || t('All priorities'))}</option>`).join('')}</select></label>
        <span class="ms-muted">${fmt(f.total)} ${esc(t('findings'))}</span>${pager('f', state.fpage, f.total)}</div>
      <div class="tablewrap"><table data-no-translate><thead><tr><th>Rule</th><th>Severity</th><th>Description</th><th>Evidence</th><th>Scope</th></tr></thead><tbody>
      ${f.findings.map(x => `<tr><td>${esc(x.rule)}</td><td>${esc(x.severity)}</td><td>${esc(x.description)}</td><td>${(x.evidence ?? []).slice(0, 4).map(id => `<button type="button" class="ms-evid" data-ev="${esc(id)}">#${esc(String(id).split(':')[2])}</button>`).join('')}${x.evidence?.length > 4 ? ` +${x.evidence.length - 4}` : ''}</td><td>${esc(x.scope)}</td></tr>`).join('')}</tbody></table></div>`;
  }

  function recordsHtml() {
    const r = state.records;
    return `<div class="ms-actions"><input class="ms-rq" value="${esc(state.q)}" placeholder="${esc(t('Search sender, recipient, IP, message ID, action…'))}">
        <select class="ms-rf">${['', 'sender', 'recipient', 'ip', 'message_id', 'action', 'id'].map(f => `<option value="${f}" ${f === state.field ? 'selected' : ''}>${esc(f ? `= ${f}` : t('contains (any field)'))}</option>`).join('')}</select>
        <label><input type="checkbox" class="ms-rd" ${state.deep ? 'checked' : ''}> ${esc(t('also raw content (slower)'))}</label>
        <button type="button" class="primary" data-act="search">${esc(t('Search'))}</button>
        <button type="button" data-act="subset">${esc(t('Copy results to workspace'))}</button></div>
      ${r ? `<p class="ms-muted">${fmt(r.total)}${r.total_capped ? '+' : ''} ${esc(t('records'))} ${pager('r', state.rpage, r.total)}</p>
      <div class="tablewrap"><table data-no-translate><thead><tr><th>Time</th><th>Source</th><th>Sender</th><th>Recipient</th><th>IP</th><th>Action</th></tr></thead><tbody>
      ${r.events.map(e => `<tr><td><button type="button" class="ms-link" data-ev="${esc(e.id)}">${esc(e.timestamp || '—')}</button></td><td>${esc(e.source)}</td><td>${esc(e.sender)}</td><td>${esc(e.recipient)}</td><td>${esc(e.ip)}</td><td>${esc(e.action)}</td></tr>`).join('')}</tbody></table></div>` : ''}
      <pre class="ms-record" data-no-translate hidden></pre>`;
  }

  function pager(kind, page, total) {
    const pages = Math.max(1, Math.ceil(total / PAGE));
    return `<span class="ms-pager"><button type="button" data-page="${kind}:-1" ${page ? '' : 'disabled'}>‹</button> ${page + 1} / ${fmt(pages)} <button type="button" data-page="${kind}:1" ${page + 1 < pages ? '' : 'disabled'}>›</button></span>`;
  }

  function render() {
    if (!state.current || !state.overview) {
      body.innerHTML = `<h2>${esc(t('How it works'))}</h2><ol class="ms-howto">
        <li>${esc(t('Create an investigation and add files (CSV, JSONL, LOG, MBOX, GZ, ZIP stream line by line; EML, JSON, EVTX, XLSX up to 256 MB each).'))}</li>
        <li>${esc(t('Files are split into batches of 2,000–20,000 records depending on free memory, processed in parallel and committed in order with a checkpoint.'))}</li>
        <li>${esc(t('Stopping or a crash keeps everything already committed; adding the same file again resumes from the checkpoint. Identical events are stored once.'))}</li>
        <li>${esc(t('After import, cross-batch correlation links bursts, traces and attack chains across all files. HELM can query the whole store.'))}</li></ol>`;
      return;
    }
    const o = state.overview;
    body.innerHTML = `<div class="ms-inv-head"><h2>${esc(o.name ?? state.current)}</h2>
        <div class="ms-actions"><button type="button" class="primary" data-act="add">${esc(t('Add files'))}</button><button type="button" data-act="refresh">${esc(t('Refresh'))}</button><button type="button" class="cp-danger" data-act="delete">${esc(t('Delete'))}</button></div></div>
      ${progressHtml()}
      <div class="copilot-tabs">${[['overview', 'Overview'], ['findings', 'Findings'], ['records', 'Records'], ['sources', 'Log sources'], ['helm', 'HELM agent']].map(([id, label]) => `<button type="button" class="${state.view === id ? 'active' : ''}" data-view="${id}">${esc(t(label))}</button>`).join('')}</div>
      <div class="ms-inv-view"></div>`;
    const view = body.querySelector('.ms-inv-view');
    if (state.view === 'overview') view.innerHTML = overviewHtml(o);
    if (state.view === 'findings') view.innerHTML = findingsHtml();
    if (state.view === 'records') view.innerHTML = recordsHtml();
    if (state.view === 'sources') {
      view.innerHTML = sourcesHtml((o.files ?? []).map(f => ({source: f.name, events: {length: f.records}, profile: f.profile})))
        + `<div class="tablewrap"><table><thead><tr><th>${esc(t('File'))}</th><th>Status</th><th>${esc(t('records'))}</th><th>${esc(t('duplicates'))}</th><th>${esc(t('failed'))}</th><th>${esc(t('batches'))}</th><th>${esc(t('Time'))}</th></tr></thead><tbody data-no-translate>
        ${(o.files ?? []).map(f => `<tr><td>${esc(f.name)}<div class="ms-muted"><code>${esc(f.sha256.slice(0, 16))}…</code> · ${mb(f.bytes)}</div></td><td>${esc(f.status)}${f.error ? ` <span class="ms-warn">${esc(f.error)}</span>` : ''}</td><td>${fmt(f.records)}</td><td>${fmt(f.duplicates)}</td><td>${fmt(f.failed)}</td><td>${fmt(f.batches)} × ${fmt(f.batch_size)}</td><td>${(f.ms / 1000).toFixed(1)} s</td></tr>`).join('')}</tbody></table></div>`;
    }
    if (state.view === 'helm') {
      view.innerHTML = `<p class="ms-muted">${esc(t('HELM queries the on-disk store with filters, aggregates and searches; it never loads all records into memory.'))}</p>
        <div class="ms-profiles">${PROFILES.slice(0, 6).map(p => `<button type="button" class="ms-profile" data-helm="${esc(p.skill)}"><strong>${esc(t(p.title))}</strong><small>${esc(t(p.hint))}</small></button>`).join('')}</div>
        <div class="ms-ask"><input class="ms-helm-q" placeholder="${esc(t('Or ask your own question, e.g. Which accounts were compromised?'))}"><button type="button" class="primary" data-helm="">${esc(t('Ask HELM'))}</button></div>`;
      view.append(helm.el);
    }
  }

  async function loadFindings() {
    state.findings = await api.backend('inv_findings', {id: state.current, severity: state.fsev, rule: state.frule ?? '', offset: state.fpage * PAGE, limit: PAGE});
    render();
  }

  async function loadRecords() {
    state.records = await api.backend('inv_search', {id: state.current, q: state.q, field: state.field, deep: state.deep, offset: state.rpage * PAGE, limit: PAGE});
    render();
  }

  async function showRecord(id) {
    const [record] = await api.backend('inv_events', {id: state.current, ids: [id]});
    if (state.view !== 'records') {
      state.view = 'records';
      render();
    }
    const pre = body.querySelector('.ms-record');
    pre.hidden = false;
    pre.textContent = JSON.stringify(record ?? {missing: id}, null, 2);
    pre.scrollIntoView({block: 'nearest'});
  }

  section.addEventListener('click', async event => {
    const b = event.target.closest('button');
    if (!b) return;
    const d = b.dataset;
    try {
      if (d.act === 'create') {
        const name = section.querySelector('.ms-new-name').value.trim();
        if (!name) return;
        const created = await api.backend('inv_create', {name});
        section.querySelector('.ms-new-name').value = '';
        return open(created.id);
      }
      if (d.open) return open(d.open);
      if (d.view) {
        state.view = d.view;
        if (d.view === 'findings' && !state.findings) return loadFindings();
        return render();
      }
      if (d.act === 'refresh') return open(state.current);
      if (d.act === 'add') {
        const paths = await api.pickFiles();
        if (!paths?.length) return;
        state.log = [];
        await api.backend('inv_import', {id: state.current, paths});
        state.running.add(state.current);
        return render();
      }
      if (d.act === 'cancel') return api.backend('inv_cancel', {id: state.current});
      if (d.act === 'delete') {
        if (!confirm(t('Delete this investigation store? Original evidence files are not touched.'))) return;
        await api.backend('inv_delete', {id: state.current});
        state.current = '';
        state.overview = null;
        await refreshList();
        return render();
      }
      if (d.page) {
        const [kind, step] = d.page.split(':');
        if (kind === 'f') {
          state.fpage = Math.max(0, state.fpage + Number(step));
          return loadFindings();
        }
        state.rpage = Math.max(0, state.rpage + Number(step));
        return loadRecords();
      }
      if (d.rule) {
        state.view = 'findings';
        state.frule = d.rule;
        state.fpage = 0;
        return loadFindings();
      }
      if (d.search !== undefined) {
        Object.assign(state, {view: 'records', q: d.search, field: '', rpage: 0});
        return loadRecords();
      }
      if (d.act === 'search') {
        Object.assign(state, {q: body.querySelector('.ms-rq').value, field: body.querySelector('.ms-rf').value, deep: body.querySelector('.ms-rd').checked, rpage: 0});
        return loadRecords();
      }
      if (d.act === 'subset') {
        const limit = Number(prompt(t('How many matching records to copy into the workspace (max 100,000)?'), '20000'));
        if (!limit) return;
        const subset = await api.backend('inv_subset', {id: state.current, q: body.querySelector('.ms-rq').value, field: body.querySelector('.ms-rf').value, limit});
        return api.importSubset(subset.events, `${subset.name ?? state.current} (${t('subset')})`);
      }
      if (d.ev) return showRecord(d.ev);
      if (d.helm !== undefined) {
        const profile = PROFILES.find(p => p.skill === d.helm);
        const task = profile?.task ?? body.querySelector('.ms-helm-q').value.trim();
        if (!task) return;
        helm.start(profile ? t(profile.title) : task);
        const outcome = await runHelm({backend: api.backend, getCase: api.getCase, task, skill: profile?.skill ?? null, investigation: state.current, onStep: s => helm.step(s)});
        helm.finish(outcome);
      }
    } catch (error) {
      if (d.helm !== undefined) helm.fail(error);
      api.status(String(error?.message ?? error));
    }
  });
  section.addEventListener('change', event => {
    if (event.target.matches('[data-f="fsev"]')) {
      state.fsev = event.target.value;
      state.frule = '';
      state.fpage = 0;
      loadFindings();
    }
  });
  section.addEventListener('keydown', event => {
    if (event.target.matches('.ms-rq') && event.key === 'Enter') body.querySelector('[data-act="search"]').click();
  });

  if (window.__TAURI_INTERNALS__) {
    import('@tauri-apps/api/event').then(({listen}) => {
      listen('inv://progress', e => {
        const {investigation, progress} = e.payload;
        state.running.add(investigation);
        state.progress[investigation] = {...state.progress[investigation], ...progress};
        if (['starting', 'complete', 'failed', 'cancelled', 'correlating', 'correlated', 'already imported'].includes(progress.state)) {
          state.log.push(`${new Date().toLocaleTimeString()} ${progress.state} ${progress.file ?? ''} ${progress.error ?? ''}`);
        }
        if (investigation === state.current && section.offsetParent) {
          const host = body.querySelector('.ms-ingest');
          if (host) host.outerHTML = progressHtml();
          else render();
        }
      });
      listen('inv://done', async e => {
        state.running.delete(e.payload.investigation);
        const failed = e.payload.error ? ` ${e.payload.error}` : '';
        api.status(`Import finished${e.payload.cancelled ? ' (stopped; add the same files again to resume)' : ''}.${failed}`);
        await refreshList();
        if (e.payload.investigation === state.current) loadOverview();
      });
    }).catch(() => {});
  }
  section.addEventListener('ms:shown', () => refreshList());
  refreshList();
  render();
  return {refreshList};
}
