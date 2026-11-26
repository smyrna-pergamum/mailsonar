// Relationship-graph overview with display filters: scope (all records, finding
// evidence, attack chains), entity types, time range, minimum connections, text
// search and a node cap. Entities that appear in the same record are linked; the
// edge weight is the number of shared records.
import {t} from '../i18n.js';
import {tt} from './strings.js';
import {esc} from './agent-view.js';
import {renderGraph} from '../nightwire.js';
import {eventTime} from '../event-time.js';

const TYPES = [['sender', 'Accounts (sender/recipient)'], ['ip', 'IP addresses'], ['message_id', 'Message IDs']];

/** Pure builder, exported for tests. */
export function entityGraph(events, {types = ['sender', 'ip'], minDegree = 1, query = '', maxNodes = 300} = {}) {
  const nodes = new Map();
  const edges = new Map();
  const want = new Set(types);
  for (const e of events) {
    const ents = [];
    for (const [field, type] of [['sender', 'sender'], ['recipient', 'sender'], ['ip', 'ip'], ['message_id', 'message_id']]) {
      const value = String(e[field] ?? '').trim();
      if (!value || !want.has(type)) continue;
      const id = `${type}:${value.toLowerCase()}`;
      if (!nodes.has(id)) nodes.set(id, {id, label: value, type, records: 0, events: []});
      const node = nodes.get(id);
      node.records += 1;
      if (node.events.length < 200) node.events.push(e.id);
      if (!ents.includes(id)) ents.push(id);
    }
    for (let i = 0; i < ents.length; i++) {
      for (let j = i + 1; j < ents.length; j++) {
        const key = ents[i] < ents[j] ? `${ents[i]}|${ents[j]}` : `${ents[j]}|${ents[i]}`;
        edges.set(key, (edges.get(key) ?? 0) + 1);
      }
    }
  }
  const degree = new Map();
  for (const key of edges.keys()) {
    const [a, b] = key.split('|');
    degree.set(a, (degree.get(a) ?? 0) + 1);
    degree.set(b, (degree.get(b) ?? 0) + 1);
  }
  const q = query.trim().toLowerCase();
  let keep = [...nodes.values()].filter(n => (degree.get(n.id) ?? 0) >= minDegree);
  if (q) {
    const hits = new Set(keep.filter(n => n.label.toLowerCase().includes(q)).map(n => n.id));
    for (const key of edges.keys()) {
      const [a, b] = key.split('|');
      if (hits.has(a)) hits.add(b);
      if (hits.has(b)) hits.add(a);
    }
    keep = keep.filter(n => hits.has(n.id));
  }
  keep.sort((a, b) => (degree.get(b.id) ?? 0) - (degree.get(a.id) ?? 0) || b.records - a.records);
  const total = keep.length;
  keep = keep.slice(0, maxNodes);
  const ids = new Set(keep.map(n => n.id));
  const edgeList = [...edges].filter(([key]) => {
    const [a, b] = key.split('|');
    return ids.has(a) && ids.has(b);
  }).map(([key, weight]) => {
    const [source, target] = key.split('|');
    return {source, target, relation: target.split(':')[0], weight};
  });
  return {nodes: keep.map(n => ({...n, degree: degree.get(n.id) ?? 0})), edges: edgeList, total, truncated: total > keep.length};
}

export function mountGraphFilters({section, api}) {
  const card = document.createElement('article');
  card.className = 'ms-graph-filters';
  section.prepend(card);
  const state = {scope: 'findings', types: ['sender', 'ip'], minDegree: 1, query: '', from: '', to: '', maxNodes: 200, selected: ''};
  card.innerHTML = `<h2>${tt('Relationship overview')}</h2>
    <p class="ms-muted">${tt('Accounts, IPs and message IDs that appear in the same records are linked. Narrow the view with the filters; click a node to list its records.')}</p>
    <div class="ms-filter-bar">
      <label>${tt('Scope')}<select data-f="scope">
        <option value="findings" data-t="${esc('Evidence of findings')}">${esc(t('Evidence of findings'))}</option><option value="chain" data-t="${esc('Attack chains')}">${esc(t('Attack chains'))}</option>
        <option value="high" data-t="${esc('High-priority findings')}">${esc(t('High-priority findings'))}</option><option value="all" data-t="${esc('All records')}">${esc(t('All records'))}</option></select></label>
      <fieldset class="ms-types"><legend>${tt('Show')}</legend>${TYPES.map(([type, label]) => `<label><input type="checkbox" data-type="${type}" ${state.types.includes(type) ? 'checked' : ''}> ${tt(label)}</label>`).join('')}</fieldset>
      <label>${tt('Min. connections')} <output data-o="deg">1</output><input type="range" min="1" max="10" value="1" data-f="minDegree"></label>
      <label>${tt('Max. nodes')}<select data-f="maxNodes"><option>100</option><option selected>200</option><option>300</option><option>500</option></select></label>
      <label>${tt('From')}<input type="datetime-local" data-f="from"></label>
      <label>${tt('To')}<input type="datetime-local" data-f="to"></label>
      <label class="ms-grow">${tt('Search entity')}<input data-f="query" placeholder="elif.kaya / 203.0.113.66"></label>
    </div>
    <p class="ms-graph-meta ms-muted"></p>
    <div class="ms-graph-canvas" role="img" aria-label="Filtered relationship graph"></div>
    <div class="ms-graph-node" data-no-translate></div>`;
  const canvas = card.querySelector('.ms-graph-canvas');
  const meta = card.querySelector('.ms-graph-meta');
  const detail = card.querySelector('.ms-graph-node');
  let last = null;

  function scopedEvents() {
    const c = api.getCase();
    let ids = null;
    if (state.scope !== 'all') {
      const findings = c.findings.filter(f => state.scope === 'chain' ? f.rule === 'COR-004' : state.scope === 'high' ? ['critical', 'high'].includes(f.severity) : true);
      ids = new Set(findings.flatMap(f => f.evidence));
    }
    const from = state.from ? Date.parse(state.from) : -Infinity;
    const to = state.to ? Date.parse(state.to) : Infinity;
    return c.events.filter(e => {
      if (ids && !ids.has(e.id)) return false;
      if (!state.from && !state.to) return true;
      const time = eventTime(e.timestamp);
      return Number.isFinite(time) && time >= from && time <= to;
    });
  }

  function draw() {
    if (!canvas.offsetParent) return;
    const events = scopedEvents();
    last = entityGraph(events, state);
    meta.textContent = t('{records} records · {shown} of {total} entities · {edges} links', {records: events.length, shown: last.nodes.length, total: last.total, edges: last.edges.length});
    renderGraph(canvas, last, {selected: state.selected, onNode: id => showNode(id)});
  }

  function showNode(id) {
    state.selected = id;
    const node = last?.nodes.find(n => n.id === id);
    if (!node) return;
    const records = api.getCase().events.filter(e => node.events.includes(e.id)).slice(0, 50);
    detail.innerHTML = `<h3>${esc(node.label)} <span class="ms-badge">${esc(node.type)}</span> <small class="ms-muted">${node.records} ${tt('records')} · ${node.degree} ${tt('links')}</small></h3>
      <div class="ms-actions"><button type="button" data-search="${esc(node.label)}">${tt('Show in Log explorer')}</button><button type="button" data-focus="${esc(node.label)}">${tt('Focus graph on this entity')}</button></div>
      <ul class="ms-node-records">${records.map(e => `<li><button type="button" class="ms-link" data-ev="${esc(e.id)}">${esc(e.timestamp || '—')} · ${esc(e.action)} · ${esc(e.sender)} → ${esc(e.recipient)}</button></li>`).join('')}</ul>`;
  }

  card.addEventListener('input', event => {
    const el = event.target;
    if (el.dataset.type) state.types = TYPES.map(([type]) => type).filter(type => card.querySelector(`[data-type="${type}"]`).checked);
    if (el.dataset.f) state[el.dataset.f] = el.type === 'range' || el.dataset.f === 'maxNodes' ? Number(el.value) : el.value;
    if (el.dataset.f === 'minDegree') card.querySelector('[data-o="deg"]').textContent = el.value;
    clearTimeout(card._t);
    card._t = setTimeout(draw, 150);
  });
  card.addEventListener('click', event => {
    const b = event.target.closest('button');
    if (!b) return;
    if (b.dataset.ev) return api.inspect(b.dataset.ev);
    if (b.dataset.search) return api.searchExplorer(b.dataset.search);
    if (b.dataset.focus) {
      state.query = b.dataset.focus;
      card.querySelector('[data-f="query"]').value = b.dataset.focus;
      draw();
    }
  });
  section.addEventListener('ms:shown', draw);
  api.onLocale?.(draw);
  return {draw};
}
