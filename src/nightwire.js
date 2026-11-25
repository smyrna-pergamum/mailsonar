import {t} from './i18n.js';
// NIGHTWIRE rendering layer: local-only charts, graph and panels.
// Cytoscape.js handles the interactive entity graph; Apache ECharts handles
// dashboard, timeline and threat-intelligence charts. No external requests.
import cytoscape from 'cytoscape';
import * as echarts from 'echarts/core';
import { BarChart, LineChart, PieChart } from 'echarts/charts';
import {
  GridComponent,
  TooltipComponent,
  LegendComponent,
  DataZoomComponent
} from 'echarts/components';
import { CanvasRenderer } from 'echarts/renderers';
import {
  ENTITY_COLORS,
  ENTITY_LABELS,
  SEVERITY_COLORS,
  aiEvaluationMetrics,
  entityColor,
  formatDuration,
  formatPercent,
  hourlyBuckets,
  iocTypeCounts,
  matchedIndicators,
  mitreRows,
  severityColor,
  severityCounts
} from './nightwire-data.js';

echarts.use([
  BarChart,
  LineChart,
  PieChart,
  GridComponent,
  TooltipComponent,
  LegendComponent,
  DataZoomComponent,
  CanvasRenderer
]);

const THEME_KEY = 'maildfir.theme';
const charts = new Map();

export function preferredTheme() {
  try {
    return localStorage.getItem(THEME_KEY) === 'light' ? 'light' : 'dark';
  } catch {
    return 'dark';
  }
}

export function applyTheme(theme, button) {
  const next = theme === 'light' ? 'light' : 'dark';
  document.documentElement.dataset.theme = next;
  document.documentElement.style.colorScheme = next;
  try {
    localStorage.setItem(THEME_KEY, next);
  } catch {
    /* Storage can be unavailable; the in-memory theme still applies. */
  }
  if (button) {
    button.textContent = next === 'light' ? 'Dark theme' : 'Light theme';
    button.setAttribute('aria-pressed', String(next === 'light'));
    button.title = next === 'light' ? 'Switch to dark theme' : 'Switch to light theme';
  }
}

export function initTheme(button, onChange) {
  applyTheme(preferredTheme(), button);
  if (!button) return;
  button.addEventListener('click', () => {
    const next = document.documentElement.dataset.theme === 'light' ? 'dark' : 'light';
    applyTheme(next, button);
    onChange?.(next);
  });
}

export function themeTokens() {
  const style = getComputedStyle(document.documentElement);
  const read = (name, fallback) => style.getPropertyValue(name).trim() || fallback;
  return {
    ink: read('--ink', '#dceaf4'),
    muted: read('--muted', '#92a9bd'),
    line: read('--line', '#293d50'),
    panel: read('--panel', '#101a29'),
    accent: read('--accent', '#26f5d2'),
    yellow: read('--yellow', '#f5e642'),
    danger: read('--danger', '#ff597d'),
    violet: read('--violet', '#b56cff')
  };
}

function chart(id) {
  const host = document.getElementById(id);
  if (!host || !host.clientWidth) return null;
  let instance = charts.get(id);
  if (!instance || instance.isDisposed?.()) {
    instance = echarts.init(host);
    charts.set(id, instance);
  }
  return instance;
}

export function resizeCharts() {
  for (const instance of charts.values()) {
    if (!instance.isDisposed?.()) instance.resize();
  }
}

export function renderDashboard(panel, { events = [], findings = [] } = {}) {
  if (!panel) return;
  if (!panel.dataset.ready) {
    panel.innerHTML = `
      <article>
        <h2>Event activity / UTC</h2>
        <div id="chartActivity" class="chart chart-dashboard"></div>
        <p id="activityMeta" class="cyber-meta"></p>
      </article>
      <article>
        <h2>Finding classification</h2>
        <div id="chartSeverity" class="chart chart-dashboard"></div>
        <p id="severityMeta" class="cyber-meta"></p>
      </article>`;
    panel.dataset.ready = '1';
  }
  const tokens = themeTokens();
  const activity = hourlyBuckets(events, 24);
  const activityChart = document.getElementById('chartActivity');
  const activityMeta = document.getElementById('activityMeta');
  if (!activity.length) {
    if (activityChart) activityChart.hidden = true;
    if (activityMeta) activityMeta.textContent = 'No dated evidence imported.';
  } else {
    if (activityChart) activityChart.hidden = false;
    const instance = chart('chartActivity');
    if (instance) {
      const labels = activity.map(([time]) => time.slice(5, 16).replace('T', ' '));
      instance.setOption(
        {
          backgroundColor: 'transparent',
          animationDuration: 300,
          grid: { left: 42, right: 12, top: 14, bottom: 30 },
          tooltip: {
            trigger: 'axis',
            backgroundColor: tokens.panel,
            borderColor: tokens.line,
            textStyle: { color: tokens.ink }
          },
          xAxis: {
            type: 'category',
            data: labels,
            axisLine: { lineStyle: { color: tokens.line } },
            axisLabel: { color: tokens.muted, fontSize: 9, hideOverlap: true },
            axisTick: { show: false }
          },
          yAxis: {
            type: 'value',
            minInterval: 1,
            axisLabel: { color: tokens.muted, fontSize: 9 },
            splitLine: { lineStyle: { color: tokens.line, opacity: 0.5 } }
          },
          series: [
            {
              type: 'bar',
              data: activity.map(([, count]) => count),
              barMaxWidth: 18,
              itemStyle: { color: tokens.accent, opacity: 0.82 },
              emphasis: { itemStyle: { color: tokens.yellow, opacity: 1 } }
            }
          ]
        },
        true
      );
      instance.resize();
    }
    const total = activity.reduce((sum, [, count]) => sum + count, 0);
    if (activityMeta) {
      activityMeta.textContent = t('{start} – {end}: {count} dated events in {hours} hourly buckets.',{start:activity[0][0],end:activity.at(-1)[0],count:total,hours:activity.length});
    }
  }

  const severities = severityCounts(findings).filter((row) => row.count > 0);
  const severityChart = document.getElementById('chartSeverity');
  const severityMeta = document.getElementById('severityMeta');
  if (!findings.length) {
    if (severityChart) severityChart.hidden = true;
    if (severityMeta) severityMeta.textContent = 'No classified findings.';
  } else {
    if (severityChart) severityChart.hidden = false;
    const instance = chart('chartSeverity');
    if (instance) {
      instance.setOption(
        {
          backgroundColor: 'transparent',
          animationDuration: 300,
          grid: { left: 76, right: 34, top: 10, bottom: 20 },
          tooltip: {
            trigger: 'axis',
            axisPointer: { type: 'shadow' },
            backgroundColor: tokens.panel,
            borderColor: tokens.line,
            textStyle: { color: tokens.ink }
          },
          xAxis: {
            type: 'value',
            minInterval: 1,
            axisLabel: { color: tokens.muted, fontSize: 9 },
            splitLine: { lineStyle: { color: tokens.line, opacity: 0.5 } }
          },
          yAxis: {
            type: 'category',
            data: severities.map((row) => t(row.severity.toUpperCase())),
            axisLine: { lineStyle: { color: tokens.line } },
            axisLabel: { color: tokens.ink, fontSize: 9, fontFamily: 'monospace' },
            axisTick: { show: false }
          },
          series: [
            {
              type: 'bar',
              data: severities.map((row) => ({
                value: row.count,
                itemStyle: { color: row.color }
              })),
              barMaxWidth: 16,
              label: {
                show: true,
                position: 'right',
                color: tokens.muted,
                fontSize: 10
              }
            }
          ]
        },
        true
      );
      instance.resize();
    }
    if (severityMeta) {
      severityMeta.textContent = t('{count} findings · {summary}. Indicators are not confirmed incidents.',{count:findings.length,summary:severities.map(row=>`${t(row.severity)}: ${row.count}`).join(', ')});
    }
  }
}

export function renderTimeline(host, events, onSelect) {
  if (!host) return;
  if (!host.dataset.ready) {
    host.innerHTML = '<div id="timelineCanvas" class="chart chart-timeline"></div><p id="timelineMeta" class="cyber-meta"></p>';
    host.dataset.ready = '1';
  }
  const tokens = themeTokens();
  const series = hourlyBuckets(events, 0);
  const canvas = document.getElementById('timelineCanvas');
  const meta = document.getElementById('timelineMeta');
  const dated = (Array.isArray(events) ? events : []).filter((event) => Number.isFinite(Date.parse(event?.timestamp))).length;
  if (!series.length) {
    if (canvas) canvas.hidden = true;
    if (meta) meta.textContent = 'No dated evidence imported. Undated records remain in the log explorer.';
    return;
  }
  if (canvas) canvas.hidden = false;
  const instance = chart('timelineCanvas');
  if (!instance) return;
  const labels = series.map(([time]) => time);
  instance.off('click');
  instance.setOption(
    {
      backgroundColor: 'transparent',
      animationDuration: 300,
      grid: { left: 44, right: 18, top: 18, bottom: 62 },
      tooltip: {
        trigger: 'axis',
        backgroundColor: tokens.panel,
        borderColor: tokens.line,
        textStyle: { color: tokens.ink }
      },
      dataZoom: [
        { type: 'inside', start: 0, end: 100 },
        {
          type: 'slider',
          height: 18,
          bottom: 10,
          borderColor: tokens.line,
          fillerColor: `${tokens.accent}22`,
          handleStyle: { color: tokens.accent },
          textStyle: { color: tokens.muted }
        }
      ],
      xAxis: {
        type: 'category',
        data: labels,
        axisLine: { lineStyle: { color: tokens.line } },
        axisLabel: { color: tokens.muted, fontSize: 9, hideOverlap: true },
        axisTick: { show: false }
      },
      yAxis: {
        type: 'value',
        minInterval: 1,
        axisLabel: { color: tokens.muted, fontSize: 9 },
        splitLine: { lineStyle: { color: tokens.line, opacity: 0.5 } }
      },
      series: [
        {
          type: 'line',
          data: series.map(([, count]) => count),
          smooth: false,
          symbol: 'circle',
          symbolSize: 5,
          lineStyle: { color: tokens.accent, width: 2 },
          itemStyle: { color: tokens.accent },
          areaStyle: { color: `${tokens.accent}18` }
        }
      ]
    },
    true
  );
  instance.resize();
  instance.on('click', (params) => onSelect?.(params.name));
  if (meta) {
    meta.textContent = t('{count} records · {dated} dated · {hours} hourly buckets. Select an hour to filter.',{count:events.length,dated,hours:series.length});
  }
}

export function renderGraph(host, graph, { selected = '', onNode } = {}) {
  if (!host) return null;
  if (host._cy) {
    host._cy.destroy();
    host._cy = null;
  }
  host.replaceChildren();
  const nodes = Array.isArray(graph?.nodes) ? graph.nodes : [];
  const edges = Array.isArray(graph?.edges) ? graph.edges : [];
  if (!nodes.length) {
    const empty = document.createElement('p');
    empty.className = 'empty';
    empty.textContent = 'No graph nodes. Import evidence and build the graph.';
    host.append(empty);
    return null;
  }
  const tokens = themeTokens();
  const limit = 500;
  const keep = new Set(nodes.slice(0, limit).map((node) => node.id));
  if (selected) keep.add(selected);
  const visibleNodes = nodes.filter((node) => keep.has(node.id));
  const visibleEdges = edges.filter((edge) => keep.has(edge.source) && keep.has(edge.target));
  const elements = [
    ...visibleNodes.map((node) => ({
      data: {
        id: node.id,
        label: node.label || node.id,
        type: node.type || 'event',
        color: entityColor(node.type)
      }
    })),
    ...visibleEdges.map((edge, index) => ({
      data: {
        id: `edge-${index}`,
        source: edge.source,
        target: edge.target,
        relation: edge.relation || ''
      }
    }))
  ];
  const cy = cytoscape({
    container: host,
    elements,
    wheelSensitivity: 0.2,
    minZoom: 0.15,
    maxZoom: 2,
    style: [
      {
        selector: 'node',
        style: {
          'background-color': 'data(color)',
          'border-color': tokens.line,
          'border-width': 1,
          label: 'data(label)',
          color: tokens.ink,
          'font-size': 9,
          'font-family': 'monospace',
          'text-valign': 'bottom',
          'text-halign': 'center',
          'text-margin-y': 6,
          'text-wrap': 'wrap',
          'text-max-width': 120,
          width: 18,
          height: 18,
          'overlay-opacity': 0
        }
      },
      {
        selector: 'node[type = "event"]',
        style: {
          shape: 'round-rectangle',
          width: 15,
          height: 15
        }
      },
      {
        selector: 'node:selected',
        style: {
          'border-color': tokens.accent,
          'border-width': 3,
          width: 28,
          height: 28
        }
      },
      {
        selector: 'edge',
        style: {
          width: 1,
          'line-color': tokens.line,
          'curve-style': 'bezier',
          opacity: 0.7,
          'overlay-opacity': 0
        }
      },
      {
        selector: 'edge[relation = "ip"]',
        style: { 'line-color': ENTITY_COLORS.ip, opacity: 0.55 }
      },
      {
        selector: 'edge[relation = "sender"]',
        style: { 'line-color': ENTITY_COLORS.sender, opacity: 0.45 }
      },
      {
        selector: 'edge[relation = "message_id"]',
        style: { 'line-color': ENTITY_COLORS.message_id, opacity: 0.55 }
      }
    ],
    layout: visibleNodes.length > 120
      ? {
          name: 'concentric',
          animate: false,
          padding: 24,
          minNodeSpacing: 24,
          concentric: (node) => (node.id() === selected ? 3 : node.data('type') === 'event' ? 2 : 1),
          levelWidth: () => 2
        }
      : {
          name: 'cose',
          animate: false,
          padding: 30,
          nodeRepulsion: 14000,
          idealEdgeLength: 105,
          edgeElasticity: 100,
          gravity: 0.25,
          numIter: 1000,
          randomize: true
        }
  });
  cy.on('tap', 'node', (event) => onNode?.(event.target.id()));
  cy.ready(() => {
    cy.fit(undefined, 36);
    if (cy.zoom() > 1.7) {
      cy.zoom(1.7);
      cy.center();
    }
  });
  host._cy = cy;
  return cy;
}

export function renderMitre(container, findings) {
  if (!container) return;
  const rows = mitreRows(findings);
  const total = Array.isArray(findings) ? findings.length : 0;
  container.innerHTML = '';
  const note = document.createElement('p');
  note.className = 'cyber-meta';
  note.textContent = total
    ? `${total} findings mapped heuristically. Empty cells are not evidence of absence.`
    : 'No findings yet. All cells show zero observed findings, not absence of technique use.';
  container.append(note);
  const grid = document.createElement('div');
  grid.className = 'mitre-grid';
  for (const row of rows) {
    const column = document.createElement('section');
    column.className = 'mitre-tactic';
    const heading = document.createElement('h3');
    heading.textContent = row.tactic;
    column.append(heading);
    for (const technique of row.techniques) {
      const cell = document.createElement('button');
      cell.type = 'button';
      cell.className = `mitre-cell${technique.count ? ' observed' : ''}`;
      cell.dataset.technique = technique.id;
      cell.setAttribute('aria-label', `${technique.id} ${technique.name}: ${technique.count} findings`);
      const id = document.createElement('span');
      id.className = 'mitre-id';
      id.textContent = technique.id;
      const name = document.createElement('span');
      name.className = 'mitre-name';
      name.textContent = technique.name;
      const count = document.createElement('span');
      count.className = 'mitre-count';
      count.textContent = String(technique.count);
      cell.append(id, name, count);
      column.append(cell);
    }
    grid.append(column);
  }
  container.append(grid);
}

export function renderThreatIntel(container, table, { iocs = [], findings = [] } = {}) {
  if (!container) return;
  const stale = charts.get('chartTiTypes');
  if (stale) {
    stale.dispose();
    charts.delete('chartTiTypes');
  }
  container.innerHTML = '';
  const tokens = themeTokens();
  const types = iocTypeCounts(iocs);
  const matches = matchedIndicators(findings);
  const summary = document.createElement('div');
  summary.className = 'ti-summary';
  const cards = [
    ['Loaded indicators', String(iocs.length)],
    ['Indicator types', String(types.length)],
    ['Matched indicators', String(matches.length)],
    ['Local matches', String(matches.reduce((sum, row) => sum + row.count, 0))]
  ];
  for (const [label, value] of cards) {
    const card = document.createElement('div');
    card.className = 'metric';
    const small = document.createElement('small');
    small.textContent = label;
    const strong = document.createElement('strong');
    strong.textContent = value;
    card.append(small, strong);
    summary.append(card);
  }
  container.append(summary);

  const grid = document.createElement('div');
  grid.className = 'cyber-grid';
  const chartCard = document.createElement('article');
  chartCard.innerHTML = '<h2>Indicator types</h2><div id="chartTiTypes" class="chart chart-dashboard"></div><p id="tiTypeMeta" class="cyber-meta"></p>';
  const matchCard = document.createElement('article');
  matchCard.innerHTML = '<h2>Matched indicators</h2><div id="tiMatches"></div>';
  grid.append(chartCard, matchCard);
  container.append(grid);

  const meta = document.getElementById('tiTypeMeta');
  const typeChart = document.getElementById('chartTiTypes');
  if (!types.length) {
    if (typeChart) typeChart.hidden = true;
    if (meta) meta.textContent = 'No threat-intelligence indicators loaded.';
  } else {
    if (typeChart) typeChart.hidden = false;
    const instance = chart('chartTiTypes');
    if (instance) {
      instance.setOption(
        {
          backgroundColor: 'transparent',
          tooltip: {
            trigger: 'item',
            backgroundColor: tokens.panel,
            borderColor: tokens.line,
            textStyle: { color: tokens.ink }
          },
          color: [tokens.accent, tokens.yellow, tokens.violet, tokens.danger, '#68baff', '#42dca1'],
          legend: {
            bottom: 0,
            textStyle: { color: tokens.muted, fontSize: 10 }
          },
          series: [
            {
              type: 'pie',
              radius: ['42%', '70%'],
              center: ['50%', '44%'],
              data: types.map((row) => ({ name: row.type, value: row.count })),
              label: { color: tokens.ink, fontSize: 10 },
              itemStyle: { borderColor: tokens.panel, borderWidth: 2 }
            }
          ]
        },
        true
      );
      instance.resize();
    }
    if (meta) meta.textContent = `${iocs.length} indicators across ${types.length} types.`;
  }

  const matchHost = document.getElementById('tiMatches');
  if (matchHost) {
    matchHost.replaceChildren();
    if (!matches.length) {
      matchHost.append(Object.assign(document.createElement('p'), { className: 'empty', textContent: 'No local IOC matches in the current evidence.' }));
    } else {
      for (const row of matches.slice(0, 200)) {
        const item = document.createElement('div');
        item.className = 'ti-match';
        const value = document.createElement('code');
        value.textContent = row.value;
        const metaRow = document.createElement('span');
        metaRow.className = 'cyber-meta';
        metaRow.textContent = `${row.type} - ${row.count} match${row.count === 1 ? '' : 'es'} - source ${row.source}`;
        item.append(value, metaRow);
        matchHost.append(item);
      }
    }
  }

  if (table) {
    table.replaceChildren();
    if (!iocs.length) {
      table.append(Object.assign(document.createElement('p'), { className: 'empty', textContent: 'Import MISP or STIX JSON in Developer rules to populate this view.' }));
    } else {
      const wrapper = document.createElement('div');
      wrapper.className = 'tablewrap';
      const gridTable = document.createElement('table');
      gridTable.innerHTML = '<thead><tr><th>Type</th><th>Indicator</th><th>Source</th></tr></thead><tbody></tbody>';
      const body = gridTable.querySelector('tbody');
      for (const ioc of iocs.slice(0, 500)) {
        const tr = document.createElement('tr');
        for (const value of [ioc.type, ioc.value, ioc.id ?? '']) {
          const td = document.createElement('td');
          td.textContent = String(value);
          tr.append(td);
        }
        body.append(tr);
      }
      wrapper.append(gridTable);
      table.append(wrapper);
      if (iocs.length > 500) {
        table.append(Object.assign(document.createElement('p'), { className: 'cyber-meta', textContent: `Showing 500 of ${iocs.length} indicators.` }));
      }
    }
  }
}

export function renderAiEvaluation(container, { runs = [], model = '', endpoint = '', answer = '' } = {}) {
  if (!container) return;
  const metrics = aiEvaluationMetrics(runs);
  const configuredModel = model || 'Not configured';
  const endpointLabel = (() => {
    try {
      return endpoint ? new URL(endpoint).host : 'Not configured';
    } catch {
      return endpoint ? 'Invalid endpoint' : 'Not configured';
    }
  })();
  const cards = [
    ['AI requests', String(metrics.total)],
    ['Completed', String(metrics.completed)],
    ['Failed', String(metrics.failed)],
    ['Median latency', formatDuration(metrics.medianMs)],
    ['Records sent', String(metrics.eventsSent)],
    ['Reference integrity', formatPercent(metrics.referenceRate)]
  ];
  const cardHtml = cards
    .map(([label, value]) => `<div class="metric"><small>${label}</small><strong>${value}</strong></div>`)
    .join('');
  const gate = (name, value, status) =>
    `<tr><td>${name}</td><td>${value}</td><td><span class="gate ${status}">${status === 'pass' ? 'PASS' : status === 'warn' ? 'REVIEW' : status === 'fail' ? 'FAIL' : 'NOT EVALUATED'}</span></td></tr>`;
  const referenceStatus = metrics.claims ? (metrics.rejected ? 'warn' : 'pass') : 'not-evaluated';
  const jsonStatus = metrics.jsonMeasured ? (metrics.validJson === metrics.jsonMeasured ? 'pass' : 'warn') : 'not-evaluated';
  const sessionRows = runs
    .slice(-50)
    .reverse()
    .map((run) => {
      const refs = run.validation
        ? `${run.validation.accepted?.length ?? 0} accepted / ${run.validation.rejected?.length ?? 0} rejected`
        : 'Not Evaluated';
      return `<tr><td>${escapeHtml(run.time ?? '')}</td><td>${escapeHtml(run.mode ?? '')}</td><td>${escapeHtml(run.model ?? '')}</td><td>${Number(run.events) || 0}</td><td>${formatDuration(Number(run.ms))}</td><td>${run.ok ? 'Completed' : 'Failed'}</td><td>${refs}</td></tr>`;
    })
    .join('');
  container.innerHTML = `
    <div class="metrics eval-metrics">${cardHtml}</div>
    <div class="cyber-grid">
      <article>
        <h2>Session configuration</h2>
        <p class="cyber-meta">Provider host: ${escapeHtml(endpointLabel)}<br>Configured model: ${escapeHtml(configuredModel)}<br>Models observed: ${escapeHtml(metrics.models.join(', ') || 'None')}<br>Modes observed: ${escapeHtml(metrics.modes.join(', ') || 'None')}</p>
        <p>Metrics are measured from this workspace session only. API keys are never stored or displayed.</p>
      </article>
      <article>
        <h2>Quality gates</h2>
        <table class="eval-table"><thead><tr><th>Gate</th><th>Observed</th><th>Status</th></tr></thead><tbody>
          ${gate('Evidence references resolve', metrics.claims ? `${metrics.accepted} of ${metrics.claims} (${formatPercent(metrics.referenceRate)})` : 'No verifiable claims', referenceStatus)}
          ${gate('JSON response compliance', metrics.jsonMeasured ? `${metrics.validJson} of ${metrics.jsonMeasured} (${formatPercent(metrics.jsonRate)})` : 'No JSON responses measured', jsonStatus)}
          ${gate('Claim accuracy / precision / recall', 'No labeled benchmark dataset', 'not-evaluated')}
          ${gate('Human review required', 'All AI output is unverified', 'pass')}
          ${gate('Minimization before transfer', 'Enforced by frontend and Rust gateway', 'pass')}
          ${gate('AI command execution', 'AI output is text only; no command channel', 'pass')}
        </tbody></table>
      </article>
    </div>
    <article>
      <h2>Benchmark status</h2>
      <p>No labeled AI benchmark corpus is present in this workspace. Accuracy, precision, recall, false-positive rate and task success are therefore reported as Not Evaluated, never as achieved targets.</p>
      <table class="eval-table"><thead><tr><th>Benchmark</th><th>Result</th><th>Status</th></tr></thead><tbody>
        <tr><td>Evidence-reference integrity</td><td>${formatPercent(metrics.referenceRate)}</td><td><span class="gate ${referenceStatus}">${metrics.claims ? 'MEASURED' : 'NOT EVALUATED'}</span></td></tr>
        <tr><td>Hallucinated reference rate</td><td>${metrics.claims ? formatPercent(metrics.rejected / metrics.claims) : 'Not Evaluated'}</td><td><span class="gate ${referenceStatus}">${metrics.claims ? 'MEASURED' : 'NOT EVALUATED'}</span></td></tr>
        <tr><td>Claim accuracy</td><td>Not Evaluated</td><td><span class="gate not-evaluated">NOT EVALUATED</span></td></tr>
        <tr><td>Precision / recall / F1</td><td>Not Evaluated</td><td><span class="gate not-evaluated">NOT EVALUATED</span></td></tr>
        <tr><td>Task success rate</td><td>Not Evaluated</td><td><span class="gate not-evaluated">NOT EVALUATED</span></td></tr>
        <tr><td>Median request latency</td><td>${formatDuration(metrics.medianMs)}</td><td><span class="gate ${Number.isFinite(metrics.medianMs) ? 'pass' : 'not-evaluated'}">${Number.isFinite(metrics.medianMs) ? 'MEASURED' : 'NOT EVALUATED'}</span></td></tr>
      </tbody></table>
    </article>
    <article>
      <h2>Session runs</h2>
      ${sessionRows ? `<div class="tablewrap"><table><thead><tr><th>Time</th><th>Mode</th><th>Model</th><th>Records</th><th>Latency</th><th>Result</th><th>References</th></tr></thead><tbody>${sessionRows}</tbody></table></div>` : '<p class="empty">No AI requests in this session. Deterministic analysis works without an AI provider.</p>'}
      ${answer ? '<p class="cyber-meta">Latest AI output is present and remains unverified. Use "Check AI evidence references" in Developer rules to re-validate it.</p>' : ''}
    </article>`;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

export { SEVERITY_COLORS, severityColor, entityColor, ENTITY_LABELS };
