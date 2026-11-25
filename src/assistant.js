import {invoke} from '@tauri-apps/api/core';
import {open,save} from '@tauri-apps/plugin-dialog';
import {listen} from '@tauri-apps/api/event';
import './assistant.css';
import {
  NODE_PALETTE,
  PROVIDER_PRESETS,
  addNode,
  clamp,
  connectNodes,
  disconnectNodes,
  formatBytes,
  formatMs,
  newWorkflow,
  nodeDefaults,
  nodeSummary,
  providerPreset,
  removeNode,
  sampleWorkflow,
  validateWorkflowLocal,
  workflowForBackend,
  workflowFromText
} from './assistant-data.js';

const PROVIDER_KEY = 'maildfir.copilot.provider';

function esc(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function el(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}

function loadProvider() {
  try {
    const saved = JSON.parse(localStorage.getItem(PROVIDER_KEY) ?? '{}');
    const preset = providerPreset(saved.preset ?? 'embedded');
    return {
      preset: preset.id,
      endpoint: saved.endpoint || preset.endpoint,
      model: saved.model || (preset.id === 'embedded' ? 'local' : ''),
      key: ''
    };
  } catch {
    return {preset: 'embedded', endpoint: providerPreset('embedded').endpoint, model: 'local', key: ''};
  }
}

function saveProvider(provider) {
  try {
    localStorage.setItem(PROVIDER_KEY, JSON.stringify({preset: provider.preset, endpoint: provider.endpoint, model: provider.model}));
  } catch {
    // Storage can be unavailable in hardened webviews; the session still works.
  }
}

function hostStatus(host, message) {
  if (typeof host.status === 'function') host.status(message);
}

export function mountCopilot(host) {
  const nav = document.querySelector('aside nav');
  const main = document.querySelector('main');
  if (!nav || !main) throw new Error('Host layout is missing');

  const hasTauri = Boolean(window.__TAURI_INTERNALS__);
  const call = async (name, args) => {
    if (window.__TAURI_INTERNALS__) return invoke(name, args);
    if (import.meta.env.DEV && typeof window.__maildfirMock === 'function') {
      return window.__maildfirMock(name, args);
    }
    throw new Error('Tauri backend is unavailable in this browser preview.');
  };

  const navButton = document.createElement('button');
  navButton.dataset.tab = 'copilot';
  navButton.textContent = 'HELM agent';
  const settingsButton = nav.querySelector('[data-tab="settings"]');
  if (settingsButton) nav.insertBefore(navButton, settingsButton);
  else nav.append(navButton);

  const section = document.createElement('section');
  section.id = 'copilot';
  section.className = 'tab copilot';
  section.hidden = true;
  main.append(section);

  section.innerHTML = `
    <div class="copilot-header">
      <div>
        <h2>HELM // bounded DFIR agent</h2>
        <p>Read-only case tools in the Rust backend. BEACON is the floating product guide; HELM proposes tool calls and the backend validates and executes them. No shell, SQL, filesystem or production-email capability is exposed.</p>
      </div>
      <div class="copilot-status">
        <span class="cp-chip" id="cpCaseChip">No case</span>
        <span class="cp-chip" id="cpProviderChip">No provider</span>
        <span class="cp-chip" id="cpEngineChip">Engine unknown</span>
      </div>
    </div>
    <div class="copilot-tabs" role="tablist">
      <button data-cp-tab="assistant" class="active">Agent console</button>
      <button data-cp-tab="model">Model center</button>
      <button data-cp-tab="workflow">WAYPOINT</button>
      <button data-cp-tab="tools">Tool registry</button>
      <button data-cp-tab="sessions">Sessions</button>
      <button data-cp-tab="monitor">Execution monitor</button>
    </div>

    <div class="copilot-panel" data-cp-panel="assistant">
      <div class="cp-grid">
        <article class="cp-card">
          <h3>Provider</h3>
          <div class="cp-row">
            <label>Preset
              <select id="cpPreset">${PROVIDER_PRESETS.map((p) => `<option value="${esc(p.id)}">${esc(p.label)}</option>`).join('')}</select>
            </label>
          </div>
          <div class="cp-row">
            <label>Endpoint <input id="cpEndpoint" placeholder="https://.../v1/chat/completions" autocomplete="off"></label>
          </div>
          <div class="cp-row">
            <label>Model <input id="cpModel" list="cpModels" placeholder="model name" autocomplete="off"></label>
            <datalist id="cpModels"></datalist>
          </div>
          <div class="cp-row">
            <label>API key (session only) <input id="cpKey" type="password" placeholder="not stored" autocomplete="off"></label>
          </div>
          <p class="cp-note" id="cpProviderNote"></p>
          <div class="cp-actions">
            <button class="cp-primary" id="cpTest">Test connection</button>
            <button class="cp-ghost" id="cpDiscover">Discover models</button>
          </div>
          <p class="cp-muted" id="cpProviderResult">No connection test yet.</p>
          <label class="cp-consent">
            <input type="checkbox" id="cpConsent">
            <span id="cpConsentText">I authorize this provider to receive my investigation task and the tool outputs needed to answer it.</span>
          </label>
          <label class="cp-consent">
            <input type="checkbox" id="cpApproveReport">
            <span>Approve <code>draft_report</code> for this run. Without approval the agent receives a denial and must adapt.</span>
          </label>
          <div class="cp-note" id="cpPrivacyNote">For non-loopback providers the backend minimizes identifiers, removes raw record data and withholds indicator values before tool results are returned.</div>
        </article>

        <article class="cp-card">
          <h3>Investigation chat</h3>
          <div class="agent-chat" id="cpChat" aria-live="polite"></div>
          <div class="agent-compose">
            <textarea id="cpTask" placeholder="Example: Triage this case. Identify the strongest evidence, the accounts and IPs involved, and what cannot be concluded from the current snapshot."></textarea>
            <div class="cp-row" style="margin-top:8px">
              <label>Max iterations <input id="cpIterations" type="number" min="1" max="12" value="8"></label>
              <label>Token budget <input id="cpBudget" type="number" min="1000" max="32000" step="1000" value="12000"></label>
            </div>
            <div class="cp-actions">
              <button class="cp-primary" id="cpRun">Run agent</button>
              <button class="cp-ghost" id="cpCancel">Cancel</button>
              <button class="cp-ghost" id="cpClear">New conversation</button>
            </div>
            <div class="agent-meta" id="cpMeta"></div>
          </div>
        </article>
      </div>
      <div class="cp-grid" style="margin-top:12px">
        <article class="cp-card">
          <h3>Tool trace</h3>
          <div id="cpTrace"><p class="cp-muted">No tool calls yet.</p></div>
        </article>
        <article class="cp-card">
          <h3>Agent policy</h3>
          <p class="cp-muted">Tools are read-only and limited to the current case snapshot (maximum 20,000 records). The agent cannot modify evidence, write files, run commands or reach production systems.</p>
          <ul class="cp-muted">
            <li>Maximum 8 iterations by default, 24 tool calls, 12,000 estimated tokens.</li>
            <li>Sensitive tools are denied unless approved above.</li>
            <li>Cloud providers receive minimized aliases and no raw record data.</li>
            <li>Answers are analyst decision support, not proof of compromise.</li>
          </ul>
        </article>
      </div>
    </div>

    <div class="copilot-panel" data-cp-panel="model" hidden></div>
    <div class="copilot-panel" data-cp-panel="workflow" hidden></div>
    <div class="copilot-panel" data-cp-panel="tools" hidden></div>
    <div class="copilot-panel" data-cp-panel="sessions" hidden></div>
    <div class="copilot-panel" data-cp-panel="monitor" hidden></div>
  `;

  const state = {
    sub: 'assistant',
    provider: loadProvider(),
    consent: false,
    approveReport: false,
    messages: [
      {
        role: 'assistant',
        text: 'HELM ready. Import evidence, choose a provider, authorize the request, then ask a focused investigation question. I can inspect records, findings, timelines, graphs and local indicators with read-only tools.'
      }
    ],
    trace: [],
    runs: [],
    busy: false,
    currentSession: '',
    providerModels: [],
    hardware: null,
    engine: null,
    engineInfo: null,
    models: [],
    catalog: [],
    catalogFiles: [],
    catalogRepo: '',
    downloads: new Map(),
    workflow: sampleWorkflow(),
    selectedNode: null,
    pendingFrom: null,
    workflowOutcome: null,
    workflowApprovals: new Set(),
    workflowSaved: [],
    tools: [],
    sessions: []
  };

  const isLoopback = (endpoint) => {
    try {
      return ['localhost', '127.0.0.1', '[::1]', '::1'].includes(new URL(endpoint).hostname);
    } catch {
      return false;
    }
  };

  function providerChip() {
    const target = section.querySelector('#cpProviderChip');
    let host = 'invalid endpoint';
    try {
      host = new URL(state.provider.endpoint).host;
    } catch {
      // Keep the fallback.
    }
    target.textContent = `${state.provider.preset} // ${host}`;
    target.className = `cp-chip ${state.provider.endpoint ? (isLoopback(state.provider.endpoint) ? 'ok' : 'warn') : 'bad'}`;
    section.querySelector('#cpProviderNote').textContent = providerPreset(state.provider.preset).note;
    section.querySelector('#cpPrivacyNote').textContent = isLoopback(state.provider.endpoint)
      ? 'Loopback provider: the case snapshot stays on this device. The model still receives the tool results you authorize.'
      : 'Non-loopback provider: the backend minimizes identifiers, removes raw record data and withholds indicator values before tool results are returned. Report drafting is disabled.';
    section.querySelector('#cpConsentText').textContent = isLoopback(state.provider.endpoint)
      ? 'I authorize the loopback provider to receive my task and the tool outputs needed to answer it.'
      : 'I authorize this external provider to receive my investigation task and the minimized tool outputs needed to answer it.';
  }

  function caseChip() {
    const current = host.getCase?.() ?? {events: [], findings: []};
    const target = section.querySelector('#cpCaseChip');
    target.textContent = `${current.events?.length ?? 0} records // ${current.findings?.length ?? 0} findings`;
    target.className = `cp-chip ${current.events?.length ? 'ok' : 'warn'}`;
  }

  function renderChat() {
    const chat = section.querySelector('#cpChat');
    chat.replaceChildren();
    for (const message of state.messages) {
      const row = el('div', undefined, `agent-msg ${message.role}`);
      row.append(el('span', message.role, 'agent-role'));
      row.append(el('div', message.text, 'agent-body'));
      chat.append(row);
    }
    chat.scrollTop = chat.scrollHeight;
  }

  function renderTrace() {
    const target = section.querySelector('#cpTrace');
    if (!state.trace.length) {
      target.innerHTML = '<p class="cp-muted">No tool calls yet.</p>';
      return;
    }
    const rows = state.trace
      .map(
        (step) => `<tr title="${esc(JSON.stringify(step.arguments ?? {}))}">
          <td>${esc(step.step)}</td>
          <td>${esc(step.kind)}</td>
          <td>${esc(step.name)}</td>
          <td class="status-${esc(step.status)}">${esc(step.status)}</td>
          <td>${esc(formatMs(step.ms))}</td>
          <td>${esc(step.detail ?? '')}</td>
        </tr>`
      )
      .join('');
    target.innerHTML = `<table class="cp-table"><thead><tr><th>#</th><th>Kind</th><th>Name</th><th>Status</th><th>Time</th><th>Detail</th></tr></thead><tbody>${rows}</tbody></table>`;
  }

  function renderMeta(outcome) {
    const target = section.querySelector('#cpMeta');
    target.replaceChildren();
    if (!outcome) return;
    const chips = [
      [outcome.status, outcome.status],
      [`${outcome.iterations ?? 0} iterations`, ''],
      [`${outcome.tool_calls ?? 0} tools`, ''],
      [`~${outcome.tokens_estimated ?? 0} tokens`, ''],
      [formatMs(outcome.duration_ms), ''],
      [outcome.minimized ? 'minimized for cloud' : 'local snapshot', outcome.minimized ? 'warn' : 'ok']
    ];
    for (const [text, kind] of chips) {
      const chip = el('span', text, `cp-chip ${kind}`);
      target.append(chip);
    }
  }

  function addRun(run) {
    state.runs.unshift({time: new Date().toISOString(), ...run});
    state.runs = state.runs.slice(0, 80);
    if (state.sub === 'monitor') renderMonitor();
  }

  function refreshCase() {
    caseChip();
  }

  async function testProvider() {
    const target = section.querySelector('#cpProviderResult');
    target.textContent = 'Testing provider...';
    try {
      const result = await call('provider_test', {
        endpoint: state.provider.endpoint,
        model: state.provider.model,
        key: state.provider.key
      });
      state.providerModels = result.models ?? [];
      renderProviderModels();
      target.textContent = result.ok
        ? `Reachable (${result.latencyMs} ms). ${result.models.length} model(s) listed.${result.modelListed ? ' Configured model is present.' : result.models.length ? ' Configured model was not listed; verify the exact name.' : ''}`
        : `Provider rejected the request: ${result.detail ?? result.status}`;
      target.className = result.ok ? 'cp-muted status-ok' : 'cp-muted cp-error';
      providerChip();
      hostStatus(host, result.ok ? 'Provider connection verified.' : 'Provider connection failed.');
    } catch (error) {
      target.textContent = String(error);
      target.className = 'cp-muted cp-error';
    }
  }

  function renderProviderModels() {
    const list = section.querySelector('#cpModels');
    list.replaceChildren();
    for (const model of state.providerModels) {
      const option = document.createElement('option');
      option.value = model;
      list.append(option);
    }
  }

  async function discoverModels() {
    const target = section.querySelector('#cpProviderResult');
    target.textContent = 'Discovering models...';
    try {
      const result = await call('provider_test', {
        endpoint: state.provider.endpoint,
        model: state.provider.model,
        key: state.provider.key
      });
      state.providerModels = result.models ?? [];
      renderProviderModels();
      target.textContent = result.ok
        ? `${state.providerModels.length} model(s) discovered. ${state.providerModels.slice(0, 8).join(', ')}`
        : `Discovery failed: ${result.detail ?? result.status}`;
      target.className = result.ok ? 'cp-muted status-ok' : 'cp-muted cp-error';
    } catch (error) {
      target.textContent = String(error);
      target.className = 'cp-muted cp-error';
    }
  }

  async function runAgent() {
    if (state.busy) return;
    const task = section.querySelector('#cpTask').value.trim();
    if (!state.consent) {
      hostStatus(host, 'Authorize the provider before running the agent.');
      return;
    }
    if (!task) {
      hostStatus(host, 'Enter an investigation task.');
      return;
    }
    if (!state.provider.endpoint || !state.provider.model) {
      hostStatus(host, 'Configure a provider endpoint and model first.');
      return;
    }
    const current = host.getCase?.() ?? {events: [], findings: [], iocs: []};
    if (!current.events?.length) {
      hostStatus(host, 'Import evidence before running the agent.');
      return;
    }
    state.busy = true;
    state.consent = false;
    section.querySelector('#cpConsent').checked = false;
    section.querySelector('#cpRun').disabled = true;
    state.currentSession = `ses-ui-${Date.now().toString(36)}`;
    state.messages.push({role: 'user', text: task});
    renderChat();
    hostStatus(host, 'Agent is running. Tool results are bounded and case-scoped.');
    try {
      const outcome = await call('agent_run', {
        request: {
          session_id: state.currentSession,
          task,
          provider: {
            endpoint: state.provider.endpoint,
            model: state.provider.model,
            key: state.provider.key
          },
          events: current.events,
          findings: current.findings ?? [],
          iocs: current.iocs ?? [],
          allowed_tools: [],
          approvals: state.approveReport ? ['draft_report'] : [],
          max_iterations: clamp(section.querySelector('#cpIterations').value, 1, 12),
          token_budget: clamp(section.querySelector('#cpBudget').value, 1000, 32000)
        }
      });
      state.trace = outcome.trace ?? [];
      state.messages.push({
        role: 'assistant',
        text: outcome.answer?.trim() || `Agent status: ${outcome.status}${outcome.error ? ` - ${outcome.error}` : ''}`
      });
      renderChat();
      renderTrace();
      renderMeta(outcome);
      addRun({
        type: 'agent',
        status: outcome.status,
        model: outcome.model,
        host: outcome.endpoint_host,
        duration: outcome.duration_ms,
        iterations: outcome.iterations,
        tools: outcome.tool_calls,
        events: outcome.events,
        minimized: outcome.minimized,
        error: outcome.error,
        trace: outcome.trace
      });
      hostStatus(host, `Agent ${outcome.status}. Analyst verification required.`);
      await refreshSessions();
    } catch (error) {
      state.messages.push({role: 'system', text: `Agent error: ${String(error)}`});
      renderChat();
      addRun({type: 'agent', status: 'error', error: String(error), trace: []});
      hostStatus(host, String(error));
    } finally {
      state.busy = false;
      section.querySelector('#cpRun').disabled = false;
      refreshCase();
    }
  }

  async function cancelAgent() {
    if (!state.currentSession) return;
    try {
      await call('agent_cancel', {sessionId: state.currentSession});
      hostStatus(host, 'Cancellation requested. The backend checks between steps.');
    } catch (error) {
      hostStatus(host, String(error));
    }
  }

  function clearConversation() {
    if (state.busy) return;
    state.messages = [
      {
        role: 'assistant',
        text: 'New conversation. The case snapshot is unchanged; the backend does not carry prior tool results into this chat automatically.'
      }
    ];
    state.trace = [];
    state.currentSession = '';
    renderChat();
    renderTrace();
    renderMeta(null);
  }

  function cpShow(sub, fromNav = false) {
    state.sub = sub;
    section.querySelectorAll('[data-cp-tab]').forEach((button) => {
      button.classList.toggle('active', button.dataset.cpTab === sub);
    });
    section.querySelectorAll('[data-cp-panel]').forEach((panel) => {
      panel.hidden = panel.dataset.cpPanel !== sub;
    });
    if (fromNav) host.tab('copilot');
    refreshCase();
    if (sub === 'assistant') {
      renderChat();
      renderTrace();
    }
    if (sub === 'model') loadModelCenter();
    if (sub === 'workflow') renderWorkflow();
    if (sub === 'tools') renderTools();
    if (sub === 'sessions') renderSessions();
    if (sub === 'monitor') renderMonitor();
  }

  navButton.onclick = () => cpShow(state.sub, true);

  section.querySelectorAll('[data-cp-tab]').forEach((button) => {
    button.onclick = () => cpShow(button.dataset.cpTab);
  });

  // Provider form.
  const preset = section.querySelector('#cpPreset');
  const endpoint = section.querySelector('#cpEndpoint');
  const model = section.querySelector('#cpModel');
  const key = section.querySelector('#cpKey');
  preset.value = state.provider.preset;
  endpoint.value = state.provider.endpoint;
  model.value = state.provider.model;
  key.value = '';
  providerChip();

  const providerChanged = () => {
    state.provider.endpoint = endpoint.value.trim();
    state.provider.model = model.value.trim();
    state.provider.key = key.value;
    state.consent = false;
    section.querySelector('#cpConsent').checked = false;
    saveProvider(state.provider);
    providerChip();
  };

  preset.onchange = () => {
    const chosen = providerPreset(preset.value);
    state.provider.preset = chosen.id;
    state.provider.endpoint = chosen.endpoint;
    if (chosen.id === 'embedded') state.provider.model = 'local';
    endpoint.value = chosen.endpoint;
    model.value = state.provider.model;
    providerChanged();
  };
  endpoint.oninput = providerChanged;
  model.oninput = providerChanged;
  key.oninput = providerChanged;
  section.querySelector('#cpConsent').onchange = (event) => {
    state.consent = event.target.checked;
  };
  section.querySelector('#cpApproveReport').onchange = (event) => {
    state.approveReport = event.target.checked;
  };
  section.querySelector('#cpTest').onclick = testProvider;
  section.querySelector('#cpDiscover').onclick = discoverModels;
  section.querySelector('#cpRun').onclick = runAgent;
  section.querySelector('#cpCancel').onclick = cancelAgent;
  section.querySelector('#cpClear').onclick = clearConversation;

  // ---------------------------------------------------------------------
  // Model center
  // ---------------------------------------------------------------------
  async function loadModelCenter() {
    const panel = section.querySelector('[data-cp-panel="model"]');
    panel.innerHTML = '<p class="cp-muted">Reading hardware, engine and installed models...</p>';
    try {
      const [hardware, engineInfo, models, engine] = await Promise.all([
        call('embedded_hardware'),
        call('embedded_engine_info'),
        call('embedded_models'),
        call('embedded_status')
      ]);
      state.hardware = hardware;
      state.engineInfo = engineInfo;
      state.models = models;
      state.engine = engine;
    } catch (error) {
      panel.innerHTML = `<p class="cp-error">${esc(error)}</p>`;
      return;
    }
    renderModelCenter();
  }

  function renderModelCenter() {
    const panel = section.querySelector('[data-cp-panel="model"]');
    const hardware = state.hardware;
    const info = state.engineInfo;
    const engine = state.engine;
    const installed = state.models.length
      ? state.models
          .map(
            (asset) => `<div class="model-row">
              <div><strong>${esc(asset.name)}</strong><small>${esc(asset.id)} // ${formatBytes(asset.bytes)}</small></div>
              <div class="model-actions">
                <button class="cp-ghost" data-act="load-model" data-path="${esc(asset.path)}">Load</button>
                <button class="cp-ghost" data-act="hash-model" data-path="${esc(asset.path)}">Hash</button>
                <button class="cp-danger" data-act="delete-model" data-path="${esc(asset.path)}">Delete</button>
              </div>
            </div>`
          )
          .join('')
      : '<p class="cp-muted">No GGUF models installed. Search the Hugging Face catalogue below or place a model under the managed model directory.</p>';
    const catalog = state.catalog.length
      ? state.catalog
          .map(
            (item) => `<button class="catalog-item" data-act="catalog-repo" data-repo="${esc(item.id)}">
              ${esc(item.id)}<small>${esc(item.downloads)} downloads // ${esc(item.likes)} likes</small>
            </button>`
          )
          .join('')
      : '<p class="cp-muted">Search the catalogue or use a recommended query.</p>';
    const files = state.catalogFiles.length
      ? state.catalogFiles
          .map(
            (file) => `<div class="model-row">
              <div><strong>${esc(file.path)}</strong><small>${formatBytes(file.bytes)} // ${file.sha256 ? 'SHA-256 published by Hugging Face' : 'no LFS checksum published'}</small></div>
              <div class="model-actions"><button class="cp-primary" data-act="download" data-path="${esc(file.path)}" data-url="${esc(file.downloadUrl)}" data-sha="${esc(file.sha256)}">Download</button></div>
            </div>`
          )
          .join('')
      : state.catalogRepo
        ? '<p class="cp-muted">No GGUF files found in this repository.</p>'
        : '';
    const downloads = [...state.downloads.values()]
      .map(
        (item) => `<div class="model-row">
          <div style="flex:1"><strong>${esc(item.filename)}</strong><small>${esc(item.state)} // ${item.downloaded ? formatBytes(item.downloaded) : '0 B'}${item.total ? ` of ${formatBytes(item.total)}` : ''} // ${esc(item.message ?? '')}</small>
          <div class="download-bar"><span style="width:${clamp(item.percent, 0, 100)}%"></span></div></div>
          <div class="model-actions">
            <button class="cp-ghost" data-act="download-pause" data-id="${esc(item.id)}">Pause</button>
            <button class="cp-ghost" data-act="download-resume" data-id="${esc(item.id)}" title="${item.sha ? 'Resume from the current byte offset' : 'Requires a published SHA-256'}" ${item.sha ? '' : 'disabled'}>Resume</button>
            <button class="cp-danger" data-act="download-cancel" data-id="${esc(item.id)}">Cancel</button>
          </div>
        </div>`
      )
      .join('');
    panel.innerHTML = `
      <div class="cp-grid">
        <article class="cp-card">
          <h3>Hardware detected</h3>
          <div class="hardware-grid">
            <div class="metric"><small>Logical cores</small><strong>${esc(hardware?.logical_cores)}</strong></div>
            <div class="metric"><small>System RAM</small><strong>${esc(hardware?.total_ram_mb)} MB</strong></div>
            <div class="metric"><small>Architecture</small><strong>${esc(hardware?.arch)}</strong></div>
            <div class="metric"><small>Accelerators</small><strong>${esc((hardware?.accelerators ?? []).join(', ') || 'CPU')}</strong></div>
          </div>
          <p class="cp-muted">Recommended: ${esc(hardware?.recommended_threads)} threads, context ${esc(hardware?.recommended_context)}, ${esc(hardware?.recommended_gpu_layers)} GPU layers. CPU fallback is always available.</p>
          ${(hardware?.notes ?? []).map((note) => `<p class="cp-note">${esc(note)}</p>`).join('')}
          <div class="cp-actions"><button class="cp-ghost" data-act="refresh">Refresh hardware</button></div>
        </article>

        <article class="cp-card">
          <h3>Managed engine</h3>
          <div class="agent-meta">
            <span class="cp-chip ${engine?.running ? 'ok' : 'bad'}">${engine?.running ? 'process running' : 'process stopped'}</span>
            <span class="cp-chip ${engine?.ready ? 'ok' : 'warn'}">${engine?.ready ? 'ready' : 'not ready'}</span>
            <span class="cp-chip">${esc(engine?.detail ?? 'no probe yet')}</span>
          </div>
          <p class="cp-muted">Expected binary: <code>${esc(info?.expected_resource_binary)}</code></p>
          <p class="cp-muted">User binary: <code>${esc(info?.expected_user_binary)}</code></p>
          <p class="${info?.binary_found ? 'cp-muted status-ok' : 'cp-muted cp-error'}">${info?.binary_found ? `Engine found${info.version ? ` // version ${esc(info.version)}` : ''}` : 'Engine binary is not installed. The application still starts and all non-inference features work.'}</p>
          <div class="cp-row">
            <label>Context <input id="mfContext" type="number" min="512" max="32768" value="${esc(hardware?.recommended_context ?? 4096)}"></label>
            <label>Threads <input id="mfThreads" type="number" min="1" max="64" value="${esc(hardware?.recommended_threads ?? 4)}"></label>
            <label>GPU layers <input id="mfGpu" type="number" min="0" max="200" value="0"></label>
            <label>Port <input id="mfPort" type="number" min="1024" max="65535" value="18081"></label>
          </div>
          <div class="cp-actions">
            <button class="cp-primary" data-act="stop-engine">Unload model</button>
            <button class="cp-ghost" data-act="engine-status">Probe status</button>
          </div>
          <p class="cp-muted" id="mfEngineResult">${esc(engine?.endpoint ?? 'No engine endpoint.')}</p>
        </article>
      </div>

      <div class="cp-grid" style="margin-top:12px">
        <article class="cp-card">
          <h3>Installed models</h3>
          <div class="model-list">${installed}</div>
          <p class="cp-muted" id="mfHashResult"></p>
        </article>
        <article class="cp-card">
          <h3>Hugging Face catalogue</h3>
          <div class="cp-row">
            <label>Search GGUF repositories <input id="mfSearch" placeholder="qwen2.5 7b instruct gguf"></label>
          </div>
          <div class="cp-actions">
            <button class="cp-primary" data-act="catalog-search">Search</button>
            <button class="cp-ghost" data-act="catalog-recommend" data-query="qwen2.5 7b instruct gguf">Qwen 2.5</button>
            <button class="cp-ghost" data-act="catalog-recommend" data-query="llama 3.2 3b instruct gguf">Llama 3.2</button>
            <button class="cp-ghost" data-act="catalog-recommend" data-query="phi-4 mini instruct gguf">Phi-4 mini</button>
            <button class="cp-ghost" data-act="catalog-recommend" data-query="mistral 7b instruct gguf">Mistral</button>
          </div>
          <div class="catalog-list" style="margin-top:8px">${catalog}</div>
          ${state.catalogRepo ? `<p class="cp-muted">Files in ${esc(state.catalogRepo)}:</p><div class="model-list">${files}</div>` : ''}
          ${downloads ? `<p class="cp-muted" style="margin-top:10px">Active downloads</p><div class="model-list">${downloads}</div>` : ''}
          <p class="cp-note">Downloads are HTTPS-only from Hugging Face. Resume uses HTTP Range. Checksums are verified when the repository publishes an LFS SHA-256. The engine binary itself is never downloaded.</p>
        </article>
      </div>
    `;
  }

  async function handleModelAction(action, target) {
    const result = section.querySelector('#mfEngineResult');
    if (action === 'refresh') return loadModelCenter();
    if (action === 'stop-engine') {
      try {
        await call('embedded_stop');
        hostStatus(host, 'Model unloaded.');
        return loadModelCenter();
      } catch (error) {
        hostStatus(host, String(error));
        return;
      }
    }
    if (action === 'engine-status') {
      try {
        state.engine = await call('embedded_status');
        renderModelCenter();
        hostStatus(host, state.engine.detail);
      } catch (error) {
        hostStatus(host, String(error));
      }
      return;
    }
    if (action === 'load-model') {
      try {
        const start = await call('embedded_start', {
          modelPath: target.dataset.path,
          port: Number(section.querySelector('#mfPort').value || 18081),
          context: Number(section.querySelector('#mfContext').value || 4096),
          threads: Number(section.querySelector('#mfThreads').value || 4),
          gpuLayers: Number(section.querySelector('#mfGpu').value || 0)
        });
        state.provider = {
          preset: 'embedded',
          endpoint: start.endpoint,
          model: start.model,
          key: start.key
        };
        saveProvider(state.provider);
        section.querySelector('#cpPreset').value = 'embedded';
        section.querySelector('#cpEndpoint').value = start.endpoint;
        section.querySelector('#cpModel').value = start.model;
        section.querySelector('#cpKey').value = start.key;
        providerChip();
        if (result) result.textContent = 'Process spawned. Waiting for readiness...';
        const ready = await call('embedded_wait_ready', {timeoutMs: 90000});
        state.engine = await call('embedded_status');
        renderModelCenter();
        hostStatus(host, ready.ready ? `Model ready after ${formatMs(ready.elapsed_ms)}.` : `Model not ready: ${ready.detail}`);
      } catch (error) {
        hostStatus(host, String(error));
      }
      return;
    }
    if (action === 'hash-model') {
      try {
        const hash = await call('embedded_model_hash', {path: target.dataset.path});
        const output = section.querySelector('#mfHashResult');
        if (output) output.textContent = `SHA-256: ${hash}`;
        hostStatus(host, 'Model hash computed.');
      } catch (error) {
        hostStatus(host, String(error));
      }
      return;
    }
    if (action === 'delete-model') {
      if (!confirm('Delete this GGUF model from the managed model directory?')) return;
      try {
        await call('embedded_delete_model', {path: target.dataset.path});
        hostStatus(host, 'Model deleted.');
        return loadModelCenter();
      } catch (error) {
        hostStatus(host, String(error));
      }
      return;
    }
    if (action === 'catalog-search') {
      const query = section.querySelector('#mfSearch').value.trim();
      try {
        const result = await call('hf_search', {query, limit: 20});
        state.catalog = result.items ?? [];
        state.catalogRepo = '';
        state.catalogFiles = [];
        renderModelCenter();
      } catch (error) {
        hostStatus(host, String(error));
      }
      return;
    }
    if (action === 'catalog-recommend') {
      section.querySelector('#mfSearch').value = target.dataset.query;
      return handleModelAction('catalog-search', target);
    }
    if (action === 'catalog-repo') {
      try {
        state.catalogRepo = target.dataset.repo;
        const result = await call('hf_files', {repo: state.catalogRepo});
        state.catalogFiles = result.files ?? [];
        renderModelCenter();
      } catch (error) {
        hostStatus(host, String(error));
      }
      return;
    }
    if (action === 'download') {
      const url = target.dataset.url;
      const sha = target.dataset.sha || '';
      const filename = target.dataset.path.split('/').pop();
      const id = `dl-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`;
      try {
        await call('model_download_start', {id, url, filename, expectedSha256: sha || null});
        state.downloads.set(id, {
          id,
          filename,
          url,
          sha,
          state: 'starting',
          downloaded: 0,
          total: 0,
          percent: 0,
          message: 'queued'
        });
        renderModelCenter();
        hostStatus(host, 'Download queued. Progress is reported by the backend.');
      } catch (error) {
        hostStatus(host, String(error));
      }
      return;
    }
    if (action === 'download-pause' || action === 'download-resume' || action === 'download-cancel') {
      const id = target.dataset.id;
      if (action.endsWith('resume')) {
        const item = state.downloads.get(id);
        if (!item?.url) {
          hostStatus(host, 'This download cannot be resumed; start it again from the catalogue.');
          return;
        }
        if (!item.sha) {
          hostStatus(host, 'This repository does not publish an LFS SHA-256, so the backend cannot safely resume a partial file. Cancel and download again.');
          return;
        }
        let lastError = '';
        for (let attempt = 0; attempt < 3; attempt += 1) {
          try {
            await call('model_download_start', {
              id,
              url: item.url,
              filename: item.filename,
              expectedSha256: item.sha || null
            });
            state.downloads.set(id, {...item, state: 'resuming', message: 'resuming from the existing partial file'});
            renderModelCenter();
            hostStatus(host, 'Resume requested. The backend continues from the current byte offset.');
            return;
          } catch (error) {
            lastError = String(error);
            if (!lastError.includes('already active')) break;
            await new Promise((resolve) => setTimeout(resolve, 400));
          }
        }
        hostStatus(host, lastError);
        return;
      }
      try {
        await call('model_download_control', {id, action: action.endsWith('pause') ? 'pause' : 'cancel'});
      } catch (error) {
        hostStatus(host, String(error));
      }
      if (action.endsWith('cancel')) {
        state.downloads.delete(id);
        renderModelCenter();
      }
      return;
    }
  }

  section.querySelector('[data-cp-panel="model"]').addEventListener('click', (event) => {
    const target = event.target.closest('[data-act]');
    if (!target) return;
    handleModelAction(target.dataset.act, target);
  });

  if (hasTauri) {
    listen('model://progress', (event) => {
      const progress = event.payload;
      const previous = state.downloads.get(progress.id) ?? {};
      state.downloads.set(progress.id, {...previous, ...progress});
      if (state.sub === 'model') renderModelCenter();
      if (progress.state === 'complete') {
        hostStatus(host, `Download complete: ${progress.filename ?? progress.id}`);
        loadModelCenter();
      }
    }).catch(() => {});
  }

  // ---------------------------------------------------------------------
  // Workflow studio
  // ---------------------------------------------------------------------
  async function renderWorkflow() {
    const panel = section.querySelector('[data-cp-panel="workflow"]');
    if (!state.tools.length) {
      try {
        state.tools = await call('agent_tools');
      } catch {
        state.tools = [];
      }
    }
    if (!state.workflowSaved.length) {
      try {
        state.workflowSaved = await call('workflow_list');
      } catch {
        state.workflowSaved = [];
      }
    }
    const workflow = state.workflow;
    const nodes = workflow.nodes
      .map((node) => {
        const status = state.workflowOutcome?.steps?.find((s) => s.node === node.id)?.status;
        return `<div class="wf-node ${state.selectedNode === node.id ? 'selected' : ''}" data-node="${esc(node.id)}" style="left:${clamp(node.x, 0, 1000)}px;top:${clamp(node.y, 0, 680)}px">
          <span class="wf-port in" data-in="${esc(node.id)}" title="Input"></span>
          <span class="wf-port out" data-out="${esc(node.id)}" data-when="" title="Connect output"></span>
          ${node.kind === 'branch' ? `<span class="wf-port out false" data-out="${esc(node.id)}" data-when="false" title="False branch"></span>` : ''}
          <header data-drag="${esc(node.id)}"><span>${esc(node.label || node.id)}</span><small>${esc(node.kind)}</small></header>
          <div class="wf-summary">${esc(nodeSummary(node))}${status ? `<br><span class="status-${esc(status)}">${esc(status)}</span>` : ''}</div>
          <footer><span>${esc(node.id)} ${node.when ? `// ${esc(node.when)}` : ''}</span><button data-delete="${esc(node.id)}" title="Delete node">x</button></footer>
        </div>`;
      })
      .join('');
    const saved = state.workflowSaved.length
      ? state.workflowSaved
          .map(
            (item) => `<div class="model-row"><div><strong>${esc(item.name)}</strong><small>${esc(item.id)} // v${esc(item.version)} // ${esc(item.nodes)} nodes</small></div>
            <div class="model-actions"><button class="cp-ghost" data-wf="load-saved" data-id="${esc(item.id)}">Load</button><button class="cp-ghost" data-wf="versions" data-id="${esc(item.id)}">Versions</button><button class="cp-danger" data-wf="delete-saved" data-id="${esc(item.id)}">Delete</button></div></div>`
          )
          .join('')
      : '<p class="cp-muted">No saved workflows yet.</p>';
    const steps = state.workflowOutcome?.steps?.length
      ? state.workflowOutcome.steps
          .map(
            (step) => `<tr data-step="${esc(step.node)}"><td>${esc(step.node)}</td><td>${esc(step.kind)}</td><td class="status-${esc(step.status)}">${esc(step.status)}</td><td>${esc(formatMs(step.ms))}</td><td>${esc(step.detail)}</td></tr>`
          )
          .join('')
      : '';
    panel.innerHTML = `
      <div class="cp-card">
        <h3>WAYPOINT // workflow studio</h3>
        <p class="cp-muted">Validated DAG execution with node-level results, version history and approval checkpoints.</p>
        <div class="cp-row">
          <label>Workflow name <input id="wfName" value="${esc(workflow.name)}"></label>
          <label>Workflow id <input id="wfId" value="${esc(workflow.id)}"></label>
          <label>Version <input value="${esc(workflow.version)}" disabled></label>
        </div>
        <div class="cp-actions">
          <button class="cp-ghost" data-wf="new">New</button>
          <button class="cp-ghost" data-wf="validate">Validate</button>
          <button class="cp-primary" data-wf="save">Save</button>
          <button class="cp-ghost" data-wf="import">Import</button>
          <button class="cp-ghost" data-wf="export">Export</button>
          <button class="cp-ghost" data-wf="run">Approve &amp; run</button>
          <button class="cp-ghost" data-wf="cancel">Cancel</button>
        </div>
        <p class="cp-muted" id="wfStatus">${esc(state.workflowOutcome ? `${state.workflowOutcome.status} in ${formatMs(state.workflowOutcome.duration_ms)}` : 'Draft workflow. Validate before running.')}</p>
      </div>
      <div class="wf-layout" style="margin-top:10px">
        <aside class="wf-palette">
          <h3>Node palette</h3>
          ${NODE_PALETTE.map((item) => `<button data-add-kind="${esc(item.kind)}">${esc(item.label)}<small>${esc(item.hint)}</small></button>`).join('')}
          <h3 style="margin-top:12px">Saved</h3>
          <div class="model-list">${saved}</div>
        </aside>
        <div class="wf-canvas-wrap">
          <div class="wf-canvas" id="wfCanvas">
            <svg class="wf-edges" id="wfEdges"></svg>
            ${nodes}
          </div>
        </div>
        <aside class="wf-props" id="wfProps">
          <h3>Properties</h3>
          <p class="cp-muted">Select a node.</p>
        </aside>
      </div>
      <div class="cp-grid" style="margin-top:10px">
        <article class="cp-card">
          <h3>AI workflow draft</h3>
          <div class="cp-row">
            <label>Investigation task <textarea id="wfTask" rows="3" placeholder="Triage phishing reports first, then check inbox-rule changes and outbound volume."></textarea></label>
          </div>
          <div class="cp-actions"><button class="cp-primary" data-wf="generate">Generate draft</button></div>
          <p class="cp-note">The draft uses a compact case summary only. Review every node and argument before running. The backend validates the DAG and tool allowlist.</p>
        </article>
        <article class="cp-card">
          <h3>Execution results</h3>
          ${steps ? `<table class="cp-table"><thead><tr><th>Node</th><th>Kind</th><th>Status</th><th>Time</th><th>Detail</th></tr></thead><tbody>${steps}</tbody></table>` : '<p class="cp-muted">No execution yet.</p>'}
          <div class="wf-result" id="wfResultDetail">Select a result row to inspect its JSON.</div>
          ${state.workflowOutcome?.pending_node ? `<p class="cp-note">Approval required for node <strong>${esc(state.workflowOutcome.pending_node)}</strong>. Review the results and press Approve &amp; run again.</p>` : ''}
          ${state.workflowOutcome?.error ? `<p class="cp-error">${esc(state.workflowOutcome.error)}</p>` : ''}
        </article>
      </div>
    `;
    drawEdges();
    renderWorkflowProps();
    bindWorkflowCanvas();
  }

  function drawEdges() {
    const svg = section.querySelector('#wfEdges');
    if (!svg) return;
    svg.replaceChildren();
    const workflow = state.workflow;
    for (const node of workflow.nodes) {
      for (const dep of node.after ?? []) {
        const source = workflow.nodes.find((n) => n.id === dep);
        if (!source) continue;
        const x1 = source.x + 180;
        const y1 = source.y + 21;
        const x2 = node.x;
        const y2 = node.y + 21;
        const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
        const bend = Math.max(40, Math.abs(x2 - x1) / 2);
        path.setAttribute('d', `M ${x1} ${y1} C ${x1 + bend} ${y1}, ${x2 - bend} ${y2}, ${x2} ${y2}`);
        path.setAttribute('class', `wf-edge ${node.when ? `when-${node.when}` : ''}`);
        path.dataset.from = dep;
        path.dataset.to = node.id;
        path.addEventListener('click', () => {
          if (!confirm(`Remove connection ${dep} -> ${node.id}?`)) return;
          disconnectNodes(workflow, dep, node.id);
          renderWorkflow();
        });
        svg.append(path);
        if (node.when) {
          const label = document.createElementNS('http://www.w3.org/2000/svg', 'text');
          label.setAttribute('x', String((x1 + x2) / 2));
          label.setAttribute('y', String((y1 + y2) / 2 - 4));
          label.setAttribute('class', 'wf-edge-label');
          label.textContent = node.when;
          svg.append(label);
        }
      }
    }
  }

  function renderWorkflowProps() {
    const props = section.querySelector('#wfProps');
    if (!props) return;
    const node = state.workflow.nodes.find((n) => n.id === state.selectedNode);
    if (!node) {
      props.innerHTML = '<h3>Properties</h3><p class="cp-muted">Select a node. Drag from an output port to an input port to connect nodes. Click an edge to remove it.</p>';
      return;
    }
    const toolOptions = state.tools
      .map((tool) => `<option value="${esc(tool.name)}" ${tool.name === node.tool ? 'selected' : ''}>${esc(tool.name)}${tool.sensitive ? ' (approval)' : ''}</option>`)
      .join('');
    props.innerHTML = `
      <h3>Node ${esc(node.id)}</h3>
      <div class="cp-field"><label>Label <input id="wfLabel" value="${esc(node.label)}"></label></div>
      <div class="cp-field"><label>Kind <input value="${esc(node.kind)}" disabled></label></div>
      ${node.kind === 'tool' ? `<div class="cp-field"><label>Tool <select id="wfTool">${toolOptions}</select></label></div>` : ''}
      <div class="cp-field"><label>When (branch output) <select id="wfWhen">
        <option value="" ${!node.when ? 'selected' : ''}>always / true</option>
        <option value="true" ${node.when === 'true' ? 'selected' : ''}>true</option>
        <option value="false" ${node.when === 'false' ? 'selected' : ''}>false</option>
      </select></label></div>
      <div class="cp-field"><label>Arguments JSON <textarea id="wfArgs" rows="7">${esc(JSON.stringify(node.args ?? {}, null, 2))}</textarea></label></div>
      <div class="cp-field"><label>Depends on <input value="${esc((node.after ?? []).join(', '))}" disabled></label></div>
      <div class="cp-actions"><button class="cp-primary" id="wfApply">Apply node</button></div>
      <p class="cp-error" id="wfPropError"></p>
    `;
    props.querySelector('#wfApply').onclick = () => {
      try {
        const args = JSON.parse(props.querySelector('#wfArgs').value || '{}');
        if (!args || typeof args !== 'object' || Array.isArray(args)) throw new Error('Arguments must be an object');
        node.label = props.querySelector('#wfLabel').value.slice(0, 80);
        node.args = args;
        const when = props.querySelector('#wfWhen').value;
        node.when = when === 'true' || when === 'false' ? when : null;
        if (node.kind === 'tool') node.tool = props.querySelector('#wfTool').value;
        renderWorkflow();
        hostStatus(host, `Node ${node.id} updated.`);
      } catch (error) {
        props.querySelector('#wfPropError').textContent = String(error);
      }
    };
  }

  function bindWorkflowCanvas() {
    const canvas = section.querySelector('#wfCanvas');
    if (!canvas) return;
    canvas.querySelectorAll('[data-delete]').forEach((button) => {
      button.onclick = (event) => {
        event.stopPropagation();
        removeNode(state.workflow, button.dataset.delete);
        if (state.selectedNode === button.dataset.delete) state.selectedNode = null;
        renderWorkflow();
      };
    });
    canvas.querySelectorAll('[data-out]').forEach((port) => {
      port.onclick = (event) => {
        event.stopPropagation();
        state.pendingFrom = {id: port.dataset.out, when: port.dataset.when || null};
        hostStatus(host, `Output ${port.dataset.out} selected. Click an input port to connect.`);
      };
    });
    canvas.querySelectorAll('[data-in]').forEach((port) => {
      port.onclick = (event) => {
        event.stopPropagation();
        if (!state.pendingFrom) {
          state.selectedNode = port.dataset.in;
          renderWorkflow();
          return;
        }
        const from = state.pendingFrom;
        connectNodes(state.workflow, from.id, port.dataset.in, from.when);
        state.pendingFrom = null;
        renderWorkflow();
      };
    });
    canvas.querySelectorAll('[data-node]').forEach((node) => {
      node.onclick = () => {
        if (state.selectedNode !== node.dataset.node) {
          state.selectedNode = node.dataset.node;
          renderWorkflow();
        }
      };
    });
    canvas.querySelectorAll('[data-drag]').forEach((header) => {
      header.onpointerdown = (event) => {
        event.preventDefault();
        const id = header.dataset.drag;
        const node = state.workflow.nodes.find((n) => n.id === id);
        const startX = event.clientX;
        const startY = event.clientY;
        const originX = node.x;
        const originY = node.y;
        const move = (moveEvent) => {
          node.x = clamp(originX + moveEvent.clientX - startX, 0, 1000);
          node.y = clamp(originY + moveEvent.clientY - startY, 0, 680);
          const element = canvas.querySelector(`[data-node="${CSS.escape(id)}"]`);
          if (element) {
            element.style.left = `${node.x}px`;
            element.style.top = `${node.y}px`;
          }
          drawEdges();
        };
        const up = () => {
          document.removeEventListener('pointermove', move);
          document.removeEventListener('pointerup', up);
          state.selectedNode = id;
          renderWorkflow();
        };
        document.addEventListener('pointermove', move);
        document.addEventListener('pointerup', up);
      };
    });
    canvas.querySelectorAll('.cp-table tr[data-step]').forEach((row) => {
      row.onclick = () => {
        const step = state.workflowOutcome?.steps?.find((s) => s.node === row.dataset.step);
        const detail = section.querySelector('#wfResultDetail');
        if (step && detail) detail.textContent = JSON.stringify(step.result, null, 2);
      };
    });
  }

  async function handleWorkflowAction(action, target) {
    const workflow = state.workflow;
    const setStatus = (text, error = false) => {
      const output = section.querySelector('#wfStatus');
      if (output) {
        output.textContent = text;
        output.className = error ? 'cp-error' : 'cp-muted';
      }
    };
    if (action === 'new') {
      state.workflow = newWorkflow();
      state.selectedNode = null;
      state.workflowOutcome = null;
      return renderWorkflow();
    }
    if (action === 'validate') {
      const local = validateWorkflowLocal(workflow);
      try {
        const remote = await call('workflow_validate', {workflow: workflowForBackend(workflow)});
        setStatus(remote.ok ? `Valid. Order: ${remote.order.join(' -> ')}` : remote.errors.join('; '), !remote.ok);
      } catch (error) {
        setStatus(String(error), true);
      }
      return local.ok;
    }
    if (action === 'save') {
      try {
        const saved = await call('workflow_save', {workflow: workflowForBackend(workflow)});
        state.workflow = saved;
        state.workflowSaved = await call('workflow_list');
        renderWorkflow();
        hostStatus(host, `Workflow saved as version ${saved.version}.`);
      } catch (error) {
        setStatus(String(error), true);
      }
      return;
    }
    if (action === 'import') {
      try {
        const path = await open({multiple: false, filters: [{name: 'Workflow', extensions: ['json']}]});
        if (!path) return;
        state.workflow = await call('workflow_import', {path});
        state.selectedNode = null;
        state.workflowOutcome = null;
        renderWorkflow();
        hostStatus(host, 'Workflow imported and validated.');
      } catch (error) {
        setStatus(String(error), true);
      }
      return;
    }
    if (action === 'export') {
      try {
        const path = await save({defaultPath: `${workflow.id}.json`, filters: [{name: 'Workflow', extensions: ['json']}]});
        if (!path) return;
        await call('export_report', {path, report: workflowForBackend(workflow)});
        hostStatus(host, 'Workflow exported.');
      } catch (error) {
        setStatus(String(error), true);
      }
      return;
    }
    if (action === 'load-saved') {
      try {
        state.workflow = await call('workflow_get', {id: target.dataset.id});
        state.selectedNode = null;
        state.workflowOutcome = null;
        renderWorkflow();
        hostStatus(host, 'Saved workflow loaded.');
      } catch (error) {
        setStatus(String(error), true);
      }
      return;
    }
    if (action === 'versions') {
      try {
        const versions = await call('workflow_versions', {id: target.dataset.id});
        setStatus(versions.length ? versions.map((v) => `v${v.version} (${v.nodes} nodes, ${v.updated_at || 'unknown time'})`).join(' | ') : 'No archived versions yet.');
      } catch (error) {
        setStatus(String(error), true);
      }
      return;
    }
    if (action === 'delete-saved') {
      if (!confirm('Delete this saved workflow and its version history?')) return;
      try {
        await call('workflow_delete', {id: target.dataset.id});
        state.workflowSaved = await call('workflow_list');
        renderWorkflow();
      } catch (error) {
        setStatus(String(error), true);
      }
      return;
    }
    if (action === 'generate') {
      const task = section.querySelector('#wfTask').value.trim();
      if (!task) return setStatus('Enter a workflow task first.', true);
      if (!state.provider.endpoint || !state.provider.model) return setStatus('Configure a provider first.', true);
      if (!state.consent) return setStatus('Authorize the provider before generating a draft.', true);
      try {
        setStatus('Generating a draft from a compact case summary...');
        const current = host.getCase?.() ?? {events: [], findings: []};
        const rules = [...new Set((current.findings ?? []).map((f) => f.rule))].slice(0, 12);
        state.workflow = await call('workflow_generate', {
          request: {
            provider: {
              endpoint: state.provider.endpoint,
              model: state.provider.model,
              key: state.provider.key
            },
            task,
            events: current.events?.length ?? 0,
            findings: current.findings?.length ?? 0,
            top_rules: rules
          }
        });
        state.selectedNode = null;
        state.workflowOutcome = null;
        renderWorkflow();
        setStatus('Draft generated. Review every node and argument, then press Approve & run.');
      } catch (error) {
        setStatus(String(error), true);
      }
      return;
    }
    if (action === 'run') {
      const current = host.getCase?.() ?? {events: [], findings: [], iocs: []};
      if (!current.events?.length) return setStatus('Import evidence first.', true);
      const runId = `run-${Date.now().toString(36)}`;
      state.currentRun = runId;
      try {
        setStatus('Running validated workflow...');
        const provider = state.provider.endpoint && state.provider.model && state.consent
          ? {endpoint: state.provider.endpoint, model: state.provider.model, key: state.provider.key}
          : null;
        const outcome = await call('workflow_run', {
          request: {
            run_id: runId,
            workflow: workflowForBackend(workflow),
            events: current.events,
            findings: current.findings ?? [],
            iocs: current.iocs ?? [],
            approvals: [...state.workflowApprovals],
            provider
          }
        });
        state.workflowOutcome = outcome;
        if (outcome.pending_node) state.workflowApprovals.add(outcome.pending_node);
        renderWorkflow();
        addRun({
          type: 'workflow',
          status: outcome.status,
          model: provider?.model ?? 'local tools',
          host: provider ? 'configured provider' : 'local',
          duration: outcome.duration_ms,
          iterations: outcome.steps.length,
          tools: outcome.steps.length,
          events: current.events.length,
          minimized: Boolean(outcome.steps.some((s) => s.kind === 'agent')),
          error: outcome.error,
          trace: outcome.steps
        });
        hostStatus(host, `Workflow ${outcome.status}.`);
      } catch (error) {
        setStatus(String(error), true);
      }
      return;
    }
    if (action === 'cancel') {
      if (!state.currentRun) return setStatus('No active workflow run.', true);
      try {
        await call('workflow_cancel', {runId: state.currentRun});
        setStatus('Cancellation requested.');
      } catch (error) {
        setStatus(String(error), true);
      }
      return;
    }
  }

  section.querySelector('[data-cp-panel="workflow"]').addEventListener('click', (event) => {
    const add = event.target.closest('[data-add-kind]');
    if (add) {
      const node = addNode(state.workflow, add.dataset.addKind);
      state.selectedNode = node.id;
      renderWorkflow();
      return;
    }
    const action = event.target.closest('[data-wf]');
    if (action) {
      handleWorkflowAction(action.dataset.wf, action);
      return;
    }
    const row = event.target.closest('tr[data-step]');
    if (row) {
      const step = state.workflowOutcome?.steps?.find((s) => s.node === row.dataset.step);
      const detail = section.querySelector('#wfResultDetail');
      if (step && detail) detail.textContent = JSON.stringify(step.result, null, 2);
    }
  });

  section.querySelector('[data-cp-panel="workflow"]').addEventListener('change', (event) => {
    if (event.target.id === 'wfName') {
      state.workflow.name = event.target.value;
    }
    if (event.target.id === 'wfId') {
      state.workflow.id = event.target.value;
    }
  });

  // ---------------------------------------------------------------------
  // Tool registry, sessions, monitor
  // ---------------------------------------------------------------------
  async function renderTools() {
    const panel = section.querySelector('[data-cp-panel="tools"]');
    try {
      state.tools = await call('agent_tools');
    } catch (error) {
      panel.innerHTML = `<p class="cp-error">${esc(error)}</p>`;
      return;
    }
    panel.innerHTML = `<div class="cp-grid">${state.tools
      .map(
        (tool) => `<article class="cp-card">
          <h3>${esc(tool.name)} ${tool.sensitive ? '<span class="cp-chip bad">approval</span>' : '<span class="cp-chip ok">read-only</span>'}</h3>
          <p class="cp-muted">${esc(tool.description)}</p>
          <details><summary class="cp-muted">Parameters</summary><pre class="wf-result">${esc(JSON.stringify(tool.parameters, null, 2))}</pre></details>
        </article>`
      )
      .join('')}</div>`;
  }

  async function refreshSessions() {
    try {
      state.sessions = await call('agent_sessions');
    } catch {
      // Session persistence is optional for the current operation.
    }
  }

  async function renderSessions() {
    const panel = section.querySelector('[data-cp-panel="sessions"]');
    await refreshSessions();
    panel.innerHTML = state.sessions.length
      ? `<div class="cp-card"><h3>Saved agent sessions</h3><table class="cp-table"><thead><tr><th>Task</th><th>Model</th><th>Status</th><th>Tools</th><th>Updated</th><th></th></tr></thead><tbody>${state.sessions
          .map(
            (session) => `<tr><td>${esc(session.task)}</td><td>${esc(session.model)}<br><small>${esc(session.endpoint_host)}</small></td><td class="status-${esc(session.status)}">${esc(session.status)}</td><td>${esc(session.tool_calls)}</td><td>${esc(session.updated_at)}</td><td><button class="cp-ghost" data-session="load" data-id="${esc(session.id)}">Open</button> <button class="cp-danger" data-session="delete" data-id="${esc(session.id)}">Delete</button></td></tr>`
          )
          .join('')}</tbody></table></div>`
      : '<div class="cp-card"><p class="cp-muted">No saved sessions yet. Completed agent runs are stored locally in the application data directory.</p></div>';
  }

  section.querySelector('[data-cp-panel="sessions"]').addEventListener('click', async (event) => {
    const button = event.target.closest('[data-session]');
    if (!button) return;
    const id = button.dataset.id;
    try {
      if (button.dataset.session === 'delete') {
        if (!confirm('Delete this saved session?')) return;
        await call('agent_session_delete', {id});
        return renderSessions();
      }
      const record = await call('agent_session_get', {id});
      state.messages = [
        {role: 'user', text: record.task},
        {role: 'assistant', text: record.answer || `Status: ${record.status}`}
      ];
      state.trace = record.trace ?? [];
      state.currentSession = record.id;
      cpShow('assistant');
      renderMeta(record);
      hostStatus(host, 'Saved session opened. It is a historical record, not a live run.');
    } catch (error) {
      hostStatus(host, String(error));
    }
  });

  function renderMonitor() {
    const panel = section.querySelector('[data-cp-panel="monitor"]');
    panel.innerHTML = state.runs.length
      ? `<div class="cp-card"><h3>Execution history (this session)</h3><table class="cp-table"><thead><tr><th>Time</th><th>Type</th><th>Status</th><th>Model</th><th>Duration</th><th>Steps</th><th>Records</th><th>Minimized</th><th></th></tr></thead><tbody>${state.runs
          .map(
            (run, index) => `<tr><td>${esc(run.time)}</td><td>${esc(run.type)}</td><td class="status-${esc(run.status)}">${esc(run.status)}</td><td>${esc(run.model)}</td><td>${esc(formatMs(run.duration))}</td><td>${esc(run.tools)}</td><td>${esc(run.events)}</td><td>${run.minimized ? 'yes' : 'no'}</td><td><button class="cp-ghost" data-monitor="${index}">Trace</button></td></tr>`
          )
          .join('')}</tbody></table><div class="wf-result" id="cpMonitorDetail">Select a run.</div></div>`
      : '<div class="cp-card"><p class="cp-muted">No runs in this session.</p></div>';
  }

  section.querySelector('[data-cp-panel="monitor"]').addEventListener('click', (event) => {
    const button = event.target.closest('[data-monitor]');
    if (!button) return;
    const run = state.runs[Number(button.dataset.monitor)];
    const detail = section.querySelector('#cpMonitorDetail');
    if (run && detail) detail.textContent = JSON.stringify({status: run.status, error: run.error, trace: run.trace}, null, 2);
  });

  // Initial state.
  renderChat();
  renderTrace();
  refreshCase();
  refreshSessions();
  if (hasTauri) {
    call('embedded_status')
      .then((status) => {
        state.engine = status;
        const chip = section.querySelector('#cpEngineChip');
        chip.textContent = status.running ? (status.ready ? 'engine ready' : 'engine loading') : 'engine stopped';
        chip.className = `cp-chip ${status.running ? (status.ready ? 'ok' : 'warn') : 'bad'}`;
      })
      .catch(() => {});
  }

  return {
    show: cpShow,
    refreshCase,
    state,
    section
  };
}
