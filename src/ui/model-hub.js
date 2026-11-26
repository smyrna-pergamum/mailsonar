// AI model page: one place to connect any model.
//  1. Recommended local models from Hugging Face: one click downloads (HTTPS, SHA-256
//     verified when published), starts the bundled llama.cpp engine and connects it.
//  2. Search Hugging Face or paste a repository link.
//  3. Installed GGUF models.
//  4. Other providers (Ollama, LM Studio, OpenAI-compatible, cloud).
import {t} from '../i18n.js';
import {tt} from './strings.js';
import {formatBytes} from '../assistant-data.js';
import {esc} from './agent-view.js';
import {describeProvider, getProvider, onProvider, presets, providerReady, rememberModel, setProvider} from './provider.js';

// Families known to work with tool calling in llama.cpp (--jinja). Files are
// resolved at runtime from the repository listing; nothing is hard-coded to a URL.
export const RECOMMENDED = [
  {repo: 'Qwen/Qwen2.5-1.5B-Instruct-GGUF', label: 'Qwen 2.5 1.5B Instruct', size: '~1.1 GB', ram: 4, speed: 'fast', note: 'Quick start on any laptop; basic tool use.'},
  {repo: 'Qwen/Qwen3-4B-GGUF', label: 'Qwen 3 4B', size: '~2.5 GB', ram: 8, speed: 'balanced', note: 'Recommended: good tool calling and reasoning for its size.'},
  {repo: 'bartowski/Llama-3.2-3B-Instruct-GGUF', label: 'Llama 3.2 3B Instruct', size: '~2.0 GB', ram: 8, speed: 'balanced', note: 'Solid general assistant; multilingual.'},
  {repo: 'Qwen/Qwen3-8B-GGUF', label: 'Qwen 3 8B', size: '~5.0 GB', ram: 16, speed: 'slower', note: 'Best quality on CPU with 16 GB RAM or a GPU.'},
  {repo: 'bartowski/Qwen2.5-7B-Instruct-GGUF', label: 'Qwen 2.5 7B Instruct', size: '~4.7 GB', ram: 16, speed: 'slower', note: 'Strong instruction following and JSON output.'}
];

/** Choose the single-file Q4_K_M quant (fallback: smallest non-split GGUF). */
export function pickQuant(files) {
  const single = (files ?? []).filter(f => /\.gguf$/i.test(f.path) && !/-\d{5}-of-\d{5}\.gguf$/i.test(f.path) && !/mmproj/i.test(f.path));
  return single.find(f => /q4_k_m\.gguf$/i.test(f.path)) ?? single.find(f => /q4/i.test(f.path)) ?? single.sort((a, b) => a.bytes - b.bytes)[0] ?? null;
}

/** Accept `owner/repo` or a huggingface.co URL. */
export function parseRepo(text) {
  const value = String(text ?? '').trim();
  const match = value.match(/^(?:https?:\/\/(?:www\.)?(?:huggingface\.co|hf\.co)\/)?([A-Za-z0-9][\w.-]*\/[\w.-]+)(?:[/?#].*)?$/);
  return match ? match[1] : '';
}

export function mountModelHub({section, api}) {
  const call = api.backend;
  const state = {hardware: null, models: [], engine: null, downloads: new Map(), search: [], repo: '', files: [], busy: '', discovery: null, scanning: false, tests: new Map()};
  const pending = new Map(); // download id -> {autoStart}
  const host = document.createElement('div');
  host.className = 'ms-models';
  section.prepend(host);

  const engineSettings = () => {
    const ram = state.hardware?.total_ram_mb ?? 8192;
    const context = Number(host.querySelector('#mhContext')?.value) || (ram >= 12000 ? 16384 : 8192);
    return {
      port: 18081,
      context: Math.min(32768, Math.max(2048, context)),
      threads: Number(host.querySelector('#mhThreads')?.value) || state.hardware?.recommended_threads || 4,
      gpuLayers: Number(host.querySelector('#mhGpu')?.value) || state.hardware?.recommended_gpu_layers || 0
    };
  };

  async function refresh() {
    try {
      const [hardware, models, engine] = await Promise.all([call('embedded_hardware'), call('embedded_models'), call('embedded_status')]);
      Object.assign(state, {hardware, models, engine});
    } catch (error) {
      api.status(String(error?.message ?? error));
    }
    render();
    if (!state.discovery && !state.scanning) discover();
  }

  async function discover() {
    state.scanning = true;
    render();
    try {
      state.discovery = await call('discover_local_ai');
    } catch {
      state.discovery = {servers: [], files: [], scanned_folders: [], duration_ms: 0};
    }
    state.scanning = false;
    render();
  }

  async function selftest(id, target) {
    state.tests.set(id, {running: true});
    render();
    try {
      state.tests.set(id, await call('ai_selftest', target));
    } catch (error) {
      state.tests.set(id, {error: String(error?.message ?? error)});
    }
    render();
  }

  async function startModel(path) {
    state.busy = path;
    render();
    try {
      try {
        await call('embedded_stop');
      } catch {
        // Nothing running.
      }
      const settings = engineSettings();
      const start = await call('embedded_start', {modelPath: path, ...settings});
      setProvider({preset: 'embedded', endpoint: start.endpoint, model: start.model, key: start.key, context: settings.context});
      rememberModel(path);
      api.status('Loading model into memory…');
      const ready = await call('embedded_wait_ready', {timeoutMs: 180000});
      api.status(ready.ready ? 'Local model ready. All AI features now use it.' : `Model not ready: ${ready.detail}`);
    } catch (error) {
      api.status(String(error?.message ?? error));
    } finally {
      state.busy = '';
      refresh();
    }
  }

  async function download(repo, file, autoStart) {
    const filename = file.path.split('/').pop();
    const existing = state.models.find(m => m.name === filename);
    if (existing) return autoStart ? startModel(existing.path) : null;
    if (!confirm(t('Download {file} ({size}) from huggingface.co/{repo}?', {file: filename, size: formatBytes(file.bytes), repo}))) return null;
    const id = `dl-${Date.now().toString(36)}`;
    pending.set(id, {autoStart});
    state.downloads.set(id, {id, filename, percent: 0, state: 'starting', total: file.bytes, downloaded: 0, url: file.downloadUrl, sha: file.sha256});
    render();
    try {
      await call('model_download_start', {id, url: file.downloadUrl, filename, expectedSha256: file.sha256 || null});
    } catch (error) {
      state.downloads.delete(id);
      api.status(String(error?.message ?? error));
      render();
    }
    return id;
  }

  async function oneClick(entry) {
    state.busy = entry.repo;
    render();
    try {
      const {files} = await call('hf_files', {repo: entry.repo});
      const file = pickQuant(files);
      if (!file) throw Error(t('No suitable GGUF file found in {repo}.', {repo: entry.repo}));
      await download(entry.repo, file, true);
    } catch (error) {
      api.status(String(error?.message ?? error));
    } finally {
      state.busy = '';
      render();
    }
  }

  function installedFor(entry) {
    const stem = entry.repo.split('/')[1].replace(/-GGUF$/i, '').toLowerCase();
    return state.models.find(m => m.name.toLowerCase().startsWith(stem.replace(/^microsoft_/, '')) || m.name.toLowerCase().includes(stem));
  }

  function render() {
    const p = getProvider();
    const ram = Math.round((state.hardware?.total_ram_mb ?? 0) / 1024);
    const running = state.engine?.running;
    const downloads = [...state.downloads.values()].map(d => `<div class="ms-dl"><span>${esc(d.filename)} · ${esc(d.state)} ${d.total ? `· ${formatBytes(d.downloaded)} / ${formatBytes(d.total)}` : ''}</span><div class="download-bar"><span style="width:${Math.max(0, Math.min(100, d.percent ?? 0))}%"></span></div><button type="button" data-cancel="${esc(d.id)}">${tt('Cancel')}</button></div>`).join('');
    host.innerHTML = `
      <article class="ms-status-card"><h2>${tt('AI model')}</h2>
        <p class="ms-provider-line"><span class="ms-dot ${providerReady(p) ? 'ok' : 'bad'}"></span>${esc(describeProvider(p))}</p>
        <p class="ms-muted">${tt('All AI features (analysis, HELM agent, rule writing, BEACON) use this one connection. AI is optional: detection, correlation and reports work without it.')}</p>
        <div class="ms-actions"><button type="button" data-act="test-current" ${providerReady(p) ? '' : 'disabled'}>${tt('Test connection')}</button>${running ? `<button type="button" data-act="stop">${tt('Stop local model')}</button>` : ''}</div>
        ${testHtml('current')}
        ${downloads ? `<div class="ms-dls">${downloads}</div>` : ''}
      </article>
      ${discoveryHtml()}
      <article><h2>${tt('Local models from Hugging Face')} <small class="ms-muted">${tt('runs offline on this PC')}</small></h2>
        <p class="ms-muted">${esc(t('This PC: {cores} cores, {ram} GB RAM, {acc}.', {cores: state.hardware?.logical_cores ?? '?', ram: ram || '?', acc: (state.hardware?.accelerators ?? ['CPU']).join(', ')}))}</p>
        <div class="ms-model-grid">${RECOMMENDED.map(entry => {
          const inst = installedFor(entry);
          const fits = !ram || ram >= entry.ram;
          const active = inst && running && p.preset === 'embedded' && p.key;
          const label = state.busy === entry.repo || (inst && state.busy === inst.path) ? t('Working…') : active ? t('Restart') : inst ? t('Start') : t('Download & start');
          return `<div class="ms-model ${fits ? '' : 'dim'}"><strong>${esc(entry.label)}</strong><small>${esc(entry.size)} · ${esc(t('needs ~{ram} GB RAM', {ram: entry.ram}))} · ${tt(entry.speed)}</small><p>${tt(entry.note)}</p>
            <button type="button" class="${fits ? 'primary' : ''}" data-rec="${esc(entry.repo)}" ${state.busy ? 'disabled' : ''}>${esc(label)}</button>${inst ? `<span class="ms-badge ok">${tt('installed')}</span>` : ''}</div>`;
        }).join('')}</div>
      </article>
      <article><h2>${tt('Search Hugging Face')}</h2>
        <div class="ms-ask"><input id="mhQuery" placeholder="${esc(t('Model name or link, e.g. qwen3 gguf or https://huggingface.co/Qwen/Qwen3-4B-GGUF'))}" data-tp="${esc('Model name or link, e.g. qwen3 gguf or https://huggingface.co/Qwen/Qwen3-4B-GGUF')}"><button type="button" class="primary" data-act="search">${tt('Search')}</button></div>
        <div class="ms-search">${state.search.map(r => `<button type="button" class="catalog-item" data-repo="${esc(r.id)}">${esc(r.id)}<small>${esc(r.downloads)} ↓ · ${esc(r.likes)} ♥</small></button>`).join('')}</div>
        ${state.repo ? `<h3>${esc(state.repo)}</h3><div class="model-list">${state.files.map((f, i) => `<div class="model-row"><div><strong>${esc(f.path)}</strong><small>${formatBytes(f.bytes)} · ${f.sha256 ? 'SHA-256 ✓' : esc(t('no checksum published'))}</small></div><div class="model-actions"><button type="button" class="primary" data-file="${i}">${tt('Download & start')}</button></div></div>`).join('') || `<p class="ms-muted">${tt('No GGUF files in this repository.')}</p>`}</div>` : ''}
      </article>
      <article><h2>${tt('Installed models')}</h2>
        ${state.models.length ? `<div class="model-list">${state.models.map(m => `<div class="model-row"><div><strong>${esc(m.name)}</strong><small>${formatBytes(m.bytes)}</small></div><div class="model-actions"><button type="button" class="primary" data-start="${esc(m.path)}" ${state.busy ? 'disabled' : ''}>${tt('Start')}</button><button type="button" class="cp-danger" data-del="${esc(m.path)}">${tt('Delete')}</button></div></div>`).join('')}</div>` : `<p class="ms-muted">${tt('No local models yet. Pick a recommended model above.')}</p>`}
        <details><summary>${tt('Engine settings')}</summary><div class="ms-form-row">
          <label>${tt('Context tokens')}<input id="mhContext" type="number" min="2048" max="32768" step="1024" value="${engineSettings().context}"></label>
          <label>${tt('CPU threads')}<input id="mhThreads" type="number" min="1" max="64" value="${engineSettings().threads}"></label>
          <label>${tt('GPU layers')}<input id="mhGpu" type="number" min="0" max="200" value="${engineSettings().gpuLayers}"></label>
        </div><p class="ms-muted">${tt('HELM needs at least 8192 context tokens for tool calling. Bundled engine: llama.cpp CPU build.')}</p></details>
      </article>
      <article><h2>${tt('Other providers')}</h2>
        <p class="ms-muted">${tt('Ollama, LM Studio, vLLM or an OpenAI-compatible cloud API. Cloud providers only receive minimized aliases.')}</p>
        <div class="ms-form-row">
          <label>${tt('Provider')}<select id="mhPreset">${presets().filter(x => x.id !== 'embedded').map(x => `<option value="${esc(x.id)}" ${p.preset === x.id ? 'selected' : ''}>${esc(x.label)}</option>`).join('')}</select></label>
          <label>${tt('Model')}<input id="mhModel" value="${p.preset === 'embedded' ? '' : esc(p.model)}" placeholder="qwen3:8b / gpt-4.1-mini"></label>
        </div>
        <label>Endpoint<input id="mhEndpoint" value="${p.preset === 'embedded' ? '' : esc(p.endpoint)}" placeholder="http://127.0.0.1:11434/v1/chat/completions"></label>
        <label>${tt('API key (memory only)')}<input id="mhKey" type="password" autocomplete="off"></label>
        <div class="ms-actions"><button type="button" class="primary" data-act="connect">${tt('Connect & test')}</button><span class="ms-muted" id="mhTest"></span></div>
      </article>`;
    const preset = host.querySelector('#mhPreset');
    preset.onchange = () => {
      const chosen = presets().find(x => x.id === preset.value);
      if (chosen?.endpoint) host.querySelector('#mhEndpoint').value = chosen.endpoint;
    };
  }

  function testHtml(id) {
    const r = state.tests.get(id);
    if (!r) return '';
    if (r.running) return `<p class="ms-test ms-muted"><span class="ms-spinner"></span> ${tt('Testing…')}</p>`;
    if (r.error && !r.chat_ok) return `<p class="ms-test ms-warn">${esc(r.error)}</p>`;
    const chip = (ok, label) => `<span class="ms-badge ${ok ? 'ok' : 'bad'}">${ok ? '✓' : '✗'} ${esc(label)}</span>`;
    return `<p class="ms-test">${chip(r.chat_ok, t('Chat'))} ${chip(r.native_tools || r.text_tools, t('Tool calling'))} ${chip(r.helm_ready, 'HELM')}
      <span class="ms-muted">${r.chat_ms ? `${(r.chat_ms / 1000).toFixed(1)} s` : ''}${r.tokens_per_second ? ` · ${esc(r.tokens_per_second)} tok/s` : ''}</span><br><small class="ms-muted">${esc(t(r.verdict ?? ''))}</small></p>`;
  }

  function discoveryHtml() {
    const found = state.discovery;
    const servers = found?.servers ?? [];
    const files = (found?.files ?? []).filter(f => !f.managed);
    const serverRows = servers.map((srv, i) => `<div class="model-row ms-found"><div><strong>${esc(srv.name)}</strong> <span class="ms-badge ok">${tt('running')}</span><small>${esc(srv.endpoint)} · ${esc(srv.detail)}</small>
        ${srv.models.length ? `<select data-model-for="${i}">${srv.models.map(m => `<option>${esc(m)}</option>`).join('')}</select>` : ''}${testHtml(`srv-${i}`)}</div>
        <div class="model-actions">${srv.managed ? '' : `<button type="button" data-test-srv="${i}" ${srv.models.length ? '' : 'disabled'}>${tt('Test')}</button><button type="button" class="primary" data-use-srv="${i}" ${srv.models.length ? '' : 'disabled'}>${tt('Use')}</button>`}</div></div>`).join('');
    const fileRows = files.map(f => `<div class="model-row"><div><strong>${esc(f.name)}</strong><small>${esc(f.source)} · ${formatBytes(f.bytes)} · ${esc(f.folder)}</small></div>
        <div class="model-actions"><button type="button" class="primary" data-start="${esc(f.path)}" ${state.busy ? 'disabled' : ''}>${tt('Start')}</button></div></div>`).join('');
    return `<article><h2>${tt('Found on this PC')} <button type="button" class="ms-link" data-act="discover">${esc(state.scanning ? t('Scanning…') : t('Scan again'))}</button></h2>
      <p class="ms-muted">${tt('Running local AI servers (Ollama, LM Studio, llama.cpp, vLLM, Jan, KoboldCpp…) and GGUF files in known model folders. Nothing is changed.')}</p>
      ${found ? '' : `<p class="ms-muted">${tt('Scanning…')}</p>`}
      ${serverRows ? `<h3>${tt('Running servers')}</h3><div class="model-list">${serverRows}</div>` : found ? `<p class="ms-muted">${tt('No running local AI server found.')}</p>` : ''}
      ${fileRows ? `<h3>${tt('Model files')}</h3><div class="model-list">${fileRows}</div>` : found ? `<p class="ms-muted">${esc(t('No GGUF files found in {count} folders.', {count: found.scanned_folders.length}))}</p>` : ''}
    </article>`;
  }

  const serverTarget = i => {
    const srv = state.discovery.servers[Number(i)];
    const model = host.querySelector(`[data-model-for="${i}"]`)?.value ?? srv.models[0];
    return {srv, model};
  };

  host.addEventListener('click', async event => {
    const target = event.target.closest('button');
    if (!target) return;
    const d = target.dataset;
    if (d.act === 'discover') return discover();
    if (d.act === 'test-current') {
      const p = getProvider();
      return selftest('current', {endpoint: p.endpoint, model: p.model, key: p.key});
    }
    if (d.testSrv !== undefined) {
      const {srv, model} = serverTarget(d.testSrv);
      return selftest(`srv-${d.testSrv}`, {endpoint: srv.endpoint, model, key: ''});
    }
    if (d.useSrv !== undefined) {
      const {srv, model} = serverTarget(d.useSrv);
      const preset = presets().find(x => x.endpoint && new URL(x.endpoint).port === String(srv.port))?.id ?? 'custom';
      setProvider({preset, endpoint: srv.endpoint, model, key: ''});
      api.status('Connected to {name} ({model}).', {name: srv.name, model});
      return selftest('current', {endpoint: srv.endpoint, model, key: ''});
    }
    if (d.rec) return oneClick(RECOMMENDED.find(r => r.repo === d.rec));
    if (d.start) return startModel(d.start);
    if (d.del) {
      if (!confirm(t('Delete this model file from disk?'))) return;
      try {
        await call('embedded_delete_model', {path: d.del});
      } catch (error) {
        api.status(String(error?.message ?? error));
      }
      return refresh();
    }
    if (d.cancel) {
      try {
        await call('model_download_control', {id: d.cancel, action: 'cancel'});
      } catch {
        // Already finished.
      }
      state.downloads.delete(d.cancel);
      return render();
    }
    if (d.repo) {
      state.repo = d.repo;
      try {
        state.files = (await call('hf_files', {repo: d.repo})).files ?? [];
      } catch (error) {
        api.status(String(error?.message ?? error));
      }
      return render();
    }
    if (d.file !== undefined) return download(state.repo, state.files[Number(d.file)], true);
    if (d.act === 'stop') {
      await call('embedded_stop').catch(() => {});
      setProvider({key: ''});
      return refresh();
    }
    if (d.act === 'search') {
      const query = host.querySelector('#mhQuery').value.trim();
      const repo = parseRepo(query);
      if (repo && query.includes('/')) {
        state.search = [];
        state.repo = repo;
        try {
          state.files = (await call('hf_files', {repo})).files ?? [];
        } catch (error) {
          api.status(String(error?.message ?? error));
        }
        return render();
      }
      try {
        state.search = (await call('hf_search', {query: `${query} gguf`.trim(), limit: 20})).items ?? [];
        state.repo = '';
      } catch (error) {
        api.status(String(error?.message ?? error));
      }
      return render();
    }
    if (d.act === 'connect') {
      const chosen = presets().find(x => x.id === host.querySelector('#mhPreset').value);
      const next = {preset: chosen?.id ?? 'custom', endpoint: host.querySelector('#mhEndpoint').value.trim(), model: host.querySelector('#mhModel').value.trim(), key: host.querySelector('#mhKey').value};
      const out = host.querySelector('#mhTest');
      out.textContent = t('Testing…');
      try {
        const result = await call('provider_test', next);
        setProvider(next);
        out.textContent = result.ok ? t('Connected ({ms} ms). {count} models listed.', {ms: result.latencyMs, count: result.models?.length ?? 0}) : t('Saved, but the test failed: {detail}', {detail: result.detail ?? result.status});
      } catch (error) {
        out.textContent = String(error?.message ?? error);
      }
    }
  });

  if (window.__TAURI_INTERNALS__) {
    import('@tauri-apps/api/event').then(({listen}) => listen('model://progress', event => {
      const progress = event.payload;
      const previous = state.downloads.get(progress.id) ?? {};
      state.downloads.set(progress.id, {...previous, ...progress});
      if (progress.state === 'complete') {
        state.downloads.delete(progress.id);
        const job = pending.get(progress.id);
        pending.delete(progress.id);
        call('embedded_models').then(models => {
          state.models = models;
          const model = models.find(m => m.name === (progress.filename ?? previous.filename));
          if (job?.autoStart && model) startModel(model.path);
          else render();
        });
      } else if (['error', 'cancelled', 'failed'].includes(progress.state)) {
        api.status(progress.message ?? progress.state);
        render();
      } else if (section.offsetParent) {
        render();
      }
    })).catch(() => {});
  }

  // Reconnect to an engine that is still running after a UI reload.
  call('embedded_connection').then(conn => {
    if (conn && (!getProvider().key || getProvider().preset === 'embedded')) setProvider({preset: 'embedded', endpoint: conn.endpoint, model: conn.model, key: conn.key});
  }).catch(() => {});
  onProvider(() => {
    if (section.offsetParent) render();
  });
  api.onLocale?.(render);
  return {refresh, startModel, discover};
}
