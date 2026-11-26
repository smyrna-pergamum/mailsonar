// Analyst-defined one-click queries: create, edit, delete and run. Stored by the
// backend in <app data>/analysis-queries.json so they survive restarts and can be
// copied between workstations.
import {t} from '../i18n.js';
import {tt} from './strings.js';
import {esc} from './agent-view.js';

export function newQueryId(existing) {
  let n = existing.length + 1;
  while (existing.some(q => q.id === `q-${n}`)) n++;
  return `q-${n}`;
}

/** Validate in the UI with the same limits as the backend. */
export function checkQuery(q) {
  if (!q.title.trim() || q.title.length > 80) return t('Title must be 1-80 characters.');
  if (q.task.trim().length < 5 || q.task.length > 4000) return t('Question must be 5-4000 characters.');
  if (q.hint.length > 160) return t('Short description must be at most 160 characters.');
  return '';
}

export function mountSavedQueries({card, api, run, freeInput}) {
  const box = document.createElement('div');
  box.className = 'ms-saved';
  card.querySelector('.ms-ask').after(box);
  const state = {items: [], skills: [], editing: null};

  async function load() {
    try {
      state.items = await api.backend('queries_list');
    } catch {
      state.items = [];
    }
    try {
      state.skills = (await api.backend('skill_list')).map(s => s.name);
    } catch {
      state.skills = [];
    }
    render();
  }

  async function persist(items) {
    await api.backend('queries_save', {items});
    state.items = items;
    render();
  }

  function form(q) {
    return `<div class="ms-query-form">
      <label>${tt('Title')}<input class="qf-title" maxlength="80" value="${esc(q.title)}"></label>
      <label>${tt('Short description')}<input class="qf-hint" maxlength="160" value="${esc(q.hint)}"></label>
      <label>${tt('Question for HELM')}<textarea class="qf-task" rows="4" maxlength="4000">${esc(q.task)}</textarea></label>
      <label>${tt('Skill (optional)')}<select class="qf-skill"><option value="" data-t="${esc('automatic')}">${esc(t('automatic'))}</option>${state.skills.map(s => `<option value="${esc(s)}" ${s === q.skill ? 'selected' : ''}>/${esc(s)}</option>`).join('')}</select></label>
      <div class="ms-actions"><button type="button" class="primary" data-q="save">${tt('Save query')}</button><button type="button" data-q="cancel">${tt('Cancel')}</button><span class="qf-error ms-warn"></span></div>
    </div>`;
  }

  function render() {
    const list = state.items.map(q => `<div class="ms-profile ms-custom" data-run="${esc(q.id)}" role="button" tabindex="0">
        <strong>${esc(q.title)}</strong><small>${esc(q.hint || q.task.slice(0, 90))}</small>
        <span class="ms-custom-actions"><button type="button" class="ms-link" data-edit="${esc(q.id)}">${tt('Edit')}</button><button type="button" class="ms-link" data-del="${esc(q.id)}">${tt('Delete')}</button></span>
      </div>`).join('');
    box.innerHTML = `<h3>${tt('My saved queries')}</h3>
      ${state.items.length ? `<div class="ms-profiles">${list}</div>` : `<p class="ms-muted">${tt('Save questions you ask often; they appear here as one-click buttons.')}</p>`}
      ${state.editing ? form(state.editing) : `<div class="ms-actions"><button type="button" data-q="new">${tt('+ New query')}</button><button type="button" data-q="from-free">${tt('Save the question above')}</button></div>`}`;
  }

  box.addEventListener('click', async event => {
    const target = event.target.closest('button, [data-run]');
    if (!target) return;
    const d = target.dataset;
    if (d.edit) {
      state.editing = {...state.items.find(q => q.id === d.edit)};
      return render();
    }
    if (d.del) {
      const q = state.items.find(x => x.id === d.del);
      if (!confirm(t('Delete saved query "{title}"?', {title: q.title}))) return;
      return persist(state.items.filter(x => x.id !== d.del)).catch(e => api.status(String(e?.message ?? e)));
    }
    if (d.run) {
      const q = state.items.find(x => x.id === d.run);
      return run(q.task, q.skill || null, q.title);
    }
    if (d.q === 'new' || d.q === 'from-free') {
      const task = d.q === 'from-free' ? freeInput.value.trim() : '';
      state.editing = {id: newQueryId(state.items), title: task.slice(0, 60), hint: '', task, skill: ''};
      return render();
    }
    if (d.q === 'cancel') {
      state.editing = null;
      return render();
    }
    if (d.q === 'save') {
      const q = {
        ...state.editing,
        title: box.querySelector('.qf-title').value.trim(),
        hint: box.querySelector('.qf-hint').value.trim(),
        task: box.querySelector('.qf-task').value.trim(),
        skill: box.querySelector('.qf-skill').value
      };
      const problem = checkQuery(q);
      if (problem) {
        box.querySelector('.qf-error').textContent = problem;
        return;
      }
      const items = state.items.some(x => x.id === q.id) ? state.items.map(x => (x.id === q.id ? q : x)) : [...state.items, q];
      try {
        state.editing = null;
        await persist(items);
        api.status('Query saved.');
      } catch (error) {
        state.editing = q;
        render();
        box.querySelector('.qf-error').textContent = String(error?.message ?? error);
      }
    }
  });
  api.onLocale?.(render);
  setTimeout(load, 0);
  return {load};
}
