// HELM skill library: Markdown playbooks (like Claude Code / Codex / OpenCode skills).
// Built-in skills are read-only; "Duplicate & edit" saves a user copy in the app-data
// skills folder, which overrides the built-in skill of the same name.
import {t} from '../i18n.js';
import {esc, markdown} from './agent-view.js';

export const SKILL_TEMPLATE = `---
name: my-skill
description: When HELM should use this skill (one or two sentences).
triggers: keyword one, keyword two
preload:
  - findings {"severity": "high", "limit": 20}
---
# My skill playbook

## Steps
1. \`update_plan\` with the steps below.
2. ...

## Answer format
- ...
`;

export function mountSkills({panel, backend, status, onUse, onLoaded}) {
  const state = {skills: [], selected: '', editing: null, dir: ''};
  async function load() {
    try {
      state.skills = await backend('skill_list');
      state.dir = await backend('skill_dir').catch(() => '');
    } catch (error) {
      status(String(error?.message ?? error));
    }
    if (!state.skills.some(s => s.name === state.selected)) state.selected = state.skills[0]?.name ?? '';
    render();
    onLoaded?.(state.skills);
  }
  function render() {
    const skill = state.skills.find(s => s.name === state.selected);
    panel.innerHTML = `<div class="cp-grid ms-skills">
      <article class="cp-card"><h3>${esc(t('Skills'))}</h3>
        <p class="cp-muted">${esc(t('Skills are Markdown playbooks. HELM picks one automatically from your question, or start a message with /skill-name.'))}</p>
        <div class="ms-skill-list">${state.skills.map(s => `<button type="button" class="ms-skill ${s.name === state.selected ? 'active' : ''}" data-pick="${esc(s.name)}"><code>/${esc(s.name)}</code><span class="ms-badge ${s.builtin ? '' : 'ok'}">${esc(s.builtin ? t('built-in') : t('custom'))}</span><small>${esc(s.description)}</small></button>`).join('')}</div>
        <div class="cp-actions"><button type="button" class="cp-primary" data-act="new">${esc(t('New skill'))}</button><label class="cp-ghost ms-file-btn">${esc(t('Import .md skill file'))}<input type="file" accept=".md,text/markdown" class="ms-skill-file" multiple hidden></label></div>
        <p class="cp-muted">${esc(t('Import playbooks written for Claude Code, Codex or OpenCode as long as they start with name/description front matter.'))}</p>
        ${state.dir ? `<p class="cp-muted">${esc(t('Folder'))}: <code>${esc(state.dir)}</code></p>` : ''}
      </article>
      <article class="cp-card">${state.editing !== null ? `
        <h3>${esc(t('Edit skill'))}</h3>
        <textarea class="ms-skill-editor" rows="22" spellcheck="false">${esc(state.editing)}</textarea>
        <div class="cp-actions"><button type="button" class="cp-primary" data-act="save">${esc(t('Save skill'))}</button><button type="button" class="cp-ghost" data-act="cancel">${esc(t('Cancel'))}</button></div>
        <p class="cp-muted">${esc(t('Front matter: name, description, triggers, preload (read-only tools run before the model starts), always (append to every run). Skills cannot add tools or permissions.'))}</p>`
      : skill ? `
        <h3><code>/${esc(skill.name)}</code></h3><p>${esc(skill.description)}</p>
        <p class="cp-muted">${esc(t('Triggers'))}: ${esc(skill.triggers.join(', ') || '—')}</p>
        <p class="cp-muted">${esc(t('Preloaded tools'))}: ${esc(skill.preload.map(p => p.tool).join(', ') || '—')}</p>
        <div class="cp-actions"><button type="button" class="cp-primary" data-act="use">${esc(t('Use in chat'))}</button><button type="button" class="cp-ghost" data-act="edit">${esc(skill.builtin ? t('Duplicate & edit') : t('Edit'))}</button>${skill.builtin ? '' : `<button type="button" class="cp-danger" data-act="delete">${esc(t('Delete'))}</button>`}</div>
        <div class="ms-skill-body" data-no-translate>${markdown(skill.body)}</div>` : `<p class="cp-muted">${esc(t('No skill selected.'))}</p>`}
      </article></div>`;
  }
  panel.addEventListener('change', async event => {
    const input = event.target.closest('.ms-skill-file');
    if (!input?.files?.length) return;
    const done = [];
    for (const file of input.files) {
      try {
        if (file.size > 32 * 1024) throw Error(t('{name}: larger than 32 KB', {name: file.name}));
        const saved = await backend('skill_save', {text: await file.text()});
        done.push(saved.name);
        state.selected = saved.name;
      } catch (error) {
        status(`${file.name}: ${String(error?.message ?? error)}`);
      }
    }
    input.value = '';
    if (done.length) status('Skills imported: {names}', {names: done.join(', ')});
    return load();
  });
  panel.addEventListener('click', async event => {
    const button = event.target.closest('button');
    if (!button) return;
    const skill = state.skills.find(s => s.name === state.selected);
    if (button.dataset.pick) {
      state.selected = button.dataset.pick;
      state.editing = null;
      return render();
    }
    const act = button.dataset.act;
    if (act === 'new') {
      state.editing = SKILL_TEMPLATE;
      return render();
    }
    if (act === 'cancel') {
      state.editing = null;
      return render();
    }
    if (act === 'use' && skill) return onUse(skill.name);
    if (act === 'edit' && skill) {
      try {
        state.editing = await backend('skill_source', {name: skill.name});
      } catch (error) {
        status(String(error?.message ?? error));
      }
      return render();
    }
    if (act === 'delete' && skill && confirm(t('Delete skill {name}?', {name: skill.name}))) {
      await backend('skill_delete', {name: skill.name}).catch(error => status(String(error?.message ?? error)));
      return load();
    }
    if (act === 'save') {
      try {
        const saved = await backend('skill_save', {text: panel.querySelector('.ms-skill-editor').value});
        state.selected = saved.name;
        state.editing = null;
        status('Skill saved.');
        return load();
      } catch (error) {
        status(String(error?.message ?? error));
      }
    }
  });
  return {load, skills: () => state.skills};
}
