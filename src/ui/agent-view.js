// Live agent result panel: plan checklist, streaming tool steps and the final answer.
// The answer is untrusted model output: it is escaped first, then given minimal
// Markdown formatting. Evidence IDs become buttons that open the record.
import {t} from '../i18n.js';
import {stepLabel} from './helm-run.js';

export function esc(value) {
  return String(value ?? '').replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
}

const ID_RE = /\b[0-9a-f]{64}:[0-9a-f]{64}:\d{1,6}\b/g;

/** Escape, then apply a tiny safe Markdown subset. */
export function markdown(text) {
  const lines = esc(text).split(/\r?\n/);
  let html = '';
  let list = false;
  let code = false;
  for (const line of lines) {
    if (line.trim().startsWith('```')) {
      html += code ? '</pre>' : '<pre class="ms-code">';
      code = !code;
      continue;
    }
    if (code) {
      html += `${line}\n`;
      continue;
    }
    const item = line.match(/^\s*(?:[-*]|\d+\.)\s+(.*)$/);
    if (item && !list) {
      html += '<ul>';
      list = true;
    }
    if (!item && list) {
      html += '</ul>';
      list = false;
    }
    let body = item ? item[1] : line;
    body = body.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>').replace(/`([^`]+)`/g, '<code>$1</code>');
    body = body.replace(ID_RE, id => `<button type="button" class="ms-evid" data-evidence="${id}" title="${id}">#${id.split(':')[2]}</button>`);
    const heading = body.match(/^(#{1,4})\s+(.*)$/);
    if (heading) html += `<h${heading[1].length + 2}>${heading[2]}</h${heading[1].length + 2}>`;
    else if (item) html += `<li>${body}</li>`;
    else if (body.trim()) html += `<p>${body}</p>`;
  }
  if (list) html += '</ul>';
  if (code) html += '</pre>';
  return html;
}

export function createAgentPanel({onEvidence} = {}) {
  const root = document.createElement('div');
  root.className = 'ms-agent';
  root.innerHTML = `<div class="ms-agent-head"><span class="ms-spinner" hidden></span><strong class="ms-agent-title"></strong><span class="ms-agent-meta"></span></div>
    <ol class="ms-plan"></ol>
    <details class="ms-steps"><summary>${esc(t('Tool steps'))} (<span>0</span>)</summary><ol></ol></details>
    <div class="ms-answer" data-no-translate></div>`;
  const $ = sel => root.querySelector(sel);
  root.addEventListener('click', event => {
    const button = event.target.closest('[data-evidence]');
    if (button) onEvidence?.(button.dataset.evidence);
  });
  let steps = 0;
  const api = {
    el: root,
    start(title) {
      steps = 0;
      $('.ms-agent-title').textContent = title;
      $('.ms-agent-meta').textContent = t('working…');
      $('.ms-spinner').hidden = false;
      $('.ms-plan').replaceChildren();
      $('.ms-steps ol').replaceChildren();
      $('.ms-steps span').textContent = '0';
      $('.ms-answer').innerHTML = '';
      root.hidden = false;
    },
    step(step) {
      steps += 1;
      $('.ms-steps span').textContent = String(steps);
      const li = document.createElement('li');
      li.className = `status-${step.status}`;
      li.textContent = stepLabel(step);
      $('.ms-steps ol').append(li);
      if (step.name === 'update_plan' && Array.isArray(step.arguments?.steps)) api.plan(step.arguments.steps);
    },
    plan(items) {
      const list = $('.ms-plan');
      list.replaceChildren();
      for (const item of items) {
        const li = document.createElement('li');
        li.className = `plan-${item.status}`;
        li.textContent = item.step;
        list.append(li);
      }
    },
    finish(outcome) {
      $('.ms-spinner').hidden = true;
      if (outcome.plan?.length) api.plan(outcome.plan);
      if (!steps) for (const step of outcome.trace ?? []) api.step(step);
      const skills = outcome.skills_loaded?.length ? ` · skill: ${outcome.skills_loaded.join(', ')}` : '';
      $('.ms-agent-meta').textContent = `${outcome.status} · ${outcome.tool_calls} ${t('tool calls')} · ${(outcome.duration_ms / 1000).toFixed(1)} s · ${outcome.model}${skills}${outcome.minimized ? ` · ${t('minimized for cloud')}` : ''}`;
      const note = outcome.error ? `<p class="ms-warn">${esc(outcome.error)}</p>` : '';
      $('.ms-answer').innerHTML = note + markdown(outcome.answer || t('No answer returned.')) + `<p class="ms-muted">${esc(t('AI output is unverified. Check every claim against the cited evidence.'))}</p>`;
    },
    fail(error) {
      $('.ms-spinner').hidden = true;
      $('.ms-agent-meta').textContent = t('failed');
      $('.ms-answer').innerHTML = `<p class="ms-warn">${esc(String(error?.message ?? error))}</p>`;
    }
  };
  root.hidden = true;
  return api;
}
