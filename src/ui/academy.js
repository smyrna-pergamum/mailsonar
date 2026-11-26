// Training mode: guided lessons on bundled datasets with answer checking, hints,
// "show me" navigation and explanations. Progress is a per-viewer convenience
// kept in localStorage; nothing here changes evidence.
import {getLocale, t} from '../i18n.js';
import {esc} from './agent-view.js';
import {DATASETS, LESSONS, checkAnswer} from './lessons.js';

const KEY = 'mailsonar.training.progress';
const pick = pair => (getLocale() === 'tr' ? pair[0] : pair[1]);

function loadProgress() {
  try {
    return JSON.parse(localStorage.getItem(KEY) ?? '{}');
  } catch {
    return {};
  }
}

function saveProgress(progress) {
  try {
    localStorage.setItem(KEY, JSON.stringify(progress));
  } catch {
    // Storage unavailable: progress lasts for this session only.
  }
}

export function mountAcademy({section, api}) {
  const state = {lesson: LESSONS[0].id, progress: loadProgress(), feedback: {}, hints: {}, loaded: ''};

  const done = id => LESSONS.find(l => l.id === id).steps.every((_, i) => state.progress[`${id}:${i}`]);

  function render() {
    const lesson = LESSONS.find(l => l.id === state.lesson);
    const total = LESSONS.reduce((n, l) => n + l.steps.length, 0);
    const solved = Object.values(state.progress).filter(Boolean).length;
    const ready = state.loaded === lesson.dataset;
    section.innerHTML = `<div class="ms-academy">
      <article class="ms-lessons"><h2>${esc(t('Training mode'))}</h2>
        <p class="ms-muted">${esc(t('Learn e-mail DFIR on safe, synthetic data. Each lesson loads its dataset, asks questions and checks your answers against the real analysis.'))}</p>
        <div class="ms-progress"><span style="width:${Math.round((solved / total) * 100)}%"></span></div>
        <p class="ms-muted">${esc(t('{solved} of {total} questions solved', {solved, total}))}</p>
        <ol>${LESSONS.map(l => `<li><button type="button" class="ms-lesson ${l.id === state.lesson ? 'active' : ''}" data-lesson="${esc(l.id)}">
          <span>${done(l.id) ? '✓' : '○'}</span><span><strong>${esc(pick(l.title))}</strong><small>${'★'.repeat(l.level)} · ${esc(pick(DATASETS[l.dataset]))}</small></span></button></li>`).join('')}</ol>
        <button type="button" class="ms-link" data-reset>${esc(t('Reset progress'))}</button>
      </article>
      <article class="ms-lesson-body" data-no-translate>
        <h2>${esc(pick(lesson.title))}</h2>
        <p>${esc(pick(lesson.goal))}</p>
        <div class="ms-actions"><button type="button" class="${ready ? '' : 'primary'}" data-load="${esc(lesson.dataset)}">${esc(ready ? t('Reload dataset') : t('Load lesson dataset'))}</button>
          <span class="ms-muted">${esc(pick(DATASETS[lesson.dataset]))}</span></div>
        ${ready ? '' : `<p class="ms-warn">${esc(t('Loading a lesson dataset replaces the current workspace. Save your case first.'))}</p>`}
        ${lesson.steps.map((step, i) => {
          const key = `${lesson.id}:${i}`;
          const fb = state.feedback[key];
          const solvedStep = state.progress[key];
          const input = step.type === 'choice'
            ? `<div class="ms-choices">${step.options.map(o => `<label><input type="radio" name="${esc(key)}" value="${esc(o)}"> ${esc(o)}</label>`).join('')}</div>`
            : step.type === 'text' ? `<input class="ms-answer-input" data-input="${esc(key)}" placeholder="${esc(t('Your answer'))}">` : '';
          return `<section class="ms-question ${solvedStep ? 'solved' : ''}">
            <h3>${i + 1}. ${esc(pick(step.q))} ${solvedStep ? '<span class="ms-badge ok">✓</span>' : ''}</h3>
            ${input}
            <div class="ms-actions"><button type="button" class="primary" data-check="${esc(key)}" ${ready ? '' : 'disabled'}>${esc(t('Check'))}</button>
              <button type="button" data-hint="${esc(key)}">${esc(t('Hint'))}</button>
              <button type="button" data-view="${esc(step.view)}">${esc(t('Show me'))}</button>
              <button type="button" data-ask="${esc(key)}" ${ready ? '' : 'disabled'}>${esc(t('Ask HELM'))}</button></div>
            ${state.hints[key] ? `<p class="ms-hint">💡 ${esc(pick(step.hint))}</p>` : ''}
            ${fb ? `<p class="${fb.ok ? 'ms-ok' : 'ms-warn'}">${esc(fb.ok ? t('Correct!') : fb.missing ? t('The dataset is not loaded or the answer cannot be computed.') : t('Not quite. Try again or use the hint.'))}</p>` : ''}
            ${solvedStep || fb?.reveal ? `<p class="ms-explain">${esc(pick(step.explain))}${fb?.expected && !solvedStep ? ` <strong>${esc(t('Answer'))}: ${esc(fb.expected)}</strong>` : ''}</p>` : ''}
            ${fb && !fb.ok && !fb.reveal ? `<button type="button" class="ms-link" data-reveal="${esc(key)}">${esc(t('Show answer'))}</button>` : ''}
          </section>`;
        }).join('')}
        ${done(lesson.id) ? `<p class="ms-ok">${esc(t('Lesson complete.'))}</p>${nextButton(lesson)}` : ''}
      </article></div>`;
  }

  function nextButton(lesson) {
    const index = LESSONS.findIndex(l => l.id === lesson.id);
    const next = LESSONS[index + 1];
    return next ? `<button type="button" class="primary" data-lesson="${esc(next.id)}">${esc(t('Next lesson'))}: ${esc(pick(next.title))}</button>` : '';
  }

  function stepFor(key) {
    const [id, index] = key.split(':');
    return LESSONS.find(l => l.id === id).steps[Number(index)];
  }

  function valueFor(key) {
    return section.querySelector(`input[name="${CSS.escape(key)}"]:checked`)?.value
      ?? section.querySelector(`[data-input="${CSS.escape(key)}"]`)?.value ?? '';
  }

  section.addEventListener('click', async event => {
    const b = event.target.closest('button');
    if (!b) return;
    const d = b.dataset;
    if (d.lesson) {
      state.lesson = d.lesson;
      return render();
    }
    if (d.reset !== undefined) {
      if (!confirm(t('Reset training progress?'))) return;
      state.progress = {};
      state.feedback = {};
      saveProgress(state.progress);
      return render();
    }
    if (d.load) {
      b.disabled = true;
      await api.loadDataset(d.load);
      state.loaded = d.load;
      return render();
    }
    if (d.view) return api.tab(d.view);
    if (d.hint) {
      state.hints[d.hint] = true;
      return render();
    }
    if (d.reveal) {
      state.feedback[d.reveal] = {...state.feedback[d.reveal], reveal: true};
      return render();
    }
    if (d.ask) {
      const step = stepFor(d.ask);
      api.tab('ai');
      return api.ask(`${pick(step.q)} ${t('Explain how to find the answer in the evidence, step by step, and cite evidence IDs.')}`, t('Training question'));
    }
    if (d.check) {
      const step = stepFor(d.check);
      const value = valueFor(d.check);
      const result = checkAnswer(step, value, {...api.getCase(), rules: api.getRules()});
      state.feedback[d.check] = result;
      if (result.ok) {
        state.progress[d.check] = true;
        saveProgress(state.progress);
      }
      return render();
    }
  });
  render();
  return {render};
}
