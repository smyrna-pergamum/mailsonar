import {topics, localAnswer, askSelected, askAgent} from './core.js';
import './panel.css';

// BEACON is the only floating assistant in the application. The HELM agent
// studio is a full workspace tab and must not mount another floating panel.
export function mountBeacon(host) {
  if (document.querySelector('#beacon-root')) return;

  const root = document.createElement('div');
  root.id = 'beacon-root';
  document.body.append(root);

  const make = (tag, text, cls) => {
    const node = document.createElement(tag);
    if (text !== undefined && text !== null) node.textContent = text;
    if (cls) node.className = cls;
    return node;
  };
  const button = (text, fn, cls) => {
    const node = make('button', text, cls);
    node.type = 'button';
    node.onclick = fn;
    return node;
  };
  const logo = () => {
    const img = document.createElement('img');
    img.src = new URL('./beacon.svg', import.meta.url).href;
    img.alt = '';
    img.setAttribute('aria-hidden', 'true');
    return img;
  };

  const panel = make('section', null, 'beacon-panel');
  panel.hidden = true;
  panel.setAttribute('role', 'dialog');
  panel.setAttribute('aria-label', 'BEACON assistant');

  const launcher = button('', () => toggle(panel.hidden), 'beacon-launch');
  launcher.append(logo());
  launcher.setAttribute('aria-label', 'Open BEACON assistant');
  launcher.setAttribute('aria-expanded', 'false');

  const head = make('header', null, 'beacon-head');
  const mark = make('span', null, 'beacon-mark');
  mark.append(logo());
  const heading = make('div');
  heading.append(make('strong', 'BEACON'), make('small', 'MAILSONAR / Investigation assistant'));
  const log = make('div', null, 'beacon-log');
  log.setAttribute('role', 'log');
  log.setAttribute('aria-live', 'polite');

  let generation = 0;
  let pending = false;

  const input = make('textarea');
  input.rows = 3;
  input.maxLength = 2000;
  input.placeholder = 'Ask about MailSonar or selected evidence...';
  input.setAttribute('aria-label', 'Question');

  const mode = make('select');
  mode.setAttribute('aria-label', 'Assistant mode');
  for (const [value, label] of [
    ['help', 'Offline product guide'],
    ['ai', 'Selected evidence AI'],
    ['agent', 'HELM agent (read-only tools)']
  ]) {
    const option = make('option', label);
    option.value = value;
    mode.append(option);
  }

  const note = make('small', null, 'beacon-note');
  function modeNote() {
    if (mode.value === 'ai') {
      note.textContent = 'AI mode sends only the selected 1-25 minimized records through the existing gateway; your question is sent as entered.';
    } else if (mode.value === 'agent') {
      note.textContent = 'HELM runs bounded read-only case tools in the Rust backend. Evidence is never modified and no shell or filesystem access is exposed.';
    } else {
      note.textContent = 'Offline guide: deterministic keyword help, no network request and no model required.';
    }
  }
  mode.onchange = modeNote;

  function message(who, text, tab) {
    const item = make('div', null, 'beacon-msg ' + (who === 'You' ? 'beacon-user' : ''));
    item.append(make('small', who), make('div', String(text)));
    if (tab && typeof host.navigate === 'function') {
      item.append(button('Open ' + tab, () => host.navigate(tab)));
    }
    log.append(item);
    log.scrollTop = log.scrollHeight;
  }

  function reset() {
    generation++;
    log.replaceChildren();
    input.value = '';
    message('BEACON', 'Hi! Ask me how to use MailSonar - evidence, AI models, findings, timelines or HELM workflows. For case-specific analysis, select evidence and switch to Selected evidence AI, or use HELM for bounded read-only case tools.');
  }

  function toggle(show) {
    panel.hidden = !show;
    launcher.setAttribute('aria-expanded', String(show));
    if (show) input.focus();
    else launcher.focus();
  }

  const newButton = button('+', reset);
  newButton.setAttribute('aria-label', 'New conversation');
  const closeButton = button('x', () => toggle(false));
  closeButton.setAttribute('aria-label', 'Close assistant');
  head.append(mark, heading, newButton, closeButton);

  const suggestions = make('div', null, 'beacon-suggest');
  for (const topic of topics.slice(0, 6)) {
    suggestions.append(button(topic[1], () => {
      mode.value = 'help';
      modeNote();
      input.value = topic[1];
      send();
    }));
  }
  suggestions.append(button('Case summary', () => {
    mode.value = 'help';
    modeNote();
    input.value = 'Case summary';
    send();
  }));

  const footer = make('div', null, 'beacon-footer');
  const sendButton = button('Send', send);
  const compose = make('div', null, 'beacon-compose');
  compose.append(input, sendButton);
  footer.append(mode, compose, note);

  const approveAi = ({destination, model, count, question}) => window.confirm(
    `Authorize one AI request to ${destination}\n` +
    `Model: ${model}\n` +
    `${count} minimized record(s)\n` +
    `Question (sent as entered): ${question}\n\n` +
    'Do not send secrets or sensitive questions.'
  );

  const approveAgent = ({destination, model, events, question}) => window.confirm(
    `Authorize HELM to run read-only case tools through ${destination}?\n` +
    `Model: ${model}\n` +
    `${events} case record(s) are available to the bounded agent\n` +
    `Task (sent as entered): ${question}\n\n` +
    'The backend executes only allow-listed read-only tools. No files, shell commands or evidence are modified.'
  );

  async function send() {
    if (pending || !input.value.trim()) return;
    const question = input.value.trim();
    const current = generation;
    input.value = '';
    message('You', question);
    pending = true;
    sendButton.disabled = true;
    try {
      if (mode.value === 'help') {
        const result = localAnswer(question, host.counts?.() ?? {});
        message('BEACON / offline guide', result.text, result.tab);
      } else if (mode.value === 'ai') {
        const result = await askSelected({
          question,
          records: host.selected?.() ?? [],
          config: host.config?.() ?? {},
          approve: approveAi,
          ask: host.ask
        });
        if (current === generation) message('BEACON / AI (unverified)', result ?? 'Request not authorized.');
      } else {
        const result = await askAgent({
          question,
          counts: host.counts?.() ?? {},
          config: host.config?.() ?? {},
          approve: approveAgent,
          run: host.agent
        });
        if (current === generation) message('HELM / agent (unverified)', result ?? 'Request not authorized.');
      }
    } catch (error) {
      if (current === generation) {
        const detail = error instanceof Error ? error.message : String(error);
        message('BEACON', `Request failed: ${detail} No automatic fallback was attempted.`);
      }
    } finally {
      pending = false;
      sendButton.disabled = false;
      modeNote();
    }
  }

  input.addEventListener('keydown', (event) => {
    if (event.key === 'Enter' && !event.shiftKey && !event.isComposing) {
      event.preventDefault();
      send();
    }
  });
  panel.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') toggle(false);
  });

  panel.append(head, log, suggestions, footer);
  root.append(panel, launcher);
  modeNote();
  reset();
}
