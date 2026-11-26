// Simplified navigation: a short primary list in investigation order, with the
// specialist views folded into an "Expert tools" group that remembers its state.
const PRIMARY = [
  ['home', 'Start'],
  ['training', 'Training mode'],
  ['dashboard', 'Overview'],
  ['email', 'E-mail analysis'],
  ['findings', 'Findings'],
  ['explorer', 'Log explorer'],
  ['ai', 'AI analysis'],
  ['copilot', 'HELM agent'],
  ['rules', 'Detection rules'],
  ['case', 'Case & report'],
  ['investigations', 'Large investigations'],
  ['settings', 'AI model']
];
const EXPERT = [
  ['timeline', 'Timeline & correlation'],
  ['graph', 'Relationship graph'],
  ['mitre', 'MITRE ATT&CK'],
  ['ti', 'Threat intelligence'],
  ['evidence', 'Evidence'],
  ['eval', 'AI evaluation']
];
const KEY = 'mailsonar.expertOpen';

export function organizeNav(nav, onSelect) {
  const buttons = new Map([...nav.querySelectorAll('button[data-tab]')].map(b => [b.dataset.tab, b]));
  const make = (id, label) => {
    const button = buttons.get(id) ?? Object.assign(document.createElement('button'), {type: 'button'});
    button.dataset.tab = id;
    button.textContent = label;
    if (!button.onclick) button.onclick = () => onSelect(id);
    return button;
  };
  nav.replaceChildren(...PRIMARY.map(([id, label]) => make(id, label)));
  const group = document.createElement('details');
  group.className = 'ms-expert';
  try {
    group.open = localStorage.getItem(KEY) === '1';
  } catch {
    group.open = false;
  }
  group.ontoggle = () => {
    try {
      localStorage.setItem(KEY, group.open ? '1' : '0');
    } catch {
      // Ignore unavailable storage.
    }
  };
  const summary = document.createElement('summary');
  summary.textContent = 'Expert tools';
  group.append(summary, ...EXPERT.map(([id, label]) => make(id, label)));
  nav.append(group);
  return {
    reveal(id) {
      if (EXPERT.some(([x]) => x === id)) group.open = true;
    }
  };
}

/** Move existing children of a section into a collapsed <details> block. */
export function foldAdvanced(section, label, keep = []) {
  const details = document.createElement('details');
  details.className = 'ms-advanced';
  const summary = document.createElement('summary');
  summary.textContent = label;
  details.append(summary);
  for (const child of [...section.children]) {
    if (!keep.includes(child)) details.append(child);
  }
  section.append(details);
  return details;
}
