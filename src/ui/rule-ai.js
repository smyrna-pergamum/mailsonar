// Detection rules made easy: describe the behaviour in plain language and HELM
// (skill `detection-engineering`) proposes rules, tests them with `test_rule` and
// returns JSON. A no-AI quick form covers simple cases. Nothing is activated until
// the analyst presses "Add".
import {customFindings, validateRules} from '../analysis.js';
import {t} from '../i18n.js';
import {createAgentPanel, esc} from './agent-view.js';
import {parseRules, runHelm} from './helm-run.js';
import {getProvider, isLoopback} from './provider.js';

const EXAMPLES = [
  'Detect inbox rules that move or delete security mails',
  'Mail forwarded automatically to external addresses',
  'Sign-ins from the IP 203.0.113.66',
  'Payment or bank account change requests',
  'Macro-enabled Office attachments'
];
const FIELDS = ['action', 'sender', 'recipient', 'ip', 'message_id', 'source', 'timestamp'];

export function mountRuleAi({host, api}) {
  const card = document.createElement('article');
  card.className = 'ms-rule-ai';
  card.innerHTML = `<h2>${esc(t('Write detection rules with AI'))}</h2>
    <p class="ms-muted">${esc(t('Describe what you want to detect. HELM picks real field values from this case, tests each rule and explains false positives.'))}</p>
    <textarea class="ms-rule-intent" rows="3" placeholder="${esc(t('e.g. Alert when someone creates an inbox rule that hides mails containing payment'))}"></textarea>
    <div class="ms-chips"></div>
    <p class="ms-warn ms-cloud-note" hidden>${esc(t('Cloud provider: identifiers are sent as aliases, so AI-written rules on sender, recipient, IP or message ID will not match. Use a local model for value-based rules.'))}</p>
    <div class="ms-actions"><button type="button" class="primary ms-rule-run">${esc(t('Generate rules'))}</button></div>
    <div class="ms-rule-result"></div>
    <details class="ms-quick-rule"><summary>${esc(t('Quick rule without AI'))}</summary>
      <div class="ms-form-row">
        <label>${esc(t('Field'))}<select class="qr-field">${FIELDS.map(f => `<option value="${f}">${f}</option>`).join('')}</select></label>
        <label>${esc(t('contains'))}<input class="qr-contains" placeholder="inboxrule"></label>
        <label>${esc(t('Severity'))}<select class="qr-sev" data-no-translate><option value="high">high</option><option value="medium" selected>medium</option><option value="low">low</option></select></label>
      </div>
      <label>${esc(t('Description'))}<input class="qr-desc" placeholder="${esc(t('What the analyst should check'))}"></label>
      <div class="ms-actions"><button type="button" class="qr-test">${esc(t('Test'))}</button><button type="button" class="primary qr-add">${esc(t('Add rule'))}</button><span class="qr-out ms-muted"></span></div>
    </details>`;
  host.prepend(card);
  const intent = card.querySelector('.ms-rule-intent');
  const chips = card.querySelector('.ms-chips');
  for (const example of EXAMPLES) {
    const chip = document.createElement('button');
    chip.type = 'button';
    chip.className = 'ms-chip';
    chip.textContent = t(example);
    chip.onclick = () => {
      intent.value = chip.textContent;
      intent.focus();
    };
    chips.append(chip);
  }
  const panel = createAgentPanel({onEvidence: id => api.inspect(id)});
  card.querySelector('.ms-rule-result').before(panel.el);
  const result = card.querySelector('.ms-rule-result');

  function preview(rules) {
    const events = api.getCase().events;
    return rules.map(rule => ({rule, hits: customFindings(events, [rule]).length}));
  }

  function showProposals(rules) {
    result.replaceChildren();
    if (!rules.length) {
      result.innerHTML = `<p class="ms-warn">${esc(t('No valid rule JSON found in the answer. Rephrase the request or use the quick form.'))}</p>`;
      return;
    }
    const total = api.getCase().events.length;
    const rows = preview(rules).map(({rule, hits}, i) => `<tr>
      <td><input type="checkbox" data-i="${i}" checked></td><td><code>${esc(rule.id)}</code></td><td>${esc(rule.field)}</td>
      <td><code>${esc(rule.contains)}</code></td><td>${esc(rule.severity)}</td><td>${hits} (${total ? Math.round((hits / total) * 100) : 0}%)</td><td>${esc(rule.description)}</td></tr>`).join('');
    result.innerHTML = `<h3>${esc(t('Proposed rules'))}</h3><div class="tablewrap"><table><thead><tr><th></th><th>ID</th><th>${esc(t('Field'))}</th><th>${esc(t('contains'))}</th><th>${esc(t('Severity'))}</th><th>${esc(t('Matches'))}</th><th>${esc(t('Description'))}</th></tr></thead><tbody>${rows}</tbody></table></div>
      <div class="ms-actions"><button type="button" class="primary ms-add">${esc(t('Add selected rules'))}</button></div>`;
    result.querySelector('.ms-add').onclick = () => {
      const chosen = [...result.querySelectorAll('input[data-i]:checked')].map(box => rules[Number(box.dataset.i)]);
      add(chosen);
    };
  }

  function add(rules) {
    try {
      const added = api.addRules(rules);
      api.status('{count} rules added and applied.', {count: added});
    } catch (error) {
      api.status(String(error?.message ?? error));
    }
  }

  let busy = false;
  card.querySelector('.ms-rule-run').onclick = async () => {
    const want = intent.value.trim();
    if (busy || want.length < 5) return;
    card.querySelector('.ms-cloud-note').hidden = isLoopback(getProvider().endpoint);
    busy = true;
    panel.start(t('Rule writing'));
    try {
      const outcome = await runHelm({
        backend: api.backend,
        getCase: api.getCase,
        skill: 'detection-engineering',
        task: `Write MailSonar custom detection rules for this request: "${want}". Test every candidate with test_rule and end with the JSON array.`,
        onStep: s => panel.step(s)
      });
      panel.finish(outcome);
      showProposals(parseRules(outcome.answer));
    } catch (error) {
      panel.fail(error);
    } finally {
      busy = false;
    }
  };

  const quick = () => {
    const contains = card.querySelector('.qr-contains').value.trim();
    const field = card.querySelector('.qr-field').value;
    const existing = new Set(api.getRules().map(r => r.id));
    let n = existing.size + 1;
    while (existing.has(`CUSTOM-${String(n).padStart(3, '0')}`)) n++;
    return validateRules([{id: `CUSTOM-${String(n).padStart(3, '0')}`, field, contains, severity: card.querySelector('.qr-sev').value, description: card.querySelector('.qr-desc').value.trim() || `${field} contains "${contains}"`}])[0];
  };
  const out = card.querySelector('.qr-out');
  card.querySelector('.qr-test').onclick = () => {
    try {
      const [{hits}] = preview([quick()]);
      out.textContent = t('{count} matching records', {count: hits});
    } catch (error) {
      out.textContent = String(error?.message ?? error);
    }
  };
  card.querySelector('.qr-add').onclick = () => {
    try {
      add([quick()]);
    } catch (error) {
      out.textContent = String(error?.message ?? error);
    }
  };
}
