// One-click AI analysis: each profile is a HELM skill. The skill's preload tools run
// deterministically in the backend, so even small local models start from real data.
import {t} from '../i18n.js';
import {createAgentPanel, esc} from './agent-view.js';
import {runHelm} from './helm-run.js';
import {describeProvider, onProvider, providerReady} from './provider.js';
import {mountSavedQueries} from './saved-queries.js';

export const PROFILES = [
  {skill: 'triage', title: 'Overall triage', hint: 'What happened, what matters most, next steps', task: 'Triage this case: what most likely happened, the strongest evidence, the accounts and IPs involved, and the next steps.'},
  {skill: 'phishing-triage', title: 'Phishing campaign', hint: 'Sender, recipients, authentication, who interacted', task: 'Investigate the phishing activity: campaign sender and infrastructure, recipients, authentication results and which recipients interacted afterwards.'},
  {skill: 'email-header-forensics', title: 'Header forensics', hint: 'Received chain, SPF/DKIM/DMARC, Reply-To, URLs', task: 'Analyse the e-mail headers of the riskiest messages: Received chain, SPF/DKIM/DMARC, From vs Return-Path vs Reply-To, deceptive URLs.'},
  {skill: 'account-takeover', title: 'Account takeover', hint: 'Brute force, spray, new IP, MFA changes', task: 'Investigate account takeover: brute force, password spray, successful sign-ins from new IPs, MFA changes and post-compromise activity.'},
  {skill: 'bec-fraud', title: 'BEC / payment fraud', hint: 'Payment change requests, impersonation, kill chain', task: 'Investigate business email compromise: payment or bank-detail change requests, impersonation, Reply-To redirection and the compromise path.'},
  {skill: 'mailbox-rule-abuse', title: 'Rules & forwarding', hint: 'Inbox rules, external forwarding, deletions', task: 'Investigate mailbox rules, forwarding and deletions: which are malicious, who created them and from which login.'},
  {skill: 'malware-delivery', title: 'Malicious attachments', hint: 'Macros, executables, hashes, recipients', task: 'Investigate malicious attachments: types, SHA-256 hashes, recipients and risk.'},
  {skill: 'data-exfiltration', title: 'Data exfiltration', hint: 'Outbound spikes, external recipients', task: 'Investigate possible data exfiltration over mail: outbound spikes, external recipients and forwarding.'},
  {skill: 'incident-report', title: 'Write incident report', hint: 'Executive summary, timeline, recommendations', task: 'Write a draft incident report for this case.'}
];

export function mountQuickAi({host, api}) {
  const card = document.createElement('article');
  card.className = 'ms-quick';
  card.innerHTML = `<h2>${esc(t('One-click AI analysis'))}</h2>
    <p class="ms-muted">${esc(t('Pick a question. HELM loads the matching skill, gathers the evidence with read-only tools and writes a cited answer.'))}</p>
    <p class="ms-provider-line"><span class="ms-dot"></span><span class="ms-provider-text"></span> <button type="button" class="ms-link" data-go="settings">${esc(t('Change AI model'))}</button></p>
    <div class="ms-profiles"></div>
    <div class="ms-ask"><input class="ms-free" placeholder="${esc(t('Or ask your own question, e.g. Which accounts were compromised?'))}"><button type="button" class="primary ms-free-run">${esc(t('Ask HELM'))}</button></div>`;
  host.prepend(card);
  const panel = createAgentPanel({onEvidence: id => api.inspect(id)});
  card.append(panel.el);
  const grid = card.querySelector('.ms-profiles');
  for (const profile of PROFILES) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'ms-profile';
    button.innerHTML = `<strong>${esc(t(profile.title))}</strong><small>${esc(t(profile.hint))}</small>`;
    button.onclick = () => run(profile.task, profile.skill, t(profile.title));
    grid.append(button);
  }
  card.querySelector('[data-go]').onclick = () => api.tab('settings');
  const free = card.querySelector('.ms-free');
  card.querySelector('.ms-free-run').onclick = () => free.value.trim() && run(free.value.trim(), null, free.value.trim());
  free.onkeydown = e => {
    if (e.key === 'Enter' && free.value.trim()) run(free.value.trim(), null, free.value.trim());
  };
  let busy = false;
  const saved = mountSavedQueries({card, api, run: (task, skill, title) => run(task, skill, title), freeInput: free});
  async function run(task, skill, title) {
    if (busy) return;
    busy = true;
    card.querySelectorAll('button').forEach(b => (b.disabled = true));
    panel.start(title);
    try {
      const outcome = await runHelm({backend: api.backend, getCase: api.getCase, task, skill, onStep: s => panel.step(s), feedback: api.feedbackContext()});
      panel.finish(outcome);
      api.onAiResult?.(outcome, title);
      api.status('AI analysis received; analyst verification required.');
    } catch (error) {
      panel.fail(error);
      api.status(String(error?.message ?? error));
    } finally {
      busy = false;
      card.querySelectorAll('button').forEach(b => (b.disabled = false));
    }
  }
  const refresh = p => {
    card.querySelector('.ms-provider-text').textContent = describeProvider(p);
    card.querySelector('.ms-dot').className = `ms-dot ${providerReady(p) ? 'ok' : 'bad'}`;
  };
  onProvider(refresh);
  refresh();
  return {run, reloadSaved: () => saved.load()};
}
