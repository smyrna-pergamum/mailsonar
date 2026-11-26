// Training-mode curriculum. Answers are computed from the loaded case (real parser
// output), not hard-coded, so a lesson stays correct if the dataset is regenerated.
// Text is [tr, en]; German falls back to English.

const lower = v => String(v ?? '').trim().toLowerCase();
const byFile = (c, suffix) => (c.evidence ?? []).find(f => f.source.endsWith(suffix));
const mails = c => (c.events ?? []).filter(e => e.data?.email_analysis);
const firstMail = (c, pred) => mails(c).find(pred);
const phish = c => firstMail(c, e => /parolan/i.test(e.data.subject ?? '') || /phish/i.test(e.message_id));
const bec = c => firstMail(c, e => e.data.email_analysis?.header?.reply_to);
const chain = c => (c.findings ?? []).find(f => f.rule === 'COR-004');
const eventsOf = (c, ids) => (c.events ?? []).filter(e => ids.includes(e.id));
const byRule = (c, rule) => (c.findings ?? []).filter(f => f.rule === rule).flatMap(f => eventsOf(c, f.evidence));
const audit = (c, op) => (c.events ?? []).find(e => lower(e.data?.Operation) === op);
const labelled = c => (c.events ?? []).filter(e => e.source.endsWith('.jsonl') && e.data?.source_dataset);

export const DATASETS = {
  'bec-demo': ['Örnek BEC vakası (sentetik, 6 kaynak)', 'Sample BEC case (synthetic, 6 sources)'],
  'github-baseline': ['GitHub veri seti: 200 etiketli olay, 18 kaynak', 'GitHub dataset: 200 labelled events, 18 sources']
};

export const LESSONS = [
  {
    id: 'sources', dataset: 'bec-demo', level: 1,
    title: ['Log kaynaklarını tanı', 'Know your log sources'],
    goal: ['Bir olayda ilk iş: elinizdeki logları hangi sistemlerin ürettiğini bilmek. Her kaynak farklı bir soruyu cevaplar.', 'First step in any case: know which systems produced your logs. Each source answers a different question.'],
    steps: [
      {q: ['Örnek vakada kaç delil dosyası var?', 'How many evidence files does the sample case contain?'], type: 'text', answer: c => String(c.evidence.length), view: 'home',
        hint: ['Başla sayfasındaki "Log kaynakları ve e-posta sağlayıcıları" tablosunu sayın.', 'Count the rows of the "Log sources and mail providers" table on the Start page.'],
        explain: ['Gateway, kimlik (Entra ID), posta kutusu denetimi, EML/MBOX iletileri ve MTA logu: saldırı zincirinin her halkası farklı bir kaynakta görünür.', 'Gateway, identity (Entra ID), mailbox audit, EML/MBOX messages and the MTA log: each link of the attack chain shows up in a different source.']},
      {q: ['02-entra-signins.jsonl dosyasını hangi ürün üretmiş?', 'Which product produced 02-entra-signins.jsonl?'], type: 'choice', options: ['Entra ID', 'Google Workspace', 'Postfix', 'Exchange Server'],
        answer: c => byFile(c, '02-entra-signins.jsonl')?.profile?.primary?.product ?? '', view: 'home',
        hint: ['Tespit edilen kaynak sütununa ve "Gerekçe" sütununa bakın.', 'Look at the Detected source and Why columns.'],
        explain: ['Oturum açma (sign-in) kayıtları bir Microsoft bulut uygulamasını adlandırıyor; bu Entra ID oturum logunun imzasıdır. Gerçek dışa aktarımda userPrincipalName ve conditionalAccessStatus sütunları bunu kesinleştirir.', 'Sign-in records naming a Microsoft cloud app are the fingerprint of an Entra ID sign-in log. In a real export userPrincipalName and conditionalAccessStatus columns make it certain.']},
      {q: ['06-postfix-mail.log hangi e-posta sunucusuna (MTA) ait?', 'Which mail server (MTA) wrote 06-postfix-mail.log?'], type: 'choice', options: ['Postfix', 'Exim', 'Sendmail', 'Microsoft Exchange'],
        answer: c => byFile(c, '06-postfix-mail.log')?.profile?.primary?.product ?? '', view: 'home',
        hint: ['Satırlardaki "postfix/smtpd[" süreç etiketi ipucudur.', 'The "postfix/smtpd[" process tag in each line is the clue.'],
        explain: ['MTA logları süreç etiketleriyle tanınır: postfix/…, exim mesaj kimliği ve <= / => işaretleri, sendmail[…].', 'MTA logs are recognised by process tags: postfix/…, Exim message ids with <= / =>, sendmail[…].']}
    ]
  },
  {
    id: 'phishing', dataset: 'bec-demo', level: 1,
    title: ['Phishing e-postasını başlıklardan incele', 'Investigate a phishing e-mail from its headers'],
    goal: ['Received zinciri, SPF/DKIM/DMARC ve benzer alan adlarıyla sahte e-postayı kanıtlayın.', 'Prove the fake e-mail using the Received chain, SPF/DKIM/DMARC and look-alike domains.'],
    steps: [
      {q: ['Phishing e-postasının SPF sonucu nedir?', 'What is the SPF result of the phishing e-mail?'], type: 'choice', options: ['pass', 'fail', 'softfail', 'none'],
        answer: c => phish(c)?.data.email_analysis.authentication.spf ?? '', view: 'email',
        hint: ['E-posta analizi ekranında en riskli iletiyi açın; SPF rozetine bakın.', 'Open the riskiest message on the E-mail analysis screen; read the SPF badge.'],
        explain: ['spf=fail: gönderen IP, alan adı adına e-posta göndermeye yetkili değil. Ancak geçen bir SPF de güvenli anlamına gelmez.', 'spf=fail: the sending IP is not authorised for the domain. A passing SPF does not mean safe either.']},
      {q: ['Hangi marka taklit ediliyor?', 'Which brand is impersonated?'], type: 'choice', options: ['Microsoft', 'Google', 'PayPal', 'DHL'],
        answer: () => 'Microsoft', check: (c, v) => lower(v) === 'microsoft' && /micr0soft/.test(phish(c)?.sender ?? ''), view: 'email',
        hint: ['Gönderen alan adındaki 0 (sıfır) harfine dikkat edin.', 'Look closely at the 0 (zero) in the sender domain.'],
        explain: ['micr0soft: "o" yerine "0" kullanan homoglyph/typosquatting. MailSonar bunu MAIL-023 kuralıyla işaretler.', 'micr0soft uses "0" for "o": a homoglyph / typosquatting trick, flagged by rule MAIL-023.']},
      {q: ['E-postanın ilk dış kaynak (origin) IP adresi nedir?', 'What is the first external (origin) IP of the message?'], type: 'text',
        answer: c => phish(c)?.data.email_analysis.origin_ip ?? '', view: 'email',
        hint: ['Received zincirini aşağıdan yukarıya okuyun; özel (10.x, 192.168.x) olmayan ilk IP.', 'Read the Received chain bottom-up; the first non-private IP.'],
        explain: ['Received başlıkları aşağıdan yukarı okunur; yalnızca kendi sunucularınızın eklediği satırlara güvenin. "unknown" ana bilgisayar adı ek bir şüphe işaretidir.', 'Received headers are read bottom-up; trust only lines added by your own servers. An "unknown" host name is an extra red flag.']}
    ]
  },
  {
    id: 'takeover', dataset: 'bec-demo', level: 2,
    title: ['Hesap ele geçirmeyi bul', 'Find the account takeover'],
    goal: ['Kaba kuvvet, password spray ve yeni IP\'den başarılı girişi ayırt edin.', 'Tell brute force, password spray and a successful sign-in from a new IP apart.'],
    steps: [
      {q: ['Hangi hesap ele geçirildi?', 'Which account was compromised?'], type: 'text', answer: c => chain(c)?.account ?? '', view: 'home',
        hint: ['Başla sayfasındaki Saldırı zincirleri kartına bakın.', 'See the Attack chains card on the Start page.'],
        explain: ['COR-004 korelasyonu aynı hesap için phishing → şüpheli giriş → posta kutusu manipülasyonu → sahte talep sırasını 24 saat içinde buldu.', 'COR-004 found phishing → suspicious sign-in → mailbox manipulation → fraudulent request for the same account within 24 h.']},
      {q: ['Saldırgan hangi IP adresinden başarılı giriş yaptı?', 'From which IP did the attacker sign in successfully?'], type: 'text',
        answer: c => byRule(c, 'MAIL-017').find(e => lower(e.data?.result) === 'success')?.ip ?? '', view: 'findings',
        hint: ['Bulgular ekranında MAIL-017 (olağandışı giriş) bulgusunu inceleyin.', 'Inspect the MAIL-017 (unusual login) finding on the Findings screen.'],
        explain: ['Aynı IP önce başarısız denemeler, sonra başarılı giriş ve MFA değişikliği yapıyor: klasik ele geçirme.', 'The same IP first fails, then succeeds and changes MFA: a classic takeover.']},
      {q: ['Password spray (birçok hesaba az deneme) hangi IP\'den geldi?', 'Which IP performed the password spray (few attempts on many accounts)?'], type: 'text',
        answer: c => {
          const counts = new Map();
          for (const e of (c.events ?? []).filter(x => lower(x.data?.result) === 'failure')) {
            const set = counts.get(e.ip) ?? new Set();
            set.add(e.sender);
            counts.set(e.ip, set);
          }
          return [...counts].sort((a, b) => b[1].size - a[1].size)[0]?.[0] ?? '';
        }, view: 'explorer',
        hint: ['Log gezgininde "failed login" arayın ve IP sütununa bakın.', 'Search "failed login" in the Log explorer and look at the IP column.'],
        explain: ['Spray: bir IP, çok hesap, hesap başına az deneme. Kaba kuvvet: tek hesap, kısa sürede çok deneme.', 'Spray: one IP, many accounts, few attempts each. Brute force: one account, many attempts quickly.']}
    ]
  },
  {
    id: 'mailbox', dataset: 'bec-demo', level: 2,
    title: ['Posta kutusu manipülasyonu', 'Mailbox manipulation'],
    goal: ['Saldırganın izlerini gizlemek için oluşturduğu kuralı ve dış yönlendirmeyi bulun.', 'Find the rule and the external forwarding the attacker used to hide.'],
    steps: [
      {q: ['E-postalar hangi dış adrese yönlendirildi?', 'To which external address was mail forwarded?'], type: 'text',
        answer: c => (String(audit(c, 'set-mailbox')?.data?.Parameters ?? '').match(/smtp:([^;\s]+)/i) ?? [])[1] ?? '', view: 'explorer',
        hint: ['Log gezgininde "Set-Mailbox" arayın; ForwardingSmtpAddress parametresi.', 'Search "Set-Mailbox" in the Log explorer; read ForwardingSmtpAddress.'],
        explain: ['DeliverToMailboxAndForward=True: kullanıcı hiçbir şey fark etmez, saldırgan her e-postanın kopyasını alır.', 'DeliverToMailboxAndForward=True: the user notices nothing while the attacker receives a copy of every mail.']},
      {q: ['Gelen kutusu kuralı e-postaları hangi klasöre taşıyor?', 'Into which folder does the inbox rule move mail?'], type: 'choice', options: ['RSS Subscriptions', 'Archive', 'Deleted Items', 'Junk Email'],
        answer: c => (String(audit(c, 'new-inboxrule')?.data?.Parameters ?? '').match(/MoveToFolder=([^;]+)/) ?? [])[1] ?? '', view: 'explorer',
        hint: ['"New-InboxRule" kaydının Parameters alanını okuyun.', 'Read the Parameters field of the "New-InboxRule" record.'],
        explain: ['Az kullanılan klasöre taşıma + okundu işaretleme, güvenlik ve ödeme e-postalarını kurbandan saklar.', 'Moving to a rarely used folder and marking as read hides security and payment mails from the victim.']}
    ]
  },
  {
    id: 'bec', dataset: 'bec-demo', level: 3,
    title: ['BEC: sahte ödeme talebi', 'BEC: fake payment request'],
    goal: ['Ele geçirilen gerçek hesaptan gönderilen dolandırıcılık e-postasını tanıyın.', 'Recognise the fraud mail sent from the real, compromised account.'],
    steps: [
      {q: ['Sahte ödeme e-postasının Reply-To alan adı nedir?', 'What is the Reply-To domain of the fake payment mail?'], type: 'text',
        answer: c => (bec(c)?.data.email_analysis.header.reply_to ?? '').split('@')[1] ?? '', view: 'email',
        hint: ['E-posta analizinde "banka hesap değişikliği" konulu iletiyi açın.', 'Open the "banka hesap değişikliği" message in E-mail analysis.'],
        explain: ['Yanıtlar saldırganın benzer alan adına gider; finans ekibi kurbanla değil saldırganla yazışır.', 'Replies go to the attacker\'s look-alike domain; finance talks to the attacker, not the victim.']},
      {q: ['Bu e-posta SPF/DKIM/DMARC kontrollerinden geçti mi?', 'Did this mail pass SPF/DKIM/DMARC?'], type: 'choice', options: ['Evet / Yes', 'Hayır / No'],
        answer: c => (bec(c)?.data.email_analysis.authentication.dmarc === 'pass' ? 'Evet / Yes' : 'Hayır / No'), view: 'email',
        hint: ['Kimlik doğrulama rozetlerine bakın.', 'Look at the authentication badges.'],
        explain: ['Geçti: e-posta gerçek, ele geçirilmiş hesaptan gönderildi. SPF/DKIM/DMARC tek başına güvenliği kanıtlamaz; davranış ve korelasyon gerekir.', 'It passed: the mail came from the real, compromised account. Authentication alone never proves safety; behaviour and correlation do.']}
    ]
  },
  {
    id: 'malware', dataset: 'bec-demo', level: 2,
    title: ['Zararlı ekler', 'Malicious attachments'],
    goal: ['Çift uzantı ve makro içeren ekleri hash\'leriyle tespit edin (hiçbiri çalıştırılmaz).', 'Detect double extensions and macro documents with their hashes (nothing is executed).'],
    steps: [
      {q: ['Çift uzantılı ekin dosya adı nedir?', 'What is the file name of the double-extension attachment?'], type: 'text',
        answer: c => mails(c).flatMap(e => e.data.email_analysis.attachments ?? []).find(a => (a.flags ?? []).some(f => f.includes('double extension')))?.filename ?? '', view: 'email',
        hint: ['"Fatura_2026_11" konulu iletilerin Ekler tablosuna bakın.', 'Check the Attachments table of the "Fatura_2026_11" messages.'],
        explain: ['.pdf.exe: Windows uzantıları gizlerse kullanıcı PDF görür. İçerik "MZ" ile başlıyor: çalıştırılabilir dosya.', '.pdf.exe: if Windows hides extensions the user sees a PDF. The content starts with "MZ": an executable.']},
      {q: ['Makro içeren Office dosyasının uzantısı nedir?', 'What is the extension of the macro-enabled Office file?'], type: 'choice', options: ['docm', 'pdf', 'zip', 'iso'],
        answer: c => mails(c).flatMap(e => e.data.email_analysis.attachments ?? []).find(a => (a.flags ?? []).some(f => f.includes('macro')))?.extension ?? '', view: 'email',
        hint: ['Ekler tablosundaki işaretler (flags) sütunu.', 'The flags column in the Attachments table.'],
        explain: ['Aynı SHA-256 değeri birden fazla alıcıda görülüyorsa kampanyadır; hash\'i EDR\'de taratın.', 'The same SHA-256 at several recipients means a campaign; sweep the hash in your EDR.']}
    ]
  },
  {
    id: 'rule', dataset: 'bec-demo', level: 2,
    title: ['Kendi tespit kuralını yaz', 'Write your own detection rule'],
    goal: ['Dış yönlendirmeyi açan Set-Mailbox işlemini yakalayan bir kural ekleyin.', 'Add a rule that catches the Set-Mailbox operation enabling forwarding.'],
    steps: [
      {q: ['Tespit kuralları ekranında "action" alanında "set-mailbox" içeren bir kural ekleyin (AI ile ya da AI\'sız hızlı kural). Sonra Kontrol et\'e basın.', 'On Detection rules add a rule whose "action" contains "set-mailbox" (with AI or the quick form). Then press Check.'], type: 'task',
        check: c => (c.rules ?? []).some(r => r.field === 'action' && 'set-mailbox'.includes(lower(r.contains)) && lower(r.contains).length >= 5), view: 'rules',
        hint: ['"AI olmadan hızlı kural" bölümünü açın: Alan=action, contains=set-mailbox.', 'Open "Quick rule without AI": Field=action, contains=set-mailbox.'],
        explain: ['İyi kural: gerçek alan değerine dayanır, önce test edilir, yanlış pozitifleri açıklanır.', 'A good rule uses a real field value, is tested first and documents its false positives.']}
    ]
  },
  {
    id: 'multisource', dataset: 'github-baseline', level: 2,
    title: ['Karışık kaynaklı loglar (GitHub veri seti)', 'Mixed-source logs (GitHub dataset)'],
    goal: ['Tek dosyada birden çok sağlayıcının kayıtları varsa her kaydın kaynağını ayırt edin.', 'When one file mixes several providers, tell each record\'s source apart.'],
    steps: [
      {q: ['JSONL dosyasında en çok kaydı hangi kaynak üretmiş?', 'Which source produced the most records in the JSONL file?'], type: 'choice', options: ['Exchange Server', 'Exchange Online', 'Entra ID', 'Google Workspace (Gmail)'],
        answer: c => byFile(c, '.jsonl')?.profile?.primary?.product ?? '', view: 'home',
        hint: ['Log kaynakları tablosunda JSONL satırının dökümü (breakdown).', 'The breakdown under the JSONL row of the Log sources table.'],
        explain: ['Exchange Online denetim kayıtları posta kutusu işlemlerini (kural, silme, izin) gösterir; kimlik olayları Entra ID\'den gelir.', 'Exchange Online audit records show mailbox operations (rules, deletes, permissions); identity events come from Entra ID.']},
      {q: ['Bu dosyada kaç farklı ürün tespit edildi?', 'How many distinct products were detected in this file?'], type: 'text',
        answer: c => String(new Set((byFile(c, '.jsonl')?.profile?.breakdown ?? []).map(b => b.product)).size), view: 'home',
        hint: ['Döküm listesindeki farklı ürün adlarını sayın.', 'Count the distinct product names in the breakdown.'],
        explain: ['msexchange-* kayıtları Exchange Server altında birleşir; Postfix, Exim, Dovecot, Rspamd, Amazon SES ayrı sistemlerdir.', 'msexchange-* records group under Exchange Server; Postfix, Exim, Dovecot, Rspamd and Amazon SES are separate systems.']},
      {q: ['Kayıtların yüzde kaçı normal trafik olarak etiketli?', 'What percentage of records are labelled normal traffic?'], type: 'choice', options: ['%25', '%55', '%80', '%95'],
        answer: c => {
          const rows = labelled(c);
          return `%${Math.round((rows.filter(e => e.data.source_dataset === 'normal_traffic').length / Math.max(1, rows.length)) * 100)}`;
        }, view: 'explorer',
        hint: ['Log gezgininde "normal_traffic" arayın ve sayıyı toplam kayda bölün.', 'Search "normal_traffic" in the Log explorer and divide by the total.'],
        explain: ['Gerçek ortamda saldırı kayıtları çok azınlıktadır; iyi bir analiz önce normali tanır.', 'In real environments attack records are a small minority; good analysis knows normal first.']}
    ]
  },
  {
    id: 'false-positives', dataset: 'github-baseline', level: 3,
    title: ['Yanlış pozitifleri ölç', 'Measure false positives'],
    goal: ['Etiketli veride kuralların normal trafikte kaç kez yanlış alarm verdiğini bulun.', 'Use labelled data to count how often rules fire on normal traffic.'],
    steps: [
      {q: ['"normal_traffic" etiketli JSONL kayıtlarından kaçı en az bir bulgu üretti?', 'How many JSONL records labelled "normal_traffic" produced at least one finding?'], type: 'text',
        answer: c => {
          const flagged = new Set((c.findings ?? []).flatMap(f => f.evidence));
          return String(labelled(c).filter(e => e.data.source_dataset === 'normal_traffic' && flagged.has(e.id)).length);
        }, view: 'findings',
        hint: ['Bulgulardaki kanıtları "normal_traffic" etiketiyle karşılaştırın; HELM\'e de sorabilirsiniz.', 'Compare finding evidence with the "normal_traffic" label; you can also ask HELM.'],
        explain: ['Bu sayı / normal kayıt sayısı = yanlış pozitif oranı. Kuralı daraltın veya Bulgular\'da "yanlış pozitif" olarak değerlendirin; değerlendirmeler eğitim verisi olur.', 'This count / normal records = false-positive rate. Tighten the rule or mark it as false positive in Findings; reviews become training data.']}
    ]
  }
];

const norm = v => lower(v).replace(/^%/, '').replace(/[<>"']/g, '');

/** Check an answer; returns {ok, expected}. */
export function checkAnswer(step, value, c) {
  if (step.type === 'task') return {ok: Boolean(step.check(c)), expected: ''};
  if (step.check) return {ok: step.check(c, value), expected: step.answer(c)};
  const expected = String(step.answer(c) ?? '');
  if (!expected) return {ok: false, expected: '', missing: true};
  const a = norm(value);
  const b = norm(expected);
  const ok = a === b || (step.type === 'choice' && a.length > 2 && b.includes(a));
  return {ok, expected};
}
