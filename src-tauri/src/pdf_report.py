"""Bounded local PDF writer; embedded into the desktop binary by Rust."""
import io, json, os, sys
from pathlib import Path
from xml.sax.saxutils import escape
from reportlab.graphics.shapes import Drawing, String, Line, Rect
from reportlab.graphics.charts.barcharts import VerticalBarChart, HorizontalBarChart
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer

LIMIT = 2 * 1024 * 1024
LABELS = {
 'en': ['Investigation report', 'Analyst review required. Indicators and AI claims are not confirmed incidents.', 'Case', 'Export timestamp', 'Analyst notes', 'Evidence manifest', 'Detection findings', 'AI assessment (unverified)', 'Evidence IDs', 'Analyst work product', 'Scope', 'evidence files', 'findings', 'No AI assessment supplied.', 'No findings supplied. This does not establish absence of compromise.', 'Original description'],
 'de': ['Untersuchungsbericht', 'Analystenprüfung erforderlich. Indikatoren und KI-Aussagen sind keine bestätigten Vorfälle.', 'Fall', 'Exportzeitpunkt', 'Analystennotizen', 'Beweismittelverzeichnis', 'Erkennungsbefunde', 'KI-Bewertung (ungeprüft)', 'Beweismittel-IDs', 'Analystenbericht', 'Umfang', 'Beweisdateien', 'Befunde', 'Keine KI-Bewertung vorhanden.', 'Keine Befunde vorhanden. Eine Kompromittierung ist damit nicht ausgeschlossen.', 'Originalbeschreibung'],
 'tr': ['İnceleme raporu', 'Analist doğrulaması gereklidir. Göstergeler ve AI iddiaları doğrulanmış olay değildir.', 'Vaka', 'Dışa aktarma zamanı', 'Analist notları', 'Delil listesi', 'Tespit bulguları', 'AI değerlendirmesi (doğrulanmamış)', 'Delil kimlikleri', 'Analist çalışma raporu', 'Kapsam', 'delil dosyası', 'bulgu', 'AI değerlendirmesi eklenmemiş.', 'Bulgu eklenmemiş. Bu, ihlal olmadığını kanıtlamaz.', 'Özgün açıklama'],
}

def register_fonts():
    # Only fixed system locations; report content cannot select resources.
    windows = Path(os.environ.get('WINDIR', 'C:/Windows')) / 'Fonts'
    candidates = [(windows/'arial.ttf', windows/'arialbd.ttf'),
        (Path('/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf'), Path('/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf')),
        (Path('/System/Library/Fonts/Supplemental/Arial.ttf'), Path('/System/Library/Fonts/Supplemental/Arial Bold.ttf'))]
    for regular, bold in candidates:
        if regular.is_file() and bold.is_file():
            pdfmetrics.registerFont(TTFont('ReportSans', str(regular)))
            pdfmetrics.registerFont(TTFont('ReportSans-Bold', str(bold)))
            return
    raise ValueError('Install Arial or DejaVu Sans for Unicode PDF reports; HTML export is also available')

VISUAL = {
 'en': {'summary':'Incident summary','analysis':'Case analysis','relationships':'Relationship explanation','activity':'Event activity (UTC)','severity':'Finding priorities','empty':'No usable data for this chart.','limits':'Charts use at most 24 populated UTC hours and six shared entities. The graph shows at most eight evidence IDs. Omitted relationships remain in the case.','caution':'Shared identifiers and temporal proximity are investigative leads, not proof of causation.','overview':'{events} events; {dated} have explicit, parseable timezones. Missing timestamps: {missing}; ambiguous or invalid: {ambiguous}.','period':'Observed interval: {first} to {last}.','review':'Analyst reviews: {reviewed}; supported: {supported}; false positives: {false_positive}; insufficient evidence: {insufficient}.','notes':'No analyst narrative supplied. Review the original evidence before drawing conclusions.','shared':'{kind}: {value} links {count} events.','high':'High','medium':'Medium','low':'Low','info':'Information','critical':'Critical','unknown':'Unknown','benign':'Benign'},
 'de': {'summary':'Vorfallsübersicht','analysis':'Fallanalyse','relationships':'Beziehungserklärung','activity':'Ereignisaktivität (UTC)','severity':'Befundprioritäten','empty':'Keine nutzbaren Daten für dieses Diagramm.','limits':'Diagramme zeigen maximal 24 belegte UTC-Stunden und sechs gemeinsame Entitäten. Der Graph zeigt höchstens acht Beweis-IDs. Weitere Beziehungen bleiben im Fall.','caution':'Gemeinsame Kennungen und zeitliche Nähe sind Ermittlungsansätze, kein Kausalitätsnachweis.','overview':'{events} Ereignisse; {dated} mit expliziter, lesbarer Zeitzone. Fehlende Zeitstempel: {missing}; mehrdeutig oder ungültig: {ambiguous}.','period':'Beobachteter Zeitraum: {first} bis {last}.','review':'Analystenbewertungen: {reviewed}; gestützt: {supported}; Fehlalarme: {false_positive}; unzureichende Beweise: {insufficient}.','notes':'Kein Analystentext vorhanden. Originalbeweise vor Schlussfolgerungen prüfen.','shared':'{kind}: {value} verbindet {count} Ereignisse.','high':'Hoch','medium':'Mittel','low':'Niedrig','info':'Information','critical':'Kritisch','unknown':'Unbekannt','benign':'Harmlos'},
 'tr': {'summary':'Olay özeti','analysis':'Vaka analizi','relationships':'İlişkisel açıklama','activity':'Olay zaman grafiği (UTC)','severity':'Bulgu önem dağılımı','empty':'Bu grafik için kullanılabilir veri yok.','limits':'Grafikler en fazla 24 dolu UTC saatini ve altı ortak varlığı gösterir. İlişki grafiği en fazla sekiz delil kimliği gösterir. Diğer ilişkiler vakada korunur.','caution':'Ortak kimlikler ve zaman yakınlığı inceleme ipucudur; nedensellik kanıtı değildir.','overview':'{events} olay; {dated} kayıtta açık ve ayrıştırılabilir saat dilimi var. Eksik zaman damgası: {missing}; belirsiz veya geçersiz: {ambiguous}.','period':'Gözlenen zaman aralığı: {first} - {last}.','review':'Analist değerlendirmesi: {reviewed}; destekleniyor: {supported}; yanlış pozitif: {false_positive}; yetersiz delil: {insufficient}.','notes':'Analist açıklaması eklenmemiş. Sonuç çıkarmadan önce özgün delilleri inceleyin.','shared':'{kind}: {value}, {count} olayı ilişkilendiriyor.','high':'Yüksek','medium':'Orta','low':'Düşük','info':'Bilgi','critical':'Kritik','unknown':'Bilinmiyor','benign':'Zararsız'},
}

def bar_chart(rows, labels, horizontal=False):
    drawing=Drawing(500,190)
    if not rows:
        drawing.add(String(5,95,labels['empty'],fontName='ReportSans',fontSize=10));return drawing
    chart=HorizontalBarChart() if horizontal else VerticalBarChart()
    chart.x=95 if horizontal else 35;chart.y=55;chart.width=390 if horizontal else 450;chart.height=120
    chart.data=[[int(row[1]) for row in rows]]
    chart.categoryAxis.categoryNames=[str(row[0]) for row in rows]
    chart.categoryAxis.labels.fontName='ReportSans';chart.categoryAxis.labels.fontSize=8 if horizontal else 6
    if not horizontal:
        chart.categoryAxis.labels.angle=45;chart.categoryAxis.labels.boxAnchor='ne';chart.categoryAxis.labels.dy=-5
    chart.valueAxis.valueMin=0;chart.valueAxis.labels.fontName='ReportSans';chart.valueAxis.labels.fontSize=8
    chart.valueAxis.forceZero=True;chart.valueAxis.valueStep=max(1, max(row[1] for row in rows)//5)
    chart.bars[0].fillColor=colors.HexColor('#087f8c');chart.bars[0].strokeColor=None
    chart.barLabels.fontName='ReportSans';chart.barLabels.fontSize=8;chart.barLabelFormat='%d'
    drawing.add(chart);return drawing

def relationship_chart(groups,labels):
    drawing=Drawing(500,250)
    if not groups:
        drawing.add(String(5,125,labels['empty'],fontName='ReportSans',fontSize=10));return drawing
    groups=groups[:6];ids=list(dict.fromkeys(e for group in groups for e in group.get('evidence',[])))[:8]
    positions={value:224-index*28 for index,value in enumerate(ids)}
    for index,group in enumerate(groups):
        y=224-index*38
        for evidence in group.get('evidence',[]):
            if evidence in positions:drawing.add(Line(225,y,365,positions[evidence],strokeColor=colors.HexColor('#a7bbc7'),strokeWidth=0.7))
    for index,group in enumerate(groups):
        y=224-index*38;drawing.add(Rect(3,y-13,222,28,fillColor=colors.HexColor('#e5f3f3'),strokeColor=colors.HexColor('#087f8c'),rx=4,ry=4))
        label=f"{group.get('kind','')}: {group.get('value','')}"
        drawing.add(String(9,y-3,label[:39]+('...' if len(label)>39 else ''),fontName='ReportSans',fontSize=8))
    for value,y in positions.items():
        drawing.add(Rect(365,y-11,130,24,fillColor=colors.HexColor('#edf1f7'),strokeColor=colors.HexColor('#73899e'),rx=4,ry=4))
        drawing.add(String(370,y-3,value[:22]+('...' if len(value)>22 else ''),fontName='ReportSans',fontSize=7))
    return drawing

def generate(data):
    if not isinstance(data, dict): raise ValueError('Report must be an object')
    register_fonts()
    labels = LABELS.get(data.get('locale'), LABELS['en'])
    visual = VISUAL.get(data.get('locale'),VISUAL['en'])
    styles = getSampleStyleSheet()
    for style in styles.byName.values():
        style.fontName = 'ReportSans'
        style.textColor = colors.HexColor('#193344')
    for name in ['Title', 'Heading1', 'Heading2', 'Heading3']: styles[name].fontName = 'ReportSans-Bold'
    styles['BodyText'].fontSize = 10
    styles['BodyText'].leading = 15
    styles['Heading2'].spaceBefore = 15
    styles['Heading2'].spaceAfter = 7
    flow = [Paragraph(labels[0], styles['Title']), Paragraph(labels[1], styles['BodyText']), Spacer(1,12)]
    def paragraph(value):
        # Escape all untrusted ReportLab markup, links and resource references.
        value = ''.join(c if c in '\n\t' or ord(c)>=32 else '?' for c in str(value))
        for start in range(0,len(value) or 1,1200):
            flow.append(Paragraph(escape(value[start:start+1200]).replace('\n','<br/>'),styles['BodyText']))
            flow.append(Spacer(1,4))
    def section(index, value=None):
        flow.append(Paragraph(labels[index],styles['Heading2']))
        if value is not None: paragraph(value)
    section(2,data.get('name',''))
    section(3,data.get('exported_at',''))
    evidence,findings=data.get('evidence',[]),data.get('findings',[])
    analysis=data.get('analysis',{})
    flow.append(Paragraph(visual['summary'],styles['Heading2']))
    paragraph(f'{len(evidence)} {labels[11]} | {len(findings)} {labels[12]}')
    if analysis:
        quality=analysis.get('time_quality',{})
        paragraph(visual['overview'].format(events=analysis.get('events',0),dated=analysis.get('dated',0),missing=quality.get('missing',0),ambiguous=quality.get('ambiguous',0)))
        if analysis.get('first'): paragraph(visual['period'].format(first=analysis['first'],last=analysis['last']))
    flow.append(Paragraph(visual['analysis'],styles['Heading2']))
    paragraph(data.get('notes','') or visual['notes'])
    reviews=analysis.get('reviews',{})
    if reviews: paragraph(visual['review'].format(**{key:reviews.get(key,0) for key in ['reviewed','supported','false_positive','insufficient']}))
    flow.append(Paragraph(visual['activity'],styles['Heading2']))
    flow.append(bar_chart([(str(row[0])[5:16],row[1]) for row in analysis.get('timeline',[])][-24:],visual))
    flow.append(Paragraph(visual['severity'],styles['Heading2']))
    flow.append(bar_chart([(visual.get(row['severity'],row['severity']),row['count']) for row in analysis.get('severity',[])],visual,True))
    flow.append(Paragraph(visual['relationships'],styles['Heading2']))
    paragraph(visual['caution']);paragraph(visual['limits'])
    groups=analysis.get('relationships',[])[:6]
    flow.append(relationship_chart(groups,visual))
    for group in groups:
        paragraph(visual['shared'].format(**group))
        paragraph(labels[8]+': '+', '.join(group.get('evidence',[])))
    section(5)
    for f in evidence:
        paragraph(f"{f.get('source','')} | {f.get('bytes','')} bytes\nSHA-256: {f.get('sha256','')}")
    section(6)
    if not findings: paragraph(labels[14])
    for index,finding in enumerate(findings,1):
        paragraph(f"{index}. {finding.get('severity','')} | {finding.get('rule','')}\n{finding.get('description','')}")
        if finding.get('description_original') and finding['description_original']!=finding.get('description'):
            paragraph(labels[15]+': '+finding['description_original'])
        paragraph(labels[8]+': '+', '.join(map(str,finding.get('evidence',[]))))
    section(7)
    # Retain batch errors and validation metadata; never promote AI claims to facts.
    paragraph(data.get('ai_output_unverified','') or labels[13])
    output=io.BytesIO()
    def footer(canvas,doc):
        canvas.saveState()
        canvas.setFillColor(colors.HexColor('#087f8c'));canvas.rect(0,A4[1]-12,A4[0],12,fill=1,stroke=0)
        canvas.setFillColor(colors.HexColor('#193344'));canvas.setFont('ReportSans-Bold',13);canvas.drawString(42,A4[1]-39,'MAILSONAR')
        canvas.setFont('ReportSans',8);canvas.drawRightString(A4[0]-42,A4[1]-38,str(data.get('name',''))[:65])
        canvas.setStrokeColor(colors.HexColor('#b7c8d2'));canvas.line(42,A4[1]-51,A4[0]-42,A4[1]-51)
        canvas.setStrokeColor(colors.HexColor('#b7c8d2'));canvas.line(42,43,A4[0]-42,43)
        canvas.setFont('ReportSans',8);canvas.drawString(42,30,'MailSonar | '+labels[9]);canvas.drawRightString(A4[0]-42,30,str(doc.page));canvas.restoreState()
    SimpleDocTemplate(output,pagesize=A4,leftMargin=42,rightMargin=42,topMargin=76,bottomMargin=58,title='MailSonar | '+labels[0]).build(flow,onFirstPage=footer,onLaterPages=footer)
    return output.getvalue()

def main():
    raw=sys.stdin.buffer.read(LIMIT+1)
    if len(raw)>LIMIT: raise ValueError('Report exceeds 2 MiB limit')
    result=generate(json.loads(raw))
    if len(result)>8*1024*1024: raise ValueError('PDF exceeds 8 MiB limit')
    sys.stdout.buffer.write(result)
if __name__=='__main__': main()
