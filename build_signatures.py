from html.parser import HTMLParser
from pathlib import Path
import re,json
root=Path(__file__).parent
class Tables(HTMLParser):
 def __init__(self):super().__init__();self.tables=[];self.table=None;self.row=None;self.cell=None
 def handle_starttag(self,t,a):
  if t=='table':self.table=[]
  elif t=='tr':self.row=[]
  elif t in ('td','th'):self.cell=[]
 def handle_data(self,d):
  if self.cell is not None:self.cell.append(d)
 def handle_endtag(self,t):
  if t in ('td','th') and self.cell is not None:
   if self.row is not None:self.row.append(' '.join(' '.join(self.cell).split()))
   self.cell=None
  elif t=='tr' and self.row is not None:
   if self.table is not None:self.table.append(self.row)
   self.row=None
  elif t=='table' and self.table is not None:self.tables.append(self.table);self.table=None
p=Tables();p.feed((root/'research/xcpe.html').read_text(encoding='utf-8'))
sigs={};source='https://cloud.google.com/blog/topics/threat-intelligence/shutting-the-door-on-the-xcpe-botnet'
for table in p.tables:
 if not table or 'Representative SHA256' not in ' '.join(table[0]):continue
 for row in table[1:]:
  hashes=[v for cell in row for v in re.findall(r'(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])',cell)]
  family=(row[0] if row else '') or 'XCPE-associated dropper/component'
  for h in hashes:
   labels=sigs.get(h,[])
   if family not in labels:labels.append(family)
   sigs[h]=labels
sigs={h:' / '.join(labels) for h,labels in sigs.items()}
assert len(sigs)>40, len(sigs)
a=root/'app/src/main/assets';a.mkdir(parents=True,exist_ok=True)
(a/'signatures.tsv').write_text(''.join(h+'\t'+family+'\n' for h,family in sorted(sigs.items())),encoding='utf-8')
(a/'sources.json').write_text(json.dumps({'signatureSource':source,'signatureCount':len(sigs),'badboxIndicators':'https://www.humansecurity.com/learn/blog/satori-threat-intelligence-disruption-badbox-2-0/','note':'Library/class names are heuristic indicators only, not confirmed malware; no all-malware coverage.'},indent=2),encoding='utf-8')
print(json.dumps({'verified_sha256_signatures':len(sigs),'families':sorted(set(sigs.values()))}))
