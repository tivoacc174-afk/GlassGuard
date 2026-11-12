import pathlib,urllib.request
from html.parser import HTMLParser
p=pathlib.Path(__file__).parent/'research';p.mkdir(exist_ok=True)
u='https://cloud.google.com/blog/topics/threat-intelligence/shutting-the-door-on-the-xcpe-botnet'
r=urllib.request.urlopen(u,timeout=50).read();(p/'xcpe.html').write_bytes(r)
class T(HTMLParser):
    def __init__(self):super().__init__();self.text=[]
    def handle_data(self,d):
        if d.strip():self.text.append(d.strip())
a=T();a.feed(r.decode());t='\n'.join(a.text);(p/'xcpe.txt').write_text(t,encoding='utf-8');i=t.lower().find('indicators of compromise');print(t[i-600:i+19000] if i>=0 else t[-18000:])
