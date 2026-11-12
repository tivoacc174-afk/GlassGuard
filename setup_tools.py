import concurrent.futures, pathlib, urllib.request, zipfile, xml.etree.ElementTree as ET
ROOT=pathlib.Path(__file__).parent/'tools'
ROOT.mkdir(exist_ok=True)
def fetch(url,path):
    req=urllib.request.Request(url,headers={'User-Agent':'Mozilla/5.0'})
    with urllib.request.urlopen(req, timeout=90) as r, open(path,'wb') as f:
        while b:=r.read(1024*1024): f.write(b)
    return path
def sdk():
    xml=fetch('https://dl.google.com/android/repository/repository2-1.xml',ROOT/'repository.xml')
    tree=ET.parse(xml)
    for wanted in ['build-tools;35.0.0','platforms;android-35']:
        pkg=next(p for p in tree.getroot() if p.tag.endswith('remotePackage') and p.attrib.get('path')==wanted)
        candidates=pkg.findall('.//archive')
        arc=next(a for a in candidates if a.findtext('host-os') in ('windows',None))
        url=arc.findtext('complete/url')
        z=fetch('https://dl.google.com/android/repository/'+url,ROOT/pathlib.Path(url).name)
        out=ROOT/('build-tools' if wanted.startswith('build') else 'platform')
        with zipfile.ZipFile(z) as f:f.extractall(out)
        print('Extracted',wanted,flush=True)
def jdk():
    urls=['https://aka.ms/download-jdk/microsoft-jdk-17.0.17-windows-x64.zip','https://cdn.azul.com/zulu/bin/zulu17.62.17-ca-jdk17.0.17-win_x64.zip']
    for url in urls:
        try:
            z=fetch(url,ROOT/'jdk.zip')
            with zipfile.ZipFile(z) as f:f.extractall(ROOT/'jdk')
            print('Extracted JDK',flush=True);return
        except Exception as e:print('JDK alternative:',str(e),flush=True)
    raise RuntimeError('No JDK download succeeded')
with concurrent.futures.ThreadPoolExecutor(2) as ex:
    list(ex.map(lambda f:f(),[sdk,jdk]))
