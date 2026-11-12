from pathlib import Path
import subprocess,json,re,sys,time
root=Path(__file__).parent;out=root/'verification';out.mkdir(exist_ok=True)
adb=str(root/'tools/platform-tools/adb.exe');device='192.168.0.99:5555'
def shell(cmd):
 return subprocess.run([adb,'-s',device,'shell',cmd],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=40).stdout
name=sys.argv[1] if len(sys.argv)>1 else 'initial'
time.sleep(1)
png=subprocess.run([adb,'-s',device,'exec-out','screencap','-p'],capture_output=True,check=True,timeout=30).stdout
p=out/(name+'.png');p.write_bytes(png)
shell('uiautomator dump /sdcard/glassguard-ui.xml')
xml=shell('cat /sdcard/glassguard-ui.xml');(out/(name+'.xml')).write_text(xml,encoding='utf-8')
print('Screenshot:',p)
import xml.etree.ElementTree as ET
try:
 tree=ET.fromstring(xml[xml.find('<?xml'):]);nodes=[dict(n.attrib) for n in tree.iter('node') if n.attrib.get('text') or n.attrib.get('content-desc')]
 (out/(name+'.json')).write_text(json.dumps(nodes,ensure_ascii=False,indent=2),encoding='utf-8')
 print(json.dumps([{'id':n.get('resource-id'),'text':n.get('text') or n.get('content-desc'),'bounds':n.get('bounds'),'focused':n.get('focused')} for n in nodes if n.get('resource-id') or n.get('focused')=='true' or any(x in n.get('text','') for x in ['XCPE','SHA-256','indikator','separa','HAPUS','UNINSTALL','PADAM'])],ensure_ascii=False,indent=2))
except Exception as e:print(xml[:500],str(e))
logs=shell('logcat -d -t 300');(out/(name+'-logcat.txt')).write_text(logs,encoding='utf-8')
print('Relevant errors:', '\n'.join(l for l in logs.splitlines() if any(t in l for t in ['FATAL EXCEPTION','net::ERR','Uncaught',' E chromium',' E AndroidRuntime'])))
