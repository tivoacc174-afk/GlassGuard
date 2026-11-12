from pathlib import Path
import os,subprocess,zipfile,secrets,json,hashlib
ROOT=Path(__file__).resolve().parent
TOOLS=ROOT/'tools'; BUILD=ROOT/'build';BUILD.mkdir(exist_ok=True)
JDK=next((TOOLS/'jdk').glob('*/bin'))
BT=next((TOOLS/'build-tools').glob('*/aapt2.exe')).parent
ANDROID=next((TOOLS/'platform').glob('*/android.jar'))
ENV=dict(os.environ,JAVA_HOME=str(JDK.parent));ENV['PATH']=str(JDK)+os.pathsep+ENV.get('PATH','')
def run(args):
 print('RUN',str(args[0]),flush=True)
 subprocess.run([str(a) for a in args],check=True,env=ENV,cwd=ROOT)
def assets():
 from PIL import Image,ImageDraw,ImageFont
 res=ROOT/'app/src/main/res/drawable';res.mkdir(parents=True,exist_ok=True)
 for name,size in [('icon',(192,192)),('banner',(320,180))]:
  im=Image.new('RGB',size,'#dfece8');d=ImageDraw.Draw(im)
  x,y=size[0]//2,size[1]//2
  d.rounded_rectangle((x-65,y-65,x+65,y+65),radius=32,fill='#f1faf6',outline='#b7d7cf',width=2)
  d.polygon([(x,y-42),(x+32,y-27),(x+28,y+14),(x,y+41),(x-28,y+14),(x-32,y-27)],fill='#147c6b')
  d.line([(x-15,y),(x-3,y+13),(x+19,y-14)],fill='white',width=7)
  im.save(res/(name+'.png'))
assets()
run([JDK/'javac.exe','-encoding','UTF-8','-d',BUILD/'test-classes',ROOT/'tests/EngineTest.java',ROOT/'app/src/main/java/com/glassguard/ScannerEngine.java'])
run([JDK/'java.exe','-cp',BUILD/'test-classes','com.glassguard.EngineTest','hash'])
run([JDK/'javac.exe','-encoding','UTF-8','-d',BUILD/'test-classes',ROOT/'tests/UpdatePolicyTest.java',ROOT/'app/src/main/java/com/glassguard/UpdatePolicy.java'])
for stage in ['version','urls','identity','tag']:run([JDK/'java.exe','-cp',BUILD/'test-classes','com.glassguard.UpdatePolicyTest',stage])
run(['node',ROOT/'ui-tests.cjs'])
run(['python',ROOT/'tests/test_native_contract.py'])
run(['python',ROOT/'build_signatures.py'])
resources=ROOT/'app/src/main/res'
run([BT/'aapt2.exe','compile','--dir',resources,'-o',BUILD/'resources.zip'])
unsigned=BUILD/'unsigned.apk'
run([BT/'aapt2.exe','link','-o',unsigned,'--manifest',ROOT/'app/src/main/AndroidManifest.xml','-I',ANDROID,'-A',ROOT/'app/src/main/assets','-R',BUILD/'resources.zip','--auto-add-overlay'])
sources=list((ROOT/'app/src/main/java').rglob('*.java'))
classes=BUILD/'classes';classes.mkdir(exist_ok=True)
run([JDK/'javac.exe','-encoding','UTF-8','--release','8','-classpath',ANDROID,'-d',classes,*sources])
jar=BUILD/'classes.jar';run([JDK/'jar.exe','cf',jar,'-C',classes,'.'])
dex=BUILD/'dex';dex.mkdir(exist_ok=True)
run([JDK/'java.exe','-cp',BT/'lib/d8.jar','com.android.tools.r8.D8','--min-api','23','--lib',ANDROID,'--output',dex,jar])
with zipfile.ZipFile(unsigned,'a',zipfile.ZIP_DEFLATED) as z:
 for p in dex.glob('*.dex'):z.write(p,p.name)
aligned=BUILD/'aligned.apk';run([BT/'zipalign.exe','-f','4',unsigned,aligned])
keydir=ROOT/'signing';keydir.mkdir(exist_ok=True);password=keydir/'password.txt';key=keydir/'glassguard.jks'
if not password.exists():password.write_text(secrets.token_urlsafe(32),encoding='utf-8')
ENV['GG_KEYPASS']=password.read_text(encoding='utf-8').strip()
if not key.exists():run([JDK/'keytool.exe','-genkeypair','-keystore',key,'-storepass:env','GG_KEYPASS','-keypass:env','GG_KEYPASS','-alias','glassguard','-keyalg','RSA','-keysize','3072','-validity','3650','-dname','CN=GlassGuard Local Build','-storetype','JKS'])
out=ROOT/'dist/GlassGuard-1.1.0.apk';out.parent.mkdir(exist_ok=True)
run([JDK/'java.exe','-jar',BT/'lib/apksigner.jar','sign','--ks',key,'--ks-key-alias','glassguard','--ks-pass','env:GG_KEYPASS','--key-pass','env:GG_KEYPASS','--out',out,aligned])
run([JDK/'java.exe','-jar',BT/'lib/apksigner.jar','verify','--verbose',out])
run([BT/'aapt2.exe','dump','badging',out])
print(json.dumps({'apk':str(out),'bytes':out.stat().st_size,'sha256':hashlib.sha256(out.read_bytes()).hexdigest()},indent=2))
