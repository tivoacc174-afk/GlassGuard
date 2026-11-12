from pathlib import Path
import os,subprocess
r=Path(__file__).parent;t=r/'tools';b=r/'verification/fixture';b.mkdir(parents=True,exist_ok=True)
j=next((t/'jdk').glob('*/bin'));bt=next((t/'build-tools').glob('*/aapt2.exe')).parent;android=next((t/'platform').glob('*/android.jar'))
e=dict(os.environ,JAVA_HOME=str(j.parent),GG_KEYPASS=(r/'signing/password.txt').read_text().strip());e['PATH']=str(j)+os.pathsep+e['PATH']
def run(a):subprocess.run([str(v) for v in a],check=True,env=e)
manifest=b/'AndroidManifest.xml';manifest.write_text('<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.glassguard.fixture" android:versionCode="1" android:versionName="test"><uses-sdk android:minSdkVersion="23" android:targetSdkVersion="35"/><application android:label="GlassGuard Test Fixture" android:hasCode="false" android:allowBackup="false"/></manifest>',encoding='utf-8')
run([bt/'aapt2.exe','link','-o',b/'unsigned.apk','--manifest',manifest,'-I',android])
run([bt/'zipalign.exe','-f','4',b/'unsigned.apk',b/'aligned.apk'])
run([j/'java.exe','-jar',bt/'lib/apksigner.jar','sign','--ks',r/'signing/glassguard.jks','--ks-key-alias','glassguard','--ks-pass','env:GG_KEYPASS','--key-pass','env:GG_KEYPASS','--out',b/'fixture.apk',b/'aligned.apk'])
run([t/'platform-tools/adb.exe','-s','192.168.0.99:5555','install','-r',b/'fixture.apk'])
print('Installed harmless no-code, no-permission uninstall fixture: com.glassguard.fixture')
