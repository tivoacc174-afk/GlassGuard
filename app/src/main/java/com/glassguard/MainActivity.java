package com.glassguard;

import android.app.*;
import android.os.*;
import android.content.*;
import android.content.pm.*;
import android.net.Uri;
import android.provider.Settings;
import android.webkit.*;
import android.view.*;
import android.widget.Toast;
import org.json.*;
import java.io.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

public final class MainActivity extends Activity {
 private WebView web;
 private final ExecutorService worker=Executors.newSingleThreadExecutor();
 private final AtomicBoolean scanning=new AtomicBoolean(false);
 private volatile String scanJson="{\"status\":\"idle\",\"scanned\":0,\"total\":0,\"findings\":[],\"limitations\":[]}";
 private volatile String appsJson="[]";
 private volatile String updateJson="{\"status\":\"idle\"}";
 private volatile JSONObject pendingRelease=null;
 private final AtomicBoolean updating=new AtomicBoolean(false);
 private static final String INSTALL_ACTION="com.glassguard.INSTALL_RESULT";
 private final BroadcastReceiver installReceiver=new BroadcastReceiver(){
  @Override public void onReceive(Context c,Intent i){onInstallResult(i);}
 };
 private volatile String message="Imbasan setempat. Tiada data dihantar ke internet.";
 private boolean pageReady=false;
 private static final String XCPE="https://cloud.google.com/blog/topics/threat-intelligence/shutting-the-door-on-the-xcpe-botnet";
 private static final String BB="https://www.humansecurity.com/learn/blog/satori-threat-intelligence-disruption-badbox-2-0/";
 private static final String HOME="https://appassets.androidplatform.net/index.html";
 @Override public void onCreate(Bundle b){
  super.onCreate(b);getWindow().setFlags(1024,1024);
  web=new WebView(this);setContentView(web);
  WebSettings s=web.getSettings();s.setJavaScriptEnabled(true);s.setDomStorageEnabled(true);
  s.setAllowFileAccess(false);s.setAllowContentAccess(false);s.setBlockNetworkLoads(true);
  s.setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW);
  web.setWebViewClient(new WebViewClient(){
   @Override public WebResourceResponse shouldInterceptRequest(WebView w,WebResourceRequest r){
    if(HOME.equals(r.getUrl().toString())){
     try{return new WebResourceResponse("text/html","UTF-8",getAssets().open("index.html"));}catch(IOException e){return blocked();}
    }return blocked();
   }
   @Override public boolean shouldOverrideUrlLoading(WebView w,WebResourceRequest r){return true;}
   @Override public boolean shouldOverrideUrlLoading(WebView w,String u){return true;}
   @Override public void onPageFinished(WebView w,String u){pageReady=true;publish();}
  });
  web.addJavascriptInterface(new Bridge(),"GlassGuard");
  try{File f=new File(getFilesDir(),"last-scan.json");if(f.exists()){
   String saved=readText(new FileInputStream(f));JSONObject j=new JSONObject(saved);
   if(!"running".equals(j.optString("status")))scanJson=j.toString();
  }}catch(Exception ignored){}
  web.loadUrl(HOME);loadApps();
  if(Build.VERSION.SDK_INT>=33)registerReceiver(installReceiver,new IntentFilter(INSTALL_ACTION),Context.RECEIVER_NOT_EXPORTED);
  else registerReceiver(installReceiver,new IntentFilter(INSTALL_ACTION));
 }
 private WebResourceResponse blocked(){return new WebResourceResponse("text/plain","UTF-8",403,"Blocked",Collections.emptyMap(),new ByteArrayInputStream(new byte[0]));}
 private String readText(InputStream in)throws IOException{
  try(InputStream i=in;ByteArrayOutputStream out=new ByteArrayOutputStream()){
   byte[] b=new byte[8192];int n;while((n=i.read(b))!=-1){if(out.size()+n>4*1024*1024)throw new IOException("Report exceeds limit");out.write(b,0,n);}return out.toString("UTF-8");
  }
 }
 private void publish(){runOnUiThread(()->{
  if(!pageReady||isFinishing())return;
  try{
   ActivityManager.MemoryInfo m=new ActivityManager.MemoryInfo();((ActivityManager)getSystemService(ACTIVITY_SERVICE)).getMemoryInfo(m);
   JSONObject state=new JSONObject().put("device",new JSONObject().put("model",Build.MANUFACTURER+" "+Build.MODEL).put("android",Build.VERSION.RELEASE).put("sdk",Build.VERSION.SDK_INT));
   state.put("memory",new JSONObject().put("total",m.totalMem).put("available",m.availMem).put("lowMemory",m.lowMemory));
   state.put("scan",new JSONObject(scanJson));state.put("apps",new JSONArray(appsJson));state.put("update",new JSONObject(updateJson));state.put("message",message);
   web.evaluateJavascript("window.renderState&&window.renderState("+state.toString()+");",null);
  }catch(Exception e){Toast.makeText(this,"Paparan gagal: "+e.getClass().getSimpleName(),Toast.LENGTH_LONG).show();}
 });}
 private void note(String s){message=s;publish();}
 private boolean isSystem(ApplicationInfo a){return (a.flags&(ApplicationInfo.FLAG_SYSTEM|ApplicationInfo.FLAG_UPDATED_SYSTEM_APP))!=0;}
 private ApplicationInfo validate(String p)throws Exception{
  if(p==null||!p.matches("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z0-9_]+)+")||p.equals(getPackageName()))throw new IllegalArgumentException("Pakej tidak dibenarkan");
  return getPackageManager().getApplicationInfo(p,PackageManager.MATCH_DISABLED_COMPONENTS);
 }
 private void loadApps(){worker.execute(()->{
  try{List<ApplicationInfo> list=getPackageManager().getInstalledApplications(PackageManager.MATCH_DISABLED_COMPONENTS);
   Collections.sort(list,(a,b)->getPackageManager().getApplicationLabel(a).toString().compareToIgnoreCase(getPackageManager().getApplicationLabel(b).toString()));
   JSONArray a=new JSONArray();for(ApplicationInfo i:list){if(i.packageName.equals(getPackageName()))continue;
    a.put(new JSONObject().put("packageName",i.packageName).put("label",getPackageManager().getApplicationLabel(i)).put("system",isSystem(i)).put("enabled",i.enabled));
   }appsJson=a.toString();publish();
  }catch(Exception e){note("Senarai aplikasi tidak dapat dibaca: "+e.getClass().getSimpleName());}
 });}
 private JSONObject finding(String id,String level,String title,String detail,String pkg,boolean system,String evidence,String source)throws JSONException{
  return new JSONObject().put("id",id).put("severity",level).put("title",title).put("detail",detail).put("packageName",pkg).put("system",system).put("evidence",evidence).put("source",source);
 }
 private void checkpoint(String status,int done,int total,JSONArray findings,JSONArray limits,long started)throws JSONException{
  scanJson=new JSONObject().put("status",status).put("scanned",done).put("total",total).put("timestamp",System.currentTimeMillis()).put("started",started).put("findings",findings).put("limitations",limits).toString();publish();
 }
 private void startScan(){
  if(!scanning.compareAndSet(false,true)){note("Imbasan sedang berjalan.");return;}
  worker.execute(()->{
   JSONArray found=new JSONArray(),limits=new JSONArray();int done=0,total=0;long started=System.currentTimeMillis();
   try{
    Map<String,String> signatures=new HashMap<>();
    try(BufferedReader r=new BufferedReader(new InputStreamReader(getAssets().open("signatures.tsv"),"UTF-8"))){
     String line;while((line=r.readLine())!=null){String[] v=line.split("\t",2);if(v.length==2&&v[0].matches("[0-9a-f]{64}"))signatures.put(v[0],v[1]);}
    }
    limits.put(signatures.size()+" tandatangan SHA-256 daripada GTIG; bukan pangkalan data semua malware. BADBOX: indikator library/class sahaja.");
    limits.put("Aplikasi sandbox tidak boleh mengesahkan keseluruhan firmware, root tersembunyi, trafik rangkaian atau /data aplikasi lain. Root tidak semestinya malware.");
    limits.put("Fail APK/DEX/library yang boleh dibaca sahaja; had 64 MiB setiap entri dan 256 MiB setiap APK. Tiada ujian exploit atau akses root diminta.");
    List<ApplicationInfo> list=getPackageManager().getInstalledApplications(PackageManager.MATCH_DISABLED_COMPONENTS);total=list.size();
    checkpoint("running",0,total,found,limits,started);
    for(ApplicationInfo a:list){
     if(Thread.currentThread().isInterrupted())throw new InterruptedException();
     String family=ScannerEngine.packageIndicator(a.packageName);
     if(!family.isEmpty()){
      String evidence=a.packageName+"\n"+a.sourceDir+"\nUID: "+a.uid;
      try{evidence+="\nAPK SHA-256: "+ScannerEngine.sha256(new File(a.sourceDir));}catch(Exception e){evidence+="\nHash tidak dapat dibaca";}
      found.put(finding(a.packageName+":package","high",family+" — indikator pakej", "Nama pakej sepadan laporan GTIG. Semak bukti hash; nama sahaja bukan pengesahan. Status: "+(a.enabled?"aktif":"dinyahaktifkan"),a.packageName,isSystem(a),evidence,XCPE));
     }
     List<String> paths=new ArrayList<>();if(a.sourceDir!=null)paths.add(a.sourceDir);
     if(a.splitSourceDirs!=null)paths.addAll(Arrays.asList(a.splitSourceDirs));
     if(!a.packageName.equals(getPackageName()))for(String path:paths){
      try{
       List<String> results=ScannerEngine.inspectApk(new File(path),signatures);
       for(String hit:results){String[] parts=hit.split("\\|",3);boolean match="match".equals(parts[0]);
        found.put(finding(a.packageName+":"+found.length(),match?"critical":"medium",parts[1]+(match?" — hash sepadan":" — petunjuk"),match?"Kandungan fail sepadan SHA-256 terbitan GTIG. Jangan anggap uninstall membuang salinan firmware.":"Petunjuk heuristik, bukan pengesahan malware. Library/class yang sama boleh mempunyai kegunaan sah.",a.packageName,isSystem(a),path+"\n"+parts[2],match?XCPE:BB));
       }
      }catch(Exception e){limits.put(a.packageName+": imbasan separa/tidak boleh baca "+path+" ("+e.getClass().getSimpleName()+")");}
     }
     done++;checkpoint("running",done,total,found,limits,started);
    }
    for(String p:new String[]{"/system/bin/su","/system/xbin/su","/sbin/su","/sbin/.magisk","/data/adb/magisk"}){
     if(new File(p).exists())found.put(finding("root:"+p,"medium","Petunjuk root ditemui","Root boleh dipasang secara sah. Ini BUKAN pengesahan root backdoor; tiada akses root dicuba.","",true,p,"Pemeriksaan kewujudan fail setempat"));
    }
    for(String p:new String[]{"/system/lib/libanl.so","/system/lib64/libanl.so","/vendor/lib/libanl.so","/vendor/lib64/libanl.so"}){
     if(new File(p).exists())found.put(finding("bb:"+p,"medium","BADBOX — nama library firmware","Nama libanl.so sahaja tidak membuktikan jangkitan. Perlu analisis firmware/hashing bebas.","",true,p,BB));
    }
    checkpoint("complete",done,total,found,limits,started);
    try(FileOutputStream out=openFileOutput("last-scan.json",MODE_PRIVATE)){out.write(scanJson.getBytes("UTF-8"));}
    note("Imbasan selesai. Tiada indikator bukan jaminan bebas malware. Laporan disimpan pada peranti.");
   }catch(Exception e){
    try{limits.put("Imbasan tidak lengkap: "+e.getClass().getSimpleName());checkpoint("error",done,total,found,limits,started);}catch(Exception ignored){}
    note("Imbasan tidak lengkap. Lihat batasan laporan.");
   }finally{scanning.set(false);}
  });
 }
 private void openSettings(String pkg){try{ApplicationInfo a=validate(pkg);startActivity(new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS,Uri.parse("package:"+a.packageName)));}catch(Exception e){note("Tetapan aplikasi tidak tersedia: "+e.getClass().getSimpleName());}}
 private void removeApp(String pkg){
  try{ApplicationInfo a=validate(pkg);if(isSystem(a)){note("Pakej sistem: gunakan tetapan untuk nyahaktif jika dibenarkan. Firmware mungkin perlu diganti.");openSettings(pkg);return;}
   new AlertDialog.Builder(this).setTitle("Hapus "+getPackageManager().getApplicationLabel(a)+"?")
    .setMessage("Android akan meminta pengesahan akhir. Data aplikasi mungkin hilang. Ini tidak membaiki firmware.")
    .setNegativeButton("Batal",null).setPositiveButton("Teruskan",(d,w)->{try{startActivity(new Intent(Intent.ACTION_DELETE,Uri.parse("package:"+pkg)));}catch(Exception e){note("Uninstall tidak tersedia; gunakan tetapan.");openSettings(pkg);}}).show();
  }catch(Exception e){note("Pakej tidak sah/tidak tersedia.");}
 }
 private void memoryTools(){
  String info="Android mengurus RAM cache secara automatik. RAM kosong bukan sasaran. Tiada jaminan 1 GB dapat dibebaskan. Menutup aplikasi boleh menghentikan notifikasi sehingga dibuka semula.";
  if(Build.VERSION.SDK_INT>=34){new AlertDialog.Builder(this).setTitle("Pengurusan RAM").setMessage(info+" Android 14+ menghadkan penutupan aplikasi lain; pilih aplikasi dalam tetapan jika perlu.").setNegativeButton("Batal",null).setPositiveButton("Tetapan aplikasi",(d,w)->{try{startActivity(new Intent(Settings.ACTION_MANAGE_APPLICATIONS_SETTINGS));}catch(Exception e){note("Buka Tetapan > Aplikasi secara manual.");}}).show();return;}
  new AlertDialog.Builder(this).setTitle("Pengurusan RAM selamat").setMessage(info).setNegativeButton("Batal",null).setPositiveButton("Pilih aplikasi",(d,w)->chooseBackground()).show();
 }
 private void chooseBackground(){
  try{
   Set<String> protectedPackages=new HashSet<>();protectedPackages.add(getPackageName());
   Intent home=new Intent(Intent.ACTION_MAIN);home.addCategory(Intent.CATEGORY_HOME);
   for(ResolveInfo r:getPackageManager().queryIntentActivities(home,0))protectedPackages.add(r.activityInfo.packageName);
   String input=Settings.Secure.getString(getContentResolver(),Settings.Secure.DEFAULT_INPUT_METHOD);
   if(input!=null)protectedPackages.add(input.split("/")[0]);
   String accessibility=Settings.Secure.getString(getContentResolver(),Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES);
   if(accessibility!=null)for(String c:accessibility.split(":"))protectedPackages.add(c.split("/")[0]);
   List<ApplicationInfo> candidates=new ArrayList<>();for(ApplicationInfo a:getPackageManager().getInstalledApplications(0))if(!isSystem(a)&&a.enabled&&!protectedPackages.contains(a.packageName))candidates.add(a);
   if(candidates.isEmpty()){note("Tiada aplikasi pengguna yang sesuai dipilih. Proses sistem tidak disentuh.");return;}
   String[] labels=new String[candidates.size()];boolean[] selected=new boolean[candidates.size()];for(int i=0;i<labels.length;i++)labels[i]=getPackageManager().getApplicationLabel(candidates.get(i))+"\n"+candidates.get(i).packageName;
   new AlertDialog.Builder(this).setTitle("Tutup latar belakang — pilih sendiri").setMultiChoiceItems(labels,selected,(d,i,v)->selected[i]=v).setNegativeButton("Batal",null).setPositiveButton("Tutup yang dipilih",(d,w)->{
    ActivityManager am=(ActivityManager)getSystemService(ACTIVITY_SERVICE);int requested=0;
    for(int i=0;i<selected.length;i++)if(selected[i]){try{am.killBackgroundProcesses(candidates.get(i).packageName);requested++;}catch(SecurityException ignored){}}
    note("Permintaan menutup latar belakang: "+requested+" aplikasi. Kejayaan bergantung Android; bacaan RAM ialah keadaan semasa, bukan jumlah dijimatkan.");
    web.postDelayed(()->publish(),1200);
   }).show();
  }catch(Exception e){note("Pengurusan RAM tidak tersedia. Gunakan Tetapan aplikasi.");}
 }
 private void setUpdating(String status,String detail)throws JSONException{
  JSONObject u=new JSONObject().put("status",status);
  if(pendingRelease!=null){
   u.put("latest",pendingRelease.optString("versionName",""));
   u.put("versionCode",pendingRelease.optLong("versionCode",0));
   u.put("size",pendingRelease.optLong("size",0));
  }
  if(detail!=null&&!detail.isEmpty())u.put("detail",detail);
  updateJson=u.toString();publish();
 }
 private void checkForUpdate(){
  if(!updating.compareAndSet(false,true)){note("Semakan kemas kini sedang berjalan.");return;}
  try{setUpdating("checking",null);}catch(Exception ignored){}
  worker.execute(()->{
   try{
    JSONObject release=Updater.latest();
    long code=release.optLong("versionCode",-1);
    pendingRelease=release;
    if(UpdatePolicy.isNewer(code,currentVersionCode()))setUpdating("available",null);
    else setUpdating("current",null);
   }catch(Exception e){
    pendingRelease=null;
    try{setUpdating("error",e.getMessage()==null?e.getClass().getSimpleName():e.getMessage());}catch(Exception ignored){}
   }finally{updating.set(false);}
  });
 }
 private int currentVersionCode(){
  try{return Updater.versionCode(getPackageManager().getPackageInfo(getPackageName(),0));}
  catch(Exception e){return -1;}
 }
 private void installUpdate(){
  JSONObject release=pendingRelease;
  if(release==null){note("Tiada keluaran yang disahkan. Tekan Check for update dahulu.");return;}
  if(!updating.compareAndSet(false,true)){note("Muat turun sedang berjalan.");return;}
  final String url=release.optString("url","");
  final long announced=release.optLong("versionCode",-1);
  final String expected=release.optString("sha256","");
  setUpdatingAsync("checking",null);
  worker.execute(()->{
   final File temp=new File(getCacheDir(),"update.apk");
   boolean keep=false;
   try{
    if(temp.exists()&&!temp.delete())throw new IOException("Fail lama tidak dapat diganti");
    String actual=Updater.download(url,temp);
    if(!UpdatePolicy.isSha256(expected))throw new IOException("Keluaran tiada digest SHA-256; pasang dibatalkan");
    if(!expected.equals(actual))throw new IOException("Hash APK tidak sepadan; pasang dibatalkan");
    if(!Updater.verify(MainActivity.this,temp,announced))throw new IOException("Pakej atau tandatangan tidak sepadan; pasang dibatalkan");
    keep=true;
    runOnUiThread(()->confirmInstall(temp,announced));
   }catch(Exception e){
    pendingRelease=null;
    try{setUpdating("error",e.getMessage()==null?e.getClass().getSimpleName():e.getMessage());}catch(Exception ignored){}
   }finally{
    if(!keep)temp.delete();
    updating.set(false);
   }
  });
 }
 private void setUpdatingAsync(String status,String detail){
  runOnUiThread(()->{try{setUpdating(status,detail);}catch(Exception ignored){}});
 }
 private void confirmInstall(final File apk,final long announced){
  new AlertDialog.Builder(this).setTitle("Pasang kemas kini?")
   .setMessage("APK "+apk.length()+" bait telah disemak: pakej dan tandatangan sepadan. Android akan meminta pengesahan akhir. Data aplikasi kekal.")
   .setNegativeButton("Batal",(d,w)->apk.delete())
   .setPositiveButton("Pasang",(d,w)->{
    try{
     Intent result=new Intent(INSTALL_ACTION).setPackage(getPackageName());
     int flags=PendingIntent.FLAG_UPDATE_CURRENT|(Build.VERSION.SDK_INT>=23?PendingIntent.FLAG_IMMUTABLE:0);
     PendingIntent pending=PendingIntent.getBroadcast(this,1,result,flags);
     Updater.install(this,apk,pending);
    }catch(Exception e){apk.delete();note("Pemasangan tidak dapat dimulakan: "+(e.getMessage()==null?e.getClass().getSimpleName():e.getMessage()));}
   }).show();
 }
 private void onInstallResult(Intent intent){
  int status=intent.getIntExtra(PackageInstaller.EXTRA_STATUS,PackageInstaller.STATUS_FAILURE);
  String detail=intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE);
  if(status==PackageInstaller.STATUS_PENDING_USER_ACTION){
   // Android needs the user's own confirmation before it will replace the app.
   Intent confirm=intent.getParcelableExtra(Intent.EXTRA_INTENT);
   if(confirm!=null){try{startActivity(confirm);}catch(Exception e){note("Pengesahan pemasangan tidak dapat dibuka.");}}
   else note("Pengesahan pemasangan diperlukan tetapi tidak tersedia.");
   return;
  }
  new File(getCacheDir(),"update.apk").delete();
  if(status==PackageInstaller.STATUS_SUCCESS){pendingRelease=null;note("Kemas kini dipasang. Buka semula GlassGuard untuk versi baharu.");}
  else{pendingRelease=null;note("Pemasangan tidak selesai"+(detail==null?".":": "+detail));}
 }
 public final class Bridge {
  @JavascriptInterface public void refresh(){publish();}
  @JavascriptInterface public void scan(){startScan();}
  @JavascriptInterface public void apps(){loadApps();}
  @JavascriptInterface public void checkForUpdate(){runOnUiThread(MainActivity.this::checkForUpdate);}
  @JavascriptInterface public void installUpdate(){runOnUiThread(MainActivity.this::installUpdate);}
  @JavascriptInterface public void openApp(String p){runOnUiThread(()->openSettings(p));}
  @JavascriptInterface public void uninstall(String p){runOnUiThread(()->removeApp(p));}
  @JavascriptInterface public void optimize(){runOnUiThread(()->memoryTools());}
  @JavascriptInterface public void exportReport(){runOnUiThread(()->{
   try{JSONObject report=new JSONObject(scanJson);report.put("device",Build.MANUFACTURER+" "+Build.MODEL);report.put("source",XCPE);
    Intent share=new Intent(Intent.ACTION_SEND);share.setType("text/plain");share.putExtra(Intent.EXTRA_SUBJECT,"GlassGuard — laporan indikator");share.putExtra(Intent.EXTRA_TEXT,report.toString(2));
    startActivity(Intent.createChooser(share,"Kongsi laporan (mengandungi senarai pakej & laluan fail)"));
   }catch(Exception e){note("Tiada aplikasi untuk berkongsi laporan. Laporan kekal dalam storan aplikasi.");}
  });}
 }
 @Override protected void onResume(){super.onResume();if(web!=null){publish();loadApps();}}
 @Override public void onBackPressed(){new AlertDialog.Builder(this).setTitle("Tutup GlassGuard?").setMessage(scanning.get()?"Imbasan sedang berjalan; keluar akan menghentikan imbasan.":"Laporan terakhir disimpan pada peranti.").setNegativeButton("Kembali",null).setPositiveButton("Tutup",(d,w)->finish()).show();}
 @Override protected void onDestroy(){try{unregisterReceiver(installReceiver);}catch(Exception ignored){}worker.shutdownNow();if(web!=null){web.removeJavascriptInterface("GlassGuard");web.destroy();}super.onDestroy();}
}
