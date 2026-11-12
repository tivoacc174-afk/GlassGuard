package com.glassguard;
import java.lang.reflect.*;
import java.nio.file.*;
import java.util.*;
import java.util.zip.*;
import java.io.*;
public final class EngineTest {
 static int count=0;
 static void check(boolean v,String m){if(!v)throw new AssertionError(m);count++;}
 static Object call(String method,Class<?>[] types,Object... args)throws Exception{
  Class<?> c;
  try {c=Class.forName("com.glassguard.ScannerEngine");}catch(ClassNotFoundException e){throw new AssertionError("ScannerEngine feature is missing");}
  return c.getMethod(method,types).invoke(null,args);
 }
 static File apk(String name,String contents)throws Exception{
  File p=File.createTempFile("gg-test-",".apk");
  try(ZipOutputStream z=new ZipOutputStream(new FileOutputStream(p))){z.putNextEntry(new ZipEntry(name));z.write(contents.getBytes("UTF-8"));z.closeEntry();}return p;
 }
 public static void main(String[] args)throws Exception{
  String stage=args.length==0?"package":args[0];
  check("XCPE".equals(call("packageIndicator",new Class[]{String.class},"com.oemservice")),"exact XCPE package indicator");
  check("XCPE".equals(call("packageIndicator",new Class[]{String.class},"x.cpe")),"x.cpe alias");
  check("".equals(call("packageIndicator",new Class[]{String.class},"com.oemservice.backup")),"no substring false positive");
  check("".equals(call("packageIndicator",new Class[]{String.class},"com.android.systemui")),"normal system app not malware");
  check("".equals(call("packageIndicator",new Class[]{String.class},(Object)null)),"null safe");
  if(!stage.equals("package")){
   File good=apk("classes.dex","ordinary application");
   check(((List<?>)call("inspectApk",new Class[]{File.class,Map.class},good,Collections.emptyMap())).isEmpty(),"benign APK has no findings");
   File lib=apk("lib/arm64-v8a/libanl.so","benign library could share name");
   List<?> indicators=(List<?>)call("inspectApk",new Class[]{File.class,Map.class},lib,Collections.emptyMap());
   check(indicators.size()==1 && indicators.get(0).toString().startsWith("indicator|"),"lib name only is an indicator, not confirmed malware");
   File dex=apk("classes.dex","Lcom/hs/app; plus catmore88.com");
   check(!((List<?>)call("inspectApk",new Class[]{File.class,Map.class},dex,Collections.emptyMap())).isEmpty(),"BADBOX loader evidence recognized");
   File split=apk("classes.dex","a".repeat(65530)+"Lcom/hs/app;");
   check(!((List<?>)call("inspectApk",new Class[]{File.class,Map.class},split,Collections.emptyMap())).isEmpty(),"marker across read boundary");
   for(File f:Arrays.asList(good,lib,dex,split))f.delete();
  }
  if(stage.equals("hash")){
   File f=File.createTempFile("gg-hash-",".bin");Files.write(f.toPath(),"abc".getBytes("UTF-8"));
   String hash=(String)call("sha256",new Class[]{File.class},f);
   check(hash.equals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),"SHA256 standard vector");
   File a=apk("classes.dex","abc");
   Map<String,String> sigs=new HashMap<>();sigs.put(hash,"TEST-FIXTURE");
   List<?> findings=(List<?>)call("inspectApk",new Class[]{File.class,Map.class},a,sigs);
   check(findings.stream().anyMatch(x->x.toString().startsWith("match|TEST-FIXTURE|")),"embedded DEX hash matched fixture signature");
   sigs.clear();sigs.put((String)call("sha256",new Class[]{File.class},a),"TEST-APK-FIXTURE");
   check(((List<?>)call("inspectApk",new Class[]{File.class,Map.class},a,sigs)).stream().anyMatch(x->x.toString().startsWith("match|TEST-APK-FIXTURE|")),"whole APK hash match");
   a.delete();f.delete();
  }
  System.out.println("PASS: "+count+" assertions ("+stage+")");
 }
}
