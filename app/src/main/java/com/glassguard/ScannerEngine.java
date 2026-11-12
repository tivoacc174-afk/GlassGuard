package com.glassguard;
import java.io.*;
import java.util.*;
import java.util.zip.*;
import java.security.*;
public final class ScannerEngine {
 public static String sha256(File file)throws Exception{
  try(InputStream in=new FileInputStream(file)){
   MessageDigest md=MessageDigest.getInstance("SHA-256");byte[] b=new byte[65536];int k;
   while((k=in.read(b))!=-1)md.update(b,0,k);
   return hex(md.digest());
  }
 }
 private static String hex(byte[] digest){StringBuilder b=new StringBuilder();for(byte v:digest)b.append(String.format(java.util.Locale.ROOT,"%02x",v&255));return b.toString();}
 public static List<String> inspectApk(File file,Map<String,String> signatures)throws Exception{
  List<String> out=new ArrayList<>();
  String whole=sha256(file);if(signatures.containsKey(whole))out.add("match|"+signatures.get(whole)+"|APK SHA-256: "+whole);
  try(ZipFile zip=new ZipFile(file)){
   Enumeration<? extends ZipEntry> entries=zip.entries();long total=0;
   while(entries.hasMoreElements()){
    ZipEntry e=entries.nextElement();String n=e.getName();
    if(n.endsWith("/libanl.so"))out.add("indicator|BADBOX 2.0|"+n+" (nama library sahaja; bukan pengesahan)");
    if(!(n.endsWith(".dex")||n.endsWith(".so")))continue;
    try(InputStream in=zip.getInputStream(e)){
     MessageDigest md=MessageDigest.getInstance("SHA-256");
     byte[] b=new byte[65536];int k;String tail="";boolean found=false;long size=0;
     while((k=in.read(b))!=-1){
      md.update(b,0,k);
      size+=k;total+=k;if(size>64L*1024*1024||total>256L*1024*1024)throw new IOException("Had bacaan APK dilampaui; imbasan separa");
      String s=tail+new String(b,0,k,"ISO-8859-1");
      if(!found&&s.contains("Lcom/hs/app;")){out.add("indicator|BADBOX 2.0|"+n+": Lcom/hs/app; (loader marker; perlu pengesahan)");found=true;}
      tail=s.substring(Math.max(0,s.length()-64));
     }
     String hash=hex(md.digest());if(signatures.containsKey(hash))out.add("match|"+signatures.get(hash)+"|"+n+" SHA-256: "+hash);
    }
   }
  }
  return out;
 }

 public static String packageIndicator(String p){
  if("x.cpe".equals(p)||"com.oemservice".equals(p))return "XCPE";
  if("com.abc.nexus".equals(p)||"com.vs.grass".equals(p))return "ABCNexus";
  if("com.android.sso.auth.handler".equals(p))return "AppSalt dropper";
  return "";
 }
}
