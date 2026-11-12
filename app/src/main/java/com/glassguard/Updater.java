package com.glassguard;

import android.app.PendingIntent;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageInstaller;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Build;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;
import java.util.Locale;

/**
 * Self-update support: read the latest GitHub release, download exactly one asset,
 * verify app identity and signature, then hand the file to Android's PackageInstaller.
 * Every URL decision is delegated to {@link UpdatePolicy} so the rules stay testable.
 */
final class Updater {
 static final long MAX_DOWNLOAD=64L*1024*1024;
 private static final int MAX_REDIRECTS=5;
 private static final int MAX_METADATA=1024*1024;
 private static final String UA="GlassGuard-Updater";

 private Updater(){}

 /** Reads the latest published release and returns the single asset this app would accept. */
 static JSONObject latest() throws Exception {
  JSONObject release=new JSONObject(read(UpdatePolicy.LATEST_RELEASE,MAX_METADATA));
  long code=UpdatePolicy.versionCodeFromTag(release.optString("tag_name",""));
  if(code<0)throw new IOException("Tag keluaran tidak sah");
  JSONArray assets=release.optJSONArray("assets");
  JSONObject best=null;
  for(int i=0;assets!=null&&i<assets.length();i++){
   JSONObject asset=assets.optJSONObject(i);
   if(asset==null)continue;
   String url=asset.optString("browser_download_url","");
   if(!UpdatePolicy.isAssetUrl(UpdatePolicy.REPOSITORY,url))continue;
   long size=asset.optLong("size",-1);
   if(size<=0||size>MAX_DOWNLOAD)continue;
   best=asset;
   break;
  }
  if(best==null)throw new IOException("Tiada APK yang sah dalam keluaran ini");
  JSONObject result=new JSONObject();
  result.put("versionName",release.optString("tag_name","").replace("v",""));
  result.put("versionCode",code);
  result.put("url",best.optString("browser_download_url",""));
  result.put("size",best.optLong("size",0));
  String digest=best.optString("digest","");
  if(digest.startsWith("sha256:"))digest=digest.substring(7);
  result.put("sha256",UpdatePolicy.isSha256(digest)?digest:"");
  return result;
 }

 /** Streams the verified asset to disk and returns the SHA-256 of the bytes actually received. */
 static String download(String url,File target) throws Exception {
  if(!UpdatePolicy.isAssetUrl(UpdatePolicy.REPOSITORY,url))throw new IOException("URL muat turun ditolak");
  String current=url;
  for(int hop=0;hop<=MAX_REDIRECTS;hop++){
   HttpURLConnection c=(HttpURLConnection)new URL(current).openConnection();
   c.setInstanceFollowRedirects(false);
   c.setConnectTimeout(15000);
   c.setReadTimeout(20000);
   c.setRequestProperty("User-Agent",UA);
   c.setRequestProperty("Accept","application/octet-stream");
   int status=c.getResponseCode();
   if(status==301||status==302||status==303||status==307||status==308){
    String location=c.getHeaderField("Location");
    c.disconnect();
    if(location==null)throw new IOException("Ubah hala tanpa lokasi");
    if(!UpdatePolicy.isTransportUrl(location))throw new IOException("Hos muat turun ditolak");
    current=location;
    continue;
   }
   if(status!=200)throw new IOException("GitHub menjawab "+status);
   long declared=c.getContentLength();
   if(declared>MAX_DOWNLOAD)throw new IOException("Fail terlalu besar");
   MessageDigest md=MessageDigest.getInstance("SHA-256");
   long written=0;
   try(InputStream in=c.getInputStream();FileOutputStream out=new FileOutputStream(target)){
    byte[] buffer=new byte[65536];int n;
    while((n=in.read(buffer))!=-1){
     written+=n;
     if(written>MAX_DOWNLOAD)throw new IOException("Fail melebihi had");
     md.update(buffer,0,n);out.write(buffer,0,n);
    }
    out.getFD().sync();
   }finally{c.disconnect();}
   if(declared>0&&written!=declared)throw new IOException("Saiz muat turun tidak sepadan");
   if(written<=0)throw new IOException("Fail kosong");
   return hex(md.digest());
  }
  throw new IOException("Terlalu banyak ubah hala");
 }

 /** True only when the archive is this package, at the announced code, signed like the installed app. */
 static boolean verify(Context context,File apk,long announcedCode) throws Exception {
  PackageManager pm=context.getPackageManager();
  int flags=Build.VERSION.SDK_INT>=28?PackageManager.GET_SIGNING_CERTIFICATES:PackageManager.GET_SIGNATURES;
  PackageInfo archive=pm.getPackageArchiveInfo(apk.getAbsolutePath(),flags);
  if(archive==null)return false;
  PackageInfo installed=pm.getPackageInfo(context.getPackageName(),flags);
  return UpdatePolicy.sameIdentity(archive.packageName,context.getPackageName(),versionCode(archive),announcedCode,certDigest(installed),certDigest(archive));
 }

 static int versionCode(PackageInfo info){
  return Build.VERSION.SDK_INT>=28?(int)info.getLongVersionCode():info.versionCode;
 }

 static String certDigest(PackageInfo info) throws Exception {
  Signature[] signatures;
  if(Build.VERSION.SDK_INT>=28)signatures=info.signingInfo==null?null:info.signingInfo.getApkContentsSigners();
  else signatures=info.signatures;
  if(signatures==null||signatures.length==0)return "";
  MessageDigest md=MessageDigest.getInstance("SHA-256");
  return hex(md.digest(signatures[0].toByteArray()));
 }

 /** Hands the verified file to Android; the system installer still asks the user to confirm. */
 static void install(Context context,File apk,PendingIntent result) throws Exception {
  PackageInstaller installer=context.getPackageManager().getPackageInstaller();
  PackageInstaller.SessionParams params=new PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL);
  params.setAppPackageName(context.getPackageName());
  int id=installer.createSession(params);
  PackageInstaller.Session session=installer.openSession(id);
  try{
   try(FileInputStream in=new FileInputStream(apk);java.io.OutputStream out=session.openWrite("base.apk",0,apk.length())){
    byte[] buffer=new byte[65536];int n;
    while((n=in.read(buffer))!=-1)out.write(buffer,0,n);
    out.flush();session.fsync(out);
   }
   session.commit(result.getIntentSender());
  }finally{session.close();}
 }

 private static String read(String address,int limit) throws Exception {
  HttpURLConnection c=(HttpURLConnection)new URL(address).openConnection();
  c.setConnectTimeout(15000);
  c.setReadTimeout(15000);
  c.setRequestProperty("User-Agent",UA);
  c.setRequestProperty("Accept","application/vnd.github+json");
  try{
   int status=c.getResponseCode();
   if(status!=200)throw new IOException("GitHub menjawab "+status);
   try(InputStream in=c.getInputStream();ByteArrayOutputStream out=new ByteArrayOutputStream()){
    byte[] buffer=new byte[8192];int n;
    while((n=in.read(buffer))!=-1){
     if(out.size()+n>limit)throw new IOException("Metadata terlalu besar");
     out.write(buffer,0,n);
    }
    return out.toString("UTF-8");
   }
  }finally{c.disconnect();}
 }

 private static String hex(byte[] data){
  StringBuilder sb=new StringBuilder(data.length*2);
  for(byte b:data)sb.append(String.format(Locale.ROOT,"%02x",b));
  return sb.toString();
 }
}
