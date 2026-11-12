package com.glassguard;

import java.net.URI;
import java.util.regex.Pattern;

/**
 * Pure policy checks for the self-update path. No Android or network types are referenced so
 * the same rules can be exercised by a plain JVM harness before they are wired to the device.
 */
public final class UpdatePolicy {
 private UpdatePolicy(){}

 private static final String HOST="github.com";
 private static final String CDN="release-assets.githubusercontent.com";
 private static final Pattern SHA256=Pattern.compile("[0-9a-f]{64}");
 private static final Pattern DIGITS=Pattern.compile("[0-9]+");
 private static final Pattern SEGMENT=Pattern.compile("[A-Za-z0-9._-]+");
 private static final Pattern REPO=Pattern.compile("[A-Za-z0-9._-]+/[A-Za-z0-9._-]+");

 public static final String REPOSITORY="tivoacc174-afk/GlassGuard";
 public static final String LATEST_RELEASE="https://api.github.com/repos/"+REPOSITORY+"/releases/latest";

 /** A strictly newer, positive version code within int range is an update. */
 public static boolean isNewer(long candidate,long installed){
  return installed>0&&candidate>installed&&candidate<=Integer.MAX_VALUE;
 }

 /** True only for an https github.com release asset of this exact repository and a .apk file. */
 public static boolean isAssetUrl(String repository,String url){
  if(url==null||repository==null)return false;
  if(!REPO.matcher(repository).matches())return false;
  if(url.indexOf('%')>=0||url.indexOf('\\')>=0)return false;
  URI uri;
  try{uri=new URI(url);}catch(Exception e){return false;}
  if(!uri.isAbsolute()||!"https".equalsIgnoreCase(uri.getScheme()))return false;
  if(!HOST.equalsIgnoreCase(uri.getHost()))return false;
  if(uri.getRawUserInfo()!=null||uri.getRawFragment()!=null||uri.getRawQuery()!=null)return false;
  if(uri.getPort()!=-1)return false;
  String path=uri.getPath();
  if(path==null)return false;
  String[] got=path.split("/",-1);
  String[] prefix=("/"+repository+"/releases/download").split("/",-1);
  if(got.length!=prefix.length+2)return false;
  for(int i=0;i<prefix.length;i++)if(!prefix[i].equals(got[i]))return false;
  String tag=got[prefix.length],file=got[prefix.length+1];
  if(!SEGMENT.matcher(tag).matches()||".".equals(tag)||"..".equals(tag))return false;
  if(!SEGMENT.matcher(file).matches()||".".equals(file)||"..".equals(file))return false;
  return file.length()>4&&file.endsWith(".apk");
 }

 /** GitHub redirects release downloads to this CDN host; nothing else may be fetched. */
 public static boolean isTransportUrl(String url){
  if(url==null||url.indexOf('\\')>=0)return false;
  URI uri;
  try{uri=new URI(url);}catch(Exception e){return false;}
  if(!uri.isAbsolute()||!"https".equalsIgnoreCase(uri.getScheme()))return false;
  if(!CDN.equalsIgnoreCase(uri.getHost()))return false;
  if(uri.getRawUserInfo()!=null||uri.getPort()!=-1||uri.getRawFragment()!=null)return false;
  String path=uri.getPath();
  if(path==null||path.length()<2)return false;
  // The path must be literal: signed release assets only ever vary in the query.
  if(uri.getRawPath()!=null&&uri.getRawPath().indexOf('%')>=0)return false;
  for(String segment:path.split("/",-1))if(".".equals(segment)||"..".equals(segment))return false;
  String query=uri.getRawQuery();
  if(query!=null){
   // Percent escapes are required by the signed query; malformed escapes are rejected, not repaired.
   for(int i=0;i<query.length();i++){
    if(query.charAt(i)!='%')continue;
    if(i+2>=query.length())return false;
    if(!isHex(query.charAt(i+1))||!isHex(query.charAt(i+2)))return false;
   }
  }
  return true;
 }

 private static boolean isHex(char c){
  return (c>='0'&&c<='9')||(c>='a'&&c<='f')||(c>='A'&&c<='F');
 }

 /** The downloaded package must be this app, at the announced version, signed by the same key. */
 public static boolean sameIdentity(String pkg,String expectedPkg,long version,long announcedVersion,String expectedCert,String actualCert){
  if(pkg==null||expectedPkg==null||!pkg.equals(expectedPkg))return false;
  if(announcedVersion<=0||version!=announcedVersion)return false;
  if(expectedCert==null||actualCert==null)return false;
  if(expectedCert.isEmpty()||actualCert.isEmpty())return false;
  return expectedCert.equals(actualCert);
 }

 /** Accepts only a canonical lowercase 64-hex digest; malformed values are rejected, never repaired. */
 public static boolean isSha256(String value){
  return value!=null&&SHA256.matcher(value).matches();
 }

 /**
  * Maps a release tag of the form vMAJOR.MINOR.PATCH to a monotonic version code
  * (major*10000 + minor*100 + patch). Anything else returns -1 so a malformed tag can
  * never be interpreted as a real update.
  */
 public static long versionCodeFromTag(String tag){
  if(tag==null)return -1;
  int i=tag.startsWith("v")||tag.startsWith("V")?1:0;
  String[] parts=tag.substring(i).split("\\.",-1);
  if(parts.length!=3)return -1;
  long[] value=new long[3];
  for(int p=0;p<3;p++){
   String s=parts[p];
   if(s.isEmpty()||s.length()>2||!DIGITS.matcher(s).matches())return -1;
   value[p]=Long.parseLong(s);
  }
  if(value[0]<1)return -1;
  long code=value[0]*10000+value[1]*100+value[2];
  return code<=Integer.MAX_VALUE?code:-1;
 }
}
