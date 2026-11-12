package com.glassguard;
import java.lang.reflect.*;
public final class UpdatePolicyTest {
 static int checks;
 static void ok(boolean v,String message){if(!v)throw new AssertionError(message);checks++;}
 static Object call(String m,Class<?>[] types,Object... args)throws Exception{
  Class<?> c;try{c=Class.forName("com.glassguard.UpdatePolicy");}catch(ClassNotFoundException e){throw new AssertionError("UpdatePolicy is not implemented");}
  return c.getMethod(m,types).invoke(null,args);
 }
 static boolean newer(long n,long old)throws Exception{return (Boolean)call("isNewer",new Class[]{long.class,long.class},n,old);}
 static boolean asset(String u)throws Exception{return (Boolean)call("isAssetUrl",new Class[]{String.class,String.class},"example/GlassGuard",u);}
 public static void main(String[] args)throws Exception{
  String stage=args.length==0?"version":args[0];
  ok(newer(2,1),"higher versionCode is update");ok(!newer(2,2),"equal versionCode is current");ok(!newer(1,2),"downgrade rejected");ok(!newer(-1,1),"negative version rejected");
  if(!stage.equals("version")){
   ok(asset("https://github.com/example/GlassGuard/releases/download/v1.1.0/GlassGuard-1.1.0.apk"),"own release asset allowed");
   for(String u:new String[]{"http://github.com/example/GlassGuard/releases/download/v1/app.apk","https://github.com/attacker/GlassGuard/releases/download/v1/app.apk","https://github.com.evil.test/example/GlassGuard/releases/download/v1/app.apk","https://evil@github.com/example/GlassGuard/releases/download/v1/app.apk","https://github.com:8443/example/GlassGuard/releases/download/v1/app.apk","https://github.com/example/GlassGuard/releases/download/v1/../app.apk","https://github.com/example/GlassGuard/releases/download/v1/%2fapp.apk","https://github.com/example/GlassGuard/releases/download/v1/app.apk?token=secret"})ok(!asset(u),"untrusted asset rejected: "+u);
   ok((Boolean)call("isTransportUrl",new Class[]{String.class},"https://release-assets.githubusercontent.com/github-production-release-asset/123/file"),"GitHub CDN redirect allowed");
   ok((Boolean)call("isTransportUrl",new Class[]{String.class},"https://release-assets.githubusercontent.com/github-production-release-asset/123/file?sp=r&sig=xidWJ%2BCo9WXb%2BOuW797AsHZYgK9171FtTRbEqHyQM5c%3D&response-content-disposition=attachment%3B%20filename%3Dapp.apk"),"signed CDN query with percent-encoding allowed");
   ok(!(Boolean)call("isTransportUrl",new Class[]{String.class},"https://release-assets.githubusercontent.com/../secret?x=1"),"CDN dot-segment rejected");
   ok(!(Boolean)call("isTransportUrl",new Class[]{String.class},"https://release-assets.githubusercontent.com/%2e%2e/secret"),"encoded dot-segment rejected");
   ok(!(Boolean)call("isTransportUrl",new Class[]{String.class},"https://release-assets.githubusercontent.com/file#frag"),"CDN fragment rejected");
   ok(!(Boolean)call("isTransportUrl",new Class[]{String.class},"https://release-assets.githubusercontent.com.evil.test/file"),"untrusted CDN rejected");
   ok(!(Boolean)call("isTransportUrl",new Class[]{String.class},"file:///sdcard/malicious.apk"),"file transport rejected");
  }
  if(stage.equals("identity")){
   Class<?>[] types={String.class,String.class,long.class,long.class,String.class,String.class};
   Object[] good={"com.glassguard","com.glassguard",2L,2L,"same-cert","same-cert"};
   ok((Boolean)call("sameIdentity",types,good),"matching package version certificate");
   Object[] wrong=good.clone();wrong[1]="com.attacker.app";ok(!(Boolean)call("sameIdentity",types,wrong),"other package rejected");
   wrong=good.clone();wrong[3]=3L;ok(!(Boolean)call("sameIdentity",types,wrong),"announced version mismatch rejected");
   wrong=good.clone();wrong[5]="different-cert";ok(!(Boolean)call("sameIdentity",types,wrong),"different signing certificate rejected");
   wrong=good.clone();wrong[4]="";wrong[5]="";ok(!(Boolean)call("sameIdentity",types,wrong),"missing certificates rejected");
   ok((Boolean)call("isSha256",new Class[]{String.class},"a".repeat(64)),"valid sha256 accepted");
   ok(!(Boolean)call("isSha256",new Class[]{String.class},"a".repeat(32)),"malformed source hash rejected not repaired");
  }
  if(stage.equals("tag")){
   Object[][] cases={{ "v1.1.0",10100 },{ "1.0.0",10000 },{ "v2.3.4",20304 },{ "v1.1",-1 },{ "1",-1 },{ "v1.1.0-beta1",-1 },{ "vv1.1.0",-1 },{ "v1.100.0",-1 },{ "v1.1.100",-1 },{ "",-1 },{ null,-1 }};
   for(Object[] c:cases){
    long got=((Number)call("versionCodeFromTag",new Class[]{String.class},c[0])).longValue();
    ok(got==((Number)c[1]).longValue(),"tag "+c[0]+" -> "+got+" expected "+c[1]);
   }
  }
  System.out.println("PASS: "+checks+" updater policy assertions ("+stage+")");
 }
}
