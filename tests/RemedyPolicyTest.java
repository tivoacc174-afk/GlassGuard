package com.glassguard;
import java.lang.reflect.*;
public final class RemedyPolicyTest {
 static int checks;
 static void ok(boolean v,String message){if(!v)throw new AssertionError(message);checks++;}
 static Object call(String m,Class<?>[] types,Object... args)throws Exception{
  Class<?> c;try{c=Class.forName("com.glassguard.RemedyPolicy");}catch(ClassNotFoundException e){throw new AssertionError("RemedyPolicy is not implemented");}
  return c.getMethod(m,types).invoke(null,args);
 }
 static String remedy(boolean pkg,boolean system)throws Exception{return (String)call("remedy",new Class[]{boolean.class,boolean.class},pkg,system);}
 static String verdict(boolean was,boolean now,boolean enabled)throws Exception{return (String)call("verdict",new Class[]{boolean.class,boolean.class,boolean.class},was,now,enabled);}
 static boolean destructive(String r)throws Exception{return (Boolean)call("isDestructive",new Class[]{String.class},r);}
 public static void main(String[] args)throws Exception{
  String stage=args.length==0?"remedy":args[0];
  ok("uninstall".equals(remedy(true,false)),"a user app can be uninstalled");
  ok("disable".equals(remedy(true,true)),"a system app is disable-only, never uninstall");
  ok("none".equals(remedy(false,false)),"a finding without a package has no removal action");
  ok("none".equals(remedy(false,true)),"a firmware finding has no removal action");
  ok(destructive("uninstall"),"uninstall is destructive and needs confirmation");
  ok(!destructive("disable"),"disable is not destructive");
  ok(!destructive("none"),"no action is not destructive");
  if(stage.equals("verdict")){
   ok("removed".equals(verdict(true,false,false)),"gone after the action means removed");
   ok("disabled".equals(verdict(true,true,false)),"still installed but disabled");
   ok("unchanged".equals(verdict(true,true,true)),"still installed and enabled is unchanged");
   ok("absent".equals(verdict(false,false,false)),"never installed");
   ok("absent".equals(verdict(false,true,true)),"appeared anyway is not our success");
   // The app must never offer a removal action for a firmware finding.
   ok("none".equals(remedy(false,true)),"a firmware finding never advertises removal");
   ok(!destructive(remedy(false,true)),"a firmware finding never triggers a destructive prompt");
  }
  System.out.println("PASS: "+checks+" remedy assertions ("+stage+")");
 }
}
