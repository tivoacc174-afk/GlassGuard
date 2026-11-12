package com.glassguard;

/**
 * Pure rules for remediation. The point of this class is honesty: an ordinary Android app
 * cannot delete files under /system, cannot rewrite firmware and cannot remove a backdoor that
 * lives in a system partition. So the strongest action that is actually permitted is chosen per
 * finding, and the result is described as what Android really did.
 */
public final class RemedyPolicy {
 private RemedyPolicy(){}

 public static final String UNINSTALL="uninstall";
 public static final String DISABLE="disable";
 public static final String NONE="none";

 /**
  * @param hasPackage the finding names a package we can act on
  * @param system     that package is part of the system image
  * @return UNINSTALL for a user app, DISABLE for a system app, NONE otherwise
  */
 public static String remedy(boolean hasPackage,boolean system){
  if(!hasPackage)return NONE;
  return system?DISABLE:UNINSTALL;
 }

 /** Only a real removal of a user app is destructive enough to warrant a warning dialog. */
 public static boolean isDestructive(String remedy){
  return UNINSTALL.equals(remedy);
 }

 /**
  * Describes the outcome after the user's action, from observed state only.
  *
  * @param wasPresent installed before the action
  * @param nowPresent installed after it
  * @param enabled    the package is enabled after it
  */
 public static String verdict(boolean wasPresent,boolean nowPresent,boolean enabled){
  if(!wasPresent)return "absent";
  if(!nowPresent)return "removed";
  return enabled?"unchanged":"disabled";
 }
}
