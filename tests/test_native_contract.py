import pathlib,unittest,xml.etree.ElementTree as ET
ROOT=pathlib.Path(__file__).resolve().parents[1]
class NativeContract(unittest.TestCase):
 def test_native_offline_dashboard_contract(self):
  p=ROOT/'app/src/main/java/com/glassguard/MainActivity.java'
  self.assertTrue(p.exists(),'Native Android dashboard is not implemented')
  s=p.read_text(encoding='utf-8')
  for method in ['scan','refresh','openApp','uninstall','optimize','exportReport','apps','checkForUpdate','installUpdate']:
   self.assertRegex(s,r'@JavascriptInterface\s+public void '+method+r'\(')
  self.assertIn('ScannerEngine.inspectApk',s)
  self.assertIn('splitSourceDirs',s)
  self.assertIn('ACTION_DELETE',s)
  self.assertIn('FLAG_SYSTEM',s)
  self.assertIn('setPositiveButton',s)
  self.assertIn('Build.VERSION.SDK_INT>=34',s)
  self.assertIn('setAllowFileAccess(false)',s)
  self.assertIn('setBlockNetworkLoads(true)',s)
  self.assertNotIn('Runtime.getRuntime().exec',s)
  self.assertNotIn('ProcessBuilder',s)
 def test_update_path_verifies_before_installing(self):
  p=ROOT/'app/src/main/java/com/glassguard/Updater.java'
  self.assertTrue(p.exists(),'Updater is not implemented')
  s=p.read_text(encoding='utf-8')
  # Every URL decision goes through the pure policy, never an ad-hoc host check.
  self.assertIn('UpdatePolicy.isAssetUrl',s)
  self.assertIn('UpdatePolicy.isTransportUrl',s)
  self.assertIn('UpdatePolicy.sameIdentity',s)
  self.assertIn('setInstanceFollowRedirects(false)',s)
  self.assertIn('MessageDigest.getInstance("SHA-256")',s)
  self.assertIn('MAX_DOWNLOAD',s)
  self.assertNotIn('Runtime.getRuntime().exec',s)
  self.assertNotIn('ProcessBuilder',s)
  # The file is handed to PackageInstaller, never installed silently.
  self.assertIn('PackageInstaller',s)
  self.assertIn('session.commit',s)
 def test_update_requires_hash_and_identity_before_confirm(self):
  s=(ROOT/'app/src/main/java/com/glassguard/MainActivity.java').read_text(encoding='utf-8')
  self.assertIn('Updater.download',s)
  self.assertIn('expected.equals(actual)',s)
  self.assertIn('Updater.verify',s)
  self.assertIn('confirmInstall',s)
  self.assertIn('STATUS_PENDING_USER_ACTION',s)
  # PackageInstaller writes the outcome into the result Intent, so Android 12+ needs MUTABLE.
  self.assertIn('FLAG_MUTABLE',s)
  self.assertNotRegex(s,r'FLAG_IMMUTABLE:0\)')
  # A failed or cancelled install must never leave the UI stuck in the checking state.
  self.assertRegex(s,r'else\{\s*\n\s*// Never leave the UI in \\?"checking\\?"')
  self.assertIn('setUpdating("error"',s)
  # Android 8+ requires the user to grant install-unknown-apps for this package.
  self.assertIn('canRequestPackageInstalls',s)
  self.assertIn('ACTION_MANAGE_UNKNOWN_APP_SOURCES',s)
  # Cancelling the confirm dialog returns to the available state rather than checking.
  self.assertRegex(s,r'\.setNegativeButton\("Batal",\(d,w\)->\{\s*\n\s*apk\.delete\(\);\s*\n\s*try\{setUpdating\("available"')
 def test_manifest_permissions_are_limited_and_declared(self):
  p=ROOT/'app/src/main/AndroidManifest.xml'
  self.assertTrue(p.exists(),'Android manifest is missing')
  root=ET.parse(p).getroot();ns='{http://schemas.android.com/apk/res/android}'
  perms={e.attrib[ns+'name'] for e in root.findall('uses-permission')}
  self.assertEqual(perms,{'android.permission.QUERY_ALL_PACKAGES','android.permission.KILL_BACKGROUND_PROCESSES','android.permission.REQUEST_DELETE_PACKAGES','android.permission.INTERNET','android.permission.REQUEST_INSTALL_PACKAGES'})
  self.assertEqual(root.find('application').attrib[ns+'allowBackup'],'false')
  # versionName and versionCode must stay in the same monotonic scheme the updater compares.
  name=root.attrib[ns+'versionName'];code=int(root.attrib[ns+'versionCode'])
  major,minor,patch=(int(x) for x in name.split('.'))
  self.assertEqual(code,major*10000+minor*100+patch,'versionCode must match versionName')
  self.assertGreaterEqual(code,2,'updater needs a code above the original 1.0.0')
if __name__=='__main__':unittest.main()
