#!/usr/bin/env python
"""Debloat the GlassGuard test TV over ADB, reversibly.

Rules learned the hard way:
  - Never disable the launcher, input method, WebView, GMS/GSF, Play Store,
    systemui, tv.settings, permissioncontroller, networkstack or vendor
    (com.sdt.*, com.realtek.*) packages: the box stops booting to a usable UI.
  - Disable in small batches and verify the launcher still resolves after each.
  - Record every package touched in debloat-state.json so `--restore` can undo it.

Usage:
  python debloat.py --plan          # print what would be disabled
  python debloat.py --apply         # disable the safe set, batch by batch
  python debloat.py --apply-target X  # disable one package
  python debloat.py --restore       # re-enable everything recorded
  python debloat.py --status        # show current state of recorded packages
"""
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).parent
ADB = str(ROOT / 'tools/platform-tools/adb.exe')
DEVICE = '192.168.0.99:5555'
STATE = ROOT / 'debloat-state.json'

# Absolutely must stay enabled on a Skyworth/Realtek Google TV STB.
PROTECTED = {
    'android',
    'com.spocky.projengmenu',              # the launcher
    'com.google.android.inputmethod.latin',  # the keyboard
    'com.google.android.webview',            # GlassGuard renders in this
    'com.google.android.gms', 'com.google.android.gsf',
    'com.android.vending',                   # Play Store
    'com.android.systemui', 'com.android.tv.settings',
    'com.android.permissioncontroller', 'com.android.shell',
    'com.android.networkstack', 'com.android.networkstack.tethering',
    'com.android.providers.settings', 'com.android.providers.media',
    'com.android.providers.media.module',
    'com.android.bluetooth', 'com.android.inputdevices',
    'com.android.packageinstaller', 'com.google.android.packageinstaller',
    'com.android.keychain', 'com.android.certinstaller',
    'com.android.wifi.dialog', 'com.android.wifi.resources',
    'com.android.settings.intelligence',
    'com.google.android.katniss',            # Google TV voice search / assistant
    'com.google.android.apps.tv.launcherx',
    'com.sdt.globalkey', 'com.sdt.customization',
    'com.sdt.frontpanelledsservice', 'com.sdt.deviceinfo',
    'com.sdt.ota', 'com.sdt.mecoolrcupair',
    'com.rtk.partnerinterface', 'com.realtek.slices',
}

# Safe to disable on a TV: entertainment/QA/backup clutter, no OS role.
CANDIDATES = {
    'com.oemservice': 'XCPE package indicator — the actual malware finding',
    'com.amazon.amazonvideo.livingroom': 'Amazon Prime Video preinstall',
    'com.google.android.play.games': 'Play Games',
    'com.google.android.youtube.tvmusic': 'YouTube Music',
    'com.google.android.apps.mediashell': 'media shell',
    'com.google.android.apps.tv.dreamx': 'TV screensaver',
    'com.android.dreams.basic': 'basic screensaver',
    'com.google.android.syncadapters.calendar': 'calendar sync',
    'com.android.providers.calendar': 'calendar storage (unused on a TV)',
    'com.google.android.feedback': 'feedback agent',
    'com.google.android.partnersetup': 'partner setup (post-provisioning)',
    'com.google.android.onetimeinitializer': 'one-time initialiser',
    'com.google.android.tungsten.setupwraith': 'setup wrapper (post-setup)',
    'com.android.printspooler': 'printing (no printer on a TV)',
    'com.android.wallpaperbackup': 'wallpaper backup',
    'com.android.backupconfirm': 'backup confirmation',
    'com.android.sharedstoragebackup': 'shared storage backup',
    'com.android.tv.feedbackconsent': 'TV feedback consent',
    'com.sdt.producttest': 'factory product test',
    'com.oem.qa': 'OEM QA harness',
    'com.sdt.demo.control': 'retail demo control',
    'com.google.android.marvin.talkback': 'TalkBack (enable if screen reader needed)',
}

BATCHES = [
    ('malware finding', ['com.oemservice']),
    ('retail / QA clutter', ['com.sdt.producttest', 'com.oem.qa', 'com.sdt.demo.control']),
    ('media preinstalls', ['com.amazon.amazonvideo.livingroom', 'com.google.android.youtube.tvmusic',
                           'com.google.android.apps.mediashell']),
    ('backup & setup leftovers', ['com.android.backupconfirm', 'com.android.sharedstoragebackup',
                                  'com.android.wallpaperbackup', 'com.google.android.partnersetup',
                                  'com.google.android.onetimeinitializer',
                                  'com.google.android.tungsten.setupwraith']),
    ('screensavers & feedback', ['com.google.android.apps.tv.dreamx', 'com.android.dreams.basic',
                                 'com.google.android.feedback', 'com.android.tv.feedbackconsent']),
    ('calendar, print, games', ['com.android.providers.calendar',
                                'com.google.android.syncadapters.calendar',
                                'com.android.printspooler', 'com.google.android.play.games']),
]


def sh(cmd, timeout=40):
    return subprocess.run([ADB, '-s', DEVICE, 'shell', cmd], capture_output=True,
                          text=True, encoding='utf-8', errors='replace', timeout=timeout).stdout.strip()


def installed(pkg):
    return pkg in sh('pm list packages')


def is_disabled(pkg):
    out = sh('pm list packages -d')
    return ('package:' + pkg) in out


def launcher_ok():
    out = sh('pm resolve-activity -c android.intent.category.HOME -a android.intent.action.MAIN')
    return 'packageName=' in out and 'Error' not in out


def load():
    if STATE.exists():
        return json.loads(STATE.read_text(encoding='utf-8'))
    return {'disabled': []}


def save(state):
    STATE.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding='utf-8')


def disable(pkg, reason, state):
    if pkg in PROTECTED:
        return f'SKIP {pkg}: protected'
    if not installed(pkg):
        return f'SKIP {pkg}: not installed'
    if is_disabled(pkg):
        return f'ALREADY {pkg}'
    out = sh(f'pm disable-user --user 0 {pkg}')
    ok = is_disabled(pkg)
    if ok:
        if pkg not in state['disabled']:
            state['disabled'].append(pkg)
        save(state)
        return f'DISABLED {pkg}  ({reason})'
    return f'FAILED {pkg}: {out[:90]}'


def do_apply(target=None):
    state = load()
    if target:
        print(disable(target, CANDIDATES.get(target, 'requested'), state))
        return 0
    for label, pkgs in BATCHES:
        print(f'\n--- {label} ---')
        for pkg in pkgs:
            print(disable(pkg, CANDIDATES.get(pkg, ''), state))
        time.sleep(2)
        if not launcher_ok():
            print('LAUNCHER BROKEN — restoring this batch immediately')
            for pkg in pkgs:
                sh(f'pm enable {pkg}')
            state['disabled'] = [p for p in state['disabled'] if p not in pkgs]
            save(state)
            return 1
        print('launcher still resolves: ok')
    return 0


def do_restore():
    state = load()
    for pkg in list(state['disabled']):
        sh(f'pm enable {pkg}')
        print(('RESTORED ' if not is_disabled(pkg) else 'STILL DISABLED ') + pkg)
    state['disabled'] = []
    save(state)
    print('launcher ok:', launcher_ok())


def do_status():
    state = load()
    if not state['disabled']:
        print('nothing recorded as disabled by this script')
    for pkg in state['disabled']:
        print(f"{pkg:45} installed={installed(pkg)!s:5} disabled={is_disabled(pkg)}")
    print('launcher ok:', launcher_ok())


def do_plan():
    print('Would disable (protected packages are never touched):')
    for label, pkgs in BATCHES:
        print(f'\n{label}:')
        for pkg in pkgs:
            mark = 'PROTECTED' if pkg in PROTECTED else ('disabled' if is_disabled(pkg) else 'enabled')
            print(f'  {pkg:45} {mark:9} {CANDIDATES.get(pkg, "")}')


if __name__ == '__main__':
    arg = sys.argv[1] if len(sys.argv) > 1 else '--plan'
    if arg == '--plan':
        do_plan()
    elif arg == '--apply':
        sys.exit(do_apply())
    elif arg == '--apply-target':
        sys.exit(do_apply(sys.argv[2]))
    elif arg == '--restore':
        do_restore()
    elif arg == '--status':
        do_status()
    else:
        print(__doc__)
        sys.exit(2)
