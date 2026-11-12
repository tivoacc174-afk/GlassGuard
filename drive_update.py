"""Drive the GlassGuard update flow on a real device over ADB.

Usage: python drive_update.py focus <id>   -> D-pad down until the named control is focused
       python drive_update.py ok           -> press OK/ENTER on the focused control
       python drive_update.py state        -> print update status text and focused control
"""
from pathlib import Path
import subprocess, sys, json, time, re
import xml.etree.ElementTree as ET

root = Path(__file__).parent
adb = str(root / 'tools/platform-tools/adb.exe')
device = '192.168.0.99:5555'


def shell(cmd, timeout=40):
    return subprocess.run([adb, '-s', device, 'shell', cmd], capture_output=True, text=True,
                          encoding='utf-8', errors='replace', timeout=timeout).stdout


def dump():
    shell('uiautomator dump /sdcard/gg.xml')
    xml = shell('cat /sdcard/gg.xml')
    start = xml.find('<?xml')
    if start < 0:
        return []
    tree = ET.fromstring(xml[start:])
    return [dict(n.attrib) for n in tree.iter('node')]


def key(code):
    shell('input keyevent ' + code)


def focused(nodes):
    for n in nodes:
        if n.get('focused') == 'true':
            return n
    return None


def find(nodes, needle):
    for n in nodes:
        text = (n.get('text') or '') + ' ' + (n.get('content-desc') or '')
        if needle in text:
            return n
    return None


def main():
    action = sys.argv[1] if len(sys.argv) > 1 else 'state'
    if action == 'focus':
        needle = sys.argv[2]
        for step in range(14):
            nodes = dump()
            cur = focused(nodes)
            if cur and needle in ((cur.get('text') or '') + ' ' + (cur.get('content-desc') or '')):
                print('focused after', step, 'presses:', needle)
                return
            key('KEYCODE_DPAD_DOWN')
            time.sleep(0.7)
        print('did not reach:', needle)
        sys.exit(1)
    elif action == 'ok':
        key('KEYCODE_DPAD_CENTER')
        time.sleep(1)
        print('OK pressed')
    elif action == 'back':
        key('KEYCODE_BACK')
        print('BACK pressed')
    else:
        nodes = dump()
        for n in nodes:
            text = n.get('text') or ''
            if 'kemas kini' in text.lower() or 'versi' in text.lower() or 'GlassGuard sudah' in text:
                print('STATUS>', text)
        cur = focused(nodes)
        if cur:
            print('FOCUS>', (cur.get('text') or ''), cur.get('bounds'))


if __name__ == '__main__':
    main()
