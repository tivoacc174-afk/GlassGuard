'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const asset = path.join(__dirname, 'app/src/main/assets/index.html');
let passed = 0;
function test(name, fn) {
  try { fn(); console.log('PASS ' + name); passed++; }
  catch (error) { console.error('FAIL ' + name + '\n' + error.message); process.exitCode = 1; }
}
// A deliberately small DOM adapter; executes the real inline script, not a reimplementation.
class Element {
  constructor(tag, document) {
    this.tagName = tag.toUpperCase(); this.ownerDocument = document;
    this.children = []; this.attributes = {}; this.listeners = {}; this.style = {};
    this.hidden = false; this.disabled = false; this.value = ''; this._text = '';
    this.classList = { add() {}, remove() {}, toggle() {} };
  }
  set textContent(value) { this._text = String(value ?? ''); this.children = []; }
  get textContent() { return this._text + this.children.map(x => x.textContent).join(''); }
  appendChild(node) { node.parentElement = this; this.children.push(node); return node; }
  append(...nodes) { nodes.forEach(n => this.appendChild(n)); }
  replaceChildren(...nodes) { this.children = []; this._text = ''; this.append(...nodes); }
  setAttribute(key, value) { this.attributes[key] = String(value); if (key === 'id') this.id = String(value); if (key === 'hidden') this.hidden = true; }
  getAttribute(key) { return this.attributes[key] ?? null; }
  removeAttribute(key) { delete this.attributes[key]; }
  addEventListener(type, fn) { (this.listeners[type] ||= []).push(fn); }
  dispatch(type, extra = {}) { const e = { target: this, key: '', preventDefault() { this.defaultPrevented = true; }, ...extra }; (this.listeners[type] || []).forEach(fn => fn(e)); return e; }
  click() { if (!this.disabled) this.dispatch('click'); }
  focus() { this.ownerDocument.activeElement = this; }
  getClientRects() { for (let e = this; e; e = e.parentElement) if (e.hidden) return []; return [this.getBoundingClientRect()]; }
  getBoundingClientRect() { const i = this.ownerDocument.all().indexOf(this); return { x: 0, y: i * 60, left: 0, top: i * 60, right: 160, bottom: i * 60 + 48, width: 160, height: 48 }; }
  matches(selector) { return selector.split(',').some(s => { s = s.trim(); return s === this.tagName.toLowerCase() || (s[0] === '#' && this.id === s.slice(1)) || (s === '[tabindex]' && this.getAttribute('tabindex') !== null); }); }
  closest(selector) { for (let e = this; e; e = e.parentElement) if (e.matches(selector)) return e; return null; }
  querySelectorAll(selector) { const out = []; const walk = el => el.children.forEach(x => { if (x.matches(selector)) out.push(x); walk(x); }); walk(this); return out; }
}
function boot(html, bridge) {
  const document = new Element('document', null); document.ownerDocument = document;
  document.all = () => document.querySelectorAll('html,head,body,main,header,footer,section,aside,div,p,span,h1,h2,h3,button,input,summary,details,ul,li,a,progress,strong,label,small,svg,path,nav');
  document.createElement = tag => new Element(tag, document);
  document.getElementById = id => document.all().find(el => el.id === id) || null;
  const clean = html.replace(/<(script|style)\b[^>]*>[\s\S]*?<\/\1>/gi, '');
  const stack = [document];
  for (const match of clean.matchAll(/<\/?([a-z][\w-]*)\b([^>]*)>/gi)) {
    const [token, tag, attrs] = match;
    if (token.startsWith('</')) { if (stack.length > 1) stack.pop(); continue; }
    const el = document.createElement(tag);
    for (const a of attrs.matchAll(/([\w-]+)(?:="([^"]*)"|='([^']*)')?/g)) el.setAttribute(a[1], a[2] ?? a[3] ?? '');
    stack.at(-1).appendChild(el);
    if (!/^(meta|input|br|hr|link|img)$/i.test(tag) && !token.endsWith('/>')) stack.push(el);
  }
  const window = { document, GlassGuard: bridge };
  const context = vm.createContext({ window, document, console, URL, Intl, Date, Number, String, Array, Object, Math, JSON, setTimeout: fn => fn(), clearTimeout() {} });
  const scripts = [...html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/gi)];
  assert.equal(scripts.length, 1, 'one self-contained inline script');
  vm.runInContext(scripts[0][1], context, { filename: 'index.html:inline' });
  return { window, document, id: id => { const el = document.getElementById(id); assert.ok(el, 'Missing #' + id); return el; } };
}
function descendants(el) { return [el, ...el.children.flatMap(descendants)]; }
function text(el) { return el.textContent; }
function controls(el) { return descendants(el).filter(x => x.tagName === 'BUTTON'); }
function fixture() {
  return { device: { model: 'TV ujian', android: '12', sdk: 31 }, memory: { total: 2147483648, available: 536870912, lowMemory: false }, scan: { status: 'complete', scanned: 12, total: 12, timestamp: 1700000000000, findings: [{ id: 'one', severity: 'high', title: '<img src=x onerror=alert(1)>', detail: 'Petunjuk ujian sahaja', packageName: 'org.test.app', system: false, evidence: ['Fail ujian', '<script>unsafe</script>'], source: 'https://example.org/report' }, { id: 'two', severity: 'medium', title: 'Komponen sistem', detail: 'Perlu semakan firmware', packageName: 'org.test.system', system: true, evidence: 'Indikator firmware', source: 'javascript:alert(1)' }], limitations: ['Tidak mengesahkan partition sistem.'] }, apps: [{ packageName: 'org.test.app', label: 'Aplikasi ujian', system: false, enabled: true }, { packageName: 'org.test.system', label: 'Sistem ujian', system: true, enabled: false }] };
}
test('HTML asset exists before loading', () => assert.ok(fs.existsSync(asset), 'Missing local HTML asset: ' + asset));
if (fs.existsSync(asset)) {
  const html = fs.readFileSync(asset, 'utf8');
  test('offline semantic Malay asset and responsive glass styles', () => {
    assert.match(html, /<html[^>]+lang="ms"/); assert.match(html, /name="viewport"/);
    assert.match(html, /Content-Security-Policy/); assert.match(html, /connect-src 'none'/);
    assert.doesNotMatch(html, /<(?:script|link|img)[^>]+(?:src|href)\s*=\s*["']https?:/i);
    assert.doesNotMatch(html, /\b(?:innerHTML|outerHTML|insertAdjacentHTML|eval)\b/);
    assert.match(html, /backdrop-filter/); assert.match(html, /Segoe UI/);
    assert.match(html, /@media[^{}]*max-width/); assert.match(html, /prefers-reduced-motion/);
    assert.match(html, /:focus-visible/); assert.match(html, /min-height:\s*44px/);
    const ids = [...html.matchAll(/\bid="([^"]+)"/g)].map(m => m[1]);
    assert.equal(ids.length, new Set(ids).size, 'IDs must be unique');
  });
  test('preview starts honestly with unknown metrics and no findings', () => {
    const ui = boot(html);
    assert.equal(typeof ui.window.renderState, 'function');
    assert.match(text(ui.id('connection')), /Pratonton — sambungkan aplikasi Android untuk data sebenar/);
    assert.match(text(ui.id('scan-status')), /Belum diimbas/);
    assert.equal(text(ui.id('memory-available')), '—');
    assert.equal(ui.id('scan-button').disabled, true);
    assert.match(text(ui.id('findings')), /Belum ada hasil/);
    assert.match(html, /Imbasan indikator, bukan jaminan peranti bebas malware\. Firmware sistem mungkin perlukan firmware bersih\./);
  });
  test('update check is an explicit native action with a disabled preview', () => {
    const preview = boot(html);
    assert.equal(preview.id('update-button').disabled, true);
    let checks = 0;
    const ui = boot(html, { refresh() {}, checkForUpdate() { checks++; } });
    assert.equal(checks, 0, 'no automatic update check on page load');
    assert.equal(ui.id('update-button').disabled, false);
    assert.equal(ui.id('update-button').getAttribute('type'), 'button');
    assert.equal(ui.id('update-button').getAttribute('class'), 'tool-button');
    assert.match(html, /<span class="tool-label">Check for update<\/span>/);
    assert.match(html, /Semak kemas kini melalui GitHub/);
    assert.match(html, /Imbasan setempat · Kemas kini melalui GitHub apabila diminta/);
    assert.doesNotMatch(html, /Data kekal pada peranti/);
    ui.window.renderState({ message: 'Mesej asli' });
    assert.equal(checks, 0, 'state rendering must not check for updates');
    ui.id('update-button').click();
    assert.equal(checks, 1);
    ui.id('update-button').focus();
    ui.document.dispatch('keydown', { key: 'ArrowUp', target: ui.id('update-button') });
    assert.notEqual(ui.document.activeElement, ui.id('update-button'));
  });
  test('update state renders version, gates install, and never auto-downloads', () => {
    let installs = 0, checks = 0;
    const ui = boot(html, { checkForUpdate() { checks++; }, installUpdate() { installs++; } });
    assert.equal(ui.id('install-button').hidden, true);
    assert.equal(installs, 0, 'no automatic download on load');
    assert.match(text(ui.id('update-status')), /Tiada semakan/);
    ui.window.renderState({ update: { status: 'available', latest: '1.2.0', versionCode: 10200, size: 4194304 } });
    assert.match(text(ui.id('update-status')), /1\.2\.0/);
    assert.match(text(ui.id('update-status')), /4([.,]0)? MB/, 'megabyte sizes are shown in MB');
    assert.equal(ui.id('install-button').hidden, false);
    assert.equal(installs, 0, 'rendering state must not start a download');
    ui.window.renderState({ update: { status: 'available', latest: '1.2.0', size: 49886 } });
    assert.match(text(ui.id('update-status')), /49 KB/, 'a small APK must not read as 0 MB');
    ui.id('install-button').click();
    assert.equal(installs, 1);
    ui.window.renderState({ update: { status: 'current', latest: '1.2.0' } });
    assert.equal(ui.id('install-button').hidden, true);
    assert.match(text(ui.id('update-status')), /terkini|terbaharu/i);
    ui.window.renderState({ update: { status: 'error', detail: 'Rangkaian tidak tersedia' } });
    assert.equal(ui.id('install-button').hidden, true);
    assert.match(text(ui.id('update-status')), /Rangkaian tidak tersedia/);
    for (const status of ['weird', '', null, 5]) {
      ui.window.renderState({ update: { status, latest: '9.9.9' } });
      assert.equal(ui.id('install-button').hidden, true, 'unknown status must not offer an install');
    }
    ui.window.renderState({ update: { status: 'checking' } });
    assert.match(text(ui.id('update-status')), /Menyemak/);
    assert.equal(ui.id('update-button').disabled, true);
  });
  test('findings offer only the strongest permitted removal and verify the outcome', () => {
    const calls = [];
    const ui = boot(html, { openApp: p => calls.push(['open', p]), uninstall: p => calls.push(['uninstall', p]), apps() {} });
    ui.window.renderState(fixture());
    const buttons = controls(ui.id('findings'));
    // A user app is offered a permanent removal; a system app is offered disable, never uninstall.
    assert.equal(buttons.filter(x => text(x) === 'Buang kekal').length, 1);
    assert.equal(buttons.filter(x => text(x) === 'Nyahaktif').length, 1);
    assert.equal(buttons.filter(x => text(x) === 'Hapus').length, 0, 'the old ambiguous label is gone');
    // Verification status must be rendered from a verdict, not assumed from the click.
    ui.window.renderState({ scan: { verdicts: { 'org.test.app': 'removed', 'org.test.system': 'disabled' } } });
    assert.match(text(ui.id('findings')), /dibuang daripada pengguna ini/i);
    assert.match(text(ui.id('findings')), /dinyahaktifkan/i);
    ui.window.renderState({ scan: { verdicts: { 'org.test.app': 'unchanged' } } });
    assert.match(text(ui.id('findings')), /masih dipasang|tidak berubah/i);
    assert.doesNotMatch(text(ui.id('findings')), /berjaya dibuang/i, 'an unchanged package is never reported as removed');
    // Firmware findings get no removal control at all.
    ui.window.renderState({ scan: { findings: [{ id: 'f', severity: 'medium', title: 'BADBOX — nama library firmware', detail: 'x', packageName: '', system: true }] } });
    assert.equal(controls(ui.id('findings')).filter(x => /Buang kekal|Nyahaktif/.test(text(x))).length, 0, 'firmware cannot be removed by an app');
  });
  test('native bridge actions are wired without automatic uninstall', () => {
    const calls = []; const bridge = {};
    for (const name of ['scan', 'refresh', 'apps', 'optimize', 'exportReport', 'openApp', 'uninstall']) bridge[name] = (...args) => calls.push([name, ...args]);
    const ui = boot(html, bridge); calls.length = 0;
    ui.id('scan-button').click(); ui.id('refresh-button').click(); ui.id('optimize-button').click(); ui.id('export-button').click(); ui.id('apps-toggle').click();
    assert.deepEqual(calls.map(x => x[0]), ['scan', 'refresh', 'optimize', 'exportReport', 'apps']);
    assert.equal(ui.id('apps-panel').hidden, false);
    assert.equal(ui.id('apps-toggle').getAttribute('aria-expanded'), 'true');
  });
  test('real memory and scan states render with partial update preservation', () => {
    const ui = boot(html, { scan() {} }); ui.window.renderState(fixture());
    assert.equal(text(ui.id('device-model')), 'TV ujian');
    assert.match(text(ui.id('memory-available')), /512\s*MB/); assert.match(text(ui.id('memory-total')), /2[,.]?048\s*MB/);
    assert.match(text(ui.id('scan-status')), /Selesai/); assert.match(text(ui.id('scan-progress')), /12\s*\/\s*12/);
    ui.window.renderState({ message: 'Mesej asli' });
    assert.equal(text(ui.id('device-model')), 'TV ujian'); assert.match(text(ui.id('findings')), /Komponen sistem/);
    ui.window.renderState({ scan: { status: 'running', scanned: 3, total: 20 } });
    assert.equal(ui.id('scan-button').disabled, true); assert.match(text(ui.id('scan-status')), /Mengimbas/);
    ui.window.renderState({ scan: { status: 'error' } }); assert.match(text(ui.id('scan-status')), /gagal/i);
    ui.window.renderState({ scan: { status: 'complete', findings: [] } });
    assert.match(text(ui.id('findings')), /Tiada indikator dikesan/);
    assert.doesNotMatch(text(ui.id('findings')), /peranti selamat|bebas malware/i);
  });
  test('untrusted findings remain text, evidence expands, and sources are safe', () => {
    const ui = boot(html); ui.window.renderState(fixture());
    const all = descendants(ui.id('findings'));
    assert.ok(text(ui.id('findings')).includes('<img src=x onerror=alert(1)>'));
    assert.equal(all.filter(x => ['IMG', 'SCRIPT'].includes(x.tagName)).length, 0);
    assert.ok(all.some(x => x.tagName === 'DETAILS')); assert.ok(all.some(x => x.tagName === 'SUMMARY'));
    const links = all.filter(x => x.tagName === 'A'); assert.equal(links.length, 1);
    assert.equal(links[0].getAttribute('href'), 'https://example.org/report');
    assert.match(text(ui.id('findings')), /javascript:alert\(1\)/);
    assert.match(text(ui.id('limitations')), /Tidak mengesahkan partition sistem/);
  });
  test('package actions guard system apps and keep uninstall explicit', () => {
    const calls = []; const ui = boot(html, { openApp: p => calls.push(['open', p]), uninstall: p => calls.push(['uninstall', p]), apps() {} });
    ui.window.renderState(fixture()); assert.deepEqual(calls, []);
    const buttons = controls(ui.id('findings'));
    assert.equal(buttons.filter(x => text(x) === 'Buang kekal').length, 1);
    buttons.find(x => text(x) === 'Buang kekal').click();
    assert.deepEqual(calls, [['uninstall', 'org.test.app']]);
    buttons.filter(x => text(x) === 'Buka tetapan').at(-1).click();
    assert.deepEqual(calls.at(-1), ['open', 'org.test.system']);
    assert.match(text(ui.id('findings')), /firmware/i);
  });
  test('app inventory search is local and system apps never get delete buttons', () => {
    const ui = boot(html, { apps() {}, openApp() {}, uninstall() {} }); ui.window.renderState(fixture()); ui.id('apps-toggle').click();
    assert.equal(controls(ui.id('apps-list')).filter(x => text(x) === 'Buang kekal').length, 1);
    ui.id('app-search').value = 'Sistem'; ui.id('app-search').dispatch('input');
    assert.match(text(ui.id('apps-list')), /Sistem ujian/); assert.doesNotMatch(text(ui.id('apps-list')), /Aplikasi ujian/);
    assert.equal(controls(ui.id('apps-list')).filter(x => text(x) === 'Buang kekal').length, 0);
    ui.id('app-search').value = 'not-found'; ui.id('app-search').dispatch('input'); assert.match(text(ui.id('apps-list')), /Tiada aplikasi sepadan/);
  });
  test('DPAD arrows move focus but do not steal search field arrows', () => {
    const ui = boot(html, { scan() {}, refresh() {}, optimize() {}, exportReport() {}, apps() {} });
    ui.id('scan-button').focus(); const event = ui.document.dispatch('keydown', { key: 'ArrowDown', target: ui.id('scan-button') });
    assert.notEqual(ui.document.activeElement, ui.id('scan-button')); assert.equal(event.defaultPrevented, true);
    ui.id('app-search').focus(); ui.document.dispatch('keydown', { key: 'ArrowRight', target: ui.id('app-search') });
    assert.equal(ui.document.activeElement, ui.id('app-search'));
  });
  test('native exceptions surface as messages and invalid updates cannot crash rendering', () => {
    const ui = boot(html, { scan() { throw Error('Ditolak oleh Android'); } });
    assert.doesNotThrow(() => ui.id('scan-button').click()); assert.match(text(ui.id('message')), /Ditolak oleh Android/);
    for (const input of [null, undefined, '', [], { scan: null, memory: null }, { scan: { findings: null, limitations: null }, apps: null }]) assert.doesNotThrow(() => ui.window.renderState(input));
    ui.window.renderState({ memory: { total: -1, available: 'bogus' } }); assert.equal(text(ui.id('memory-available')), '—');
  });
}
console.log(`${passed} UI tests passed${process.exitCode ? '; failures present' : ''}.`);
