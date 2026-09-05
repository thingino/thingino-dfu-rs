/**
 * The page with no engine at all.
 *
 * A failed `init()` is a one-way state - `tdfu.js` memoises the boot promise, so
 * nothing can un-fail it - which is why this is its own file: `node --test` runs
 * each file in its own process, and the tests next door need an engine.
 *
 * What is pinned here is that the three buttons which merely returned in silence
 * now say why. `connectDevice` already did; Bootstrap, Write and
 * Read did not, so on a page whose footer reads "page <sha>, no engine" they
 * were indistinguishable from a hung flasher.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { dom } from './dom-stub.mjs';

globalThis.__TDFU_STUB__ = { failInit: true };
localStorage.setItem('tdfu_backend', 'dfu');
localStorage.setItem('tdfu_inject', '0');

await import('../src/app.js');
await dom.settle();

test('the page says the engine did not load', () => {
    assert.match(dom.logText(), /Failed to initialize/);
    assert.match(dom.el('version-num').textContent, /no engine/);
});

test('Bootstrap says why it did nothing', async () => {
    dom.clearLog();
    await globalThis.doBootstrap();
    await dom.settle(0);
    assert.deepEqual(dom.logLines(), [{ level: 'warn', text: 'Engine not ready' }]);
});

test('Read says why it did nothing', async () => {
    dom.clearLog();
    await globalThis.doRead();
    await dom.settle(0);
    assert.deepEqual(dom.logLines(), [{ level: 'warn', text: 'Engine not ready' }]);
});

test('Write says why it did nothing', async () => {
    dom.clearLog();
    // Choosing the file is the click: #btn-write only opens the chooser.
    await dom.chooseFirmware(new Uint8Array(512), 'thingino-t31x.bin');
    await dom.settle();
    assert.match(dom.logText(), /Firmware loaded/, 'the file was read');
    assert.ok(
        dom.logLines().some((l) => l.level === 'warn' && l.text === 'Engine not ready'),
        'and the write that followed said why it stopped'
    );
});

test('Connect still says it, as the C did', async () => {
    dom.clearLog();
    await globalThis.connectDevice();
    await dom.settle(0);
    assert.deepEqual(dom.logLines(), [{ level: 'warn', text: 'Engine not ready' }]);
});
