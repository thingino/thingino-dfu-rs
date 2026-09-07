/**
 * What the page does when the engine or the daemon says no.
 *
 *   npm --prefix web test        (which forces the stub, then runs this)
 *
 * The adapter test next door pins the seam; this pins the half above it, which
 * is where an audit found the page's two live defects: a rejection with
 * no handler at all, and a refusal contradicted by the next line.
 * Both are about what an operator is left looking at, so both are asserted
 * against the log panel and the buttons rather than against a return value.
 *
 * `dom-stub.mjs` installs the browser doubles and must be imported first.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { dom } from './dom-stub.mjs';

/* Remote mode is chosen from localStorage while app.js is loading, so the local
 * tests here set it before the import and the remote one flips it back after. */
localStorage.setItem('tdfu_backend', 'dfu');
localStorage.setItem('tdfu_debug', '1');
localStorage.setItem('tdfu_inject', '0');
localStorage.setItem('tdfu_verify', '0');
localStorage.setItem('tdfu_reboot', '0');

await import('../src/app.js');
await dom.settle();

const BOOTROM = { id: 1, vid: 0xa108, pid: 0xc309, stage: 'bootrom', variant: null };
const GADGET = { id: 2, vid: 0xa108, pid: 0x4d44, stage: 'dfu', variant: null };

/** Loader images for a local bootstrap, and nothing else over fetch. */
function loaderFetch() {
    globalThis.fetch = async () => ({ ok: true, arrayBuffer: async () => new ArrayBuffer(64) });
}

test('a rejected auto-attach says so and hands the controls back', async () => {
    globalThis.__TDFU_STUB__ = {
        devices: [GADGET],
        failWith: 'Usb',
        failMessage: 'Failed to open the device: SecurityError',
    };
    dom.clearLog();

    await dom.usbConnect({ vendorId: 0xa108, productId: 0x4d44 });
    await dom.settle();

    const text = dom.logText();
    assert.match(text, /Auto-attach failed/, 'the failure is in the log panel, not only in devtools');
    assert.match(text, /SecurityError/, "the engine's own message is shown");
    assert.match(text, /\[Usb\]/, 'and its kind');
    assert.ok(
        dom.logLines().some((l) => l.level === 'error'),
        'logged at error, so it is not hidden behind the debug toggle'
    );

    // The state it leaves behind is the point: 'detecting' greys every control.
    assert.notEqual(dom.status(), 'Detecting...');
    assert.equal(dom.status(), 'Error');
    assert.equal(dom.el('btn-connect').disabled, false, 'Connect is live, so the manual pick is one click');
    assert.equal(dom.el('btn-settings').disabled, false);

    delete globalThis.__TDFU_STUB__;
});

test('a bootstrap re-discovers, and works from the new id', async () => {
    const calls = [];
    globalThis.__TDFU_STUB__ = { devices: [BOOTROM], calls };
    loaderFetch();
    dom.clearLog();

    // Attach the bootrom the way the page does: the connect event, then discover.
    await dom.usbConnect({ vendorId: 0xa108, productId: 0xc309 });
    await dom.settle();
    assert.equal(dom.status(), 'Ready');
    assert.deepEqual(
        calls.filter((c) => c[0] === 'detect'),
        [['detect', 1]],
        'the bootrom was detected under the id discover() issued'
    );

    await globalThis.doBootstrap();
    await dom.settle();
    assert.deepEqual(calls.at(-1), ['bootstrap', 1]);

    /* Between the bootstrap and the re-attach the page holds no usable handle:
     * the bootrom is gone and its id with it. An operation now must say there is
     * no device rather than reach for the dead one. */
    calls.length = 0;
    dom.clearLog();
    await globalThis.doDiag();
    await dom.settle();
    assert.deepEqual(calls, [], 'nothing was sent to the id the bootrom used to have');
    assert.match(dom.logText(), /Connect a device first/);

    /* The gadget is a NEW USBDevice, so the engine hands out a new id for it.
     * The page must take that one: an operation against the old id reaches a
     * dead handle for the rest of the session. */
    globalThis.__TDFU_STUB__.devices = [GADGET];
    await dom.usbConnect({ vendorId: 0xa108, productId: 0x4d44 });
    await dom.settle();
    assert.equal(dom.status(), 'Ready');

    calls.length = 0;
    await globalThis.doRead();
    await dom.settle();
    assert.deepEqual(calls, [['read', 2]], 'the read went to the id the second discover issued, not to 1');

    delete globalThis.__TDFU_STUB__;
});

test('a verify mismatch is not reported as a failed download', async () => {
    globalThis.__TDFU_STUB__ = { devices: [GADGET] };
    await dom.usbConnect({ vendorId: 0xa108, productId: 0x4d44 });
    await dom.settle();
    assert.equal(dom.status(), 'Ready');

    globalThis.__TDFU_STUB__ = {
        devices: [GADGET],
        failWith: 'Verify',
        failMessage: 'flash does not match the image at 0x1000',
    };
    dom.clearLog();
    await dom.chooseFirmware(new Uint8Array(2048), 'thingino-t31x.bin');
    await dom.settle(100);

    const text = dom.logText();
    assert.match(text, /DFU verify failed: flash does not match/, 'the prefix names the pass that failed');
    assert.doesNotMatch(text, /DFU write error/, 'the download itself did not fail');
    assert.equal(dom.status(), 'Error');

    delete globalThis.__TDFU_STUB__;
});

test('a refused discover on the daemon stops there', async () => {
    // Remote mode reads its URL from localStorage; saveSettings() is the page's
    // own way in, and applyBackendMode is what a saved change calls.
    localStorage.setItem('tdfu_remote_url', '192.0.2.10:5050');
    dom.el('setting-remote').checked = true;
    dom.el('remote-url').value = '192.0.2.10:5050';
    dom.el('remote-token').value = 'wrong';
    dom.document.querySelectorAll = () => [];
    // saveSettings() reads the checked radio through querySelector.
    const radio = { value: 'remote' };
    const priorQuery = dom.document.querySelector;
    dom.document.querySelector = (sel) =>
        sel === 'input[name="backend-mode"]:checked' ? radio : priorQuery.call(dom.document, sel);
    globalThis.saveSettings();
    dom.document.querySelector = priorQuery;

    let posts = 0;
    globalThis.fetch = async () => {
        posts += 1;
        return { ok: false, status: 403, statusText: 'Forbidden', body: null };
    };

    dom.clearLog();
    await globalThis.connectDevice();
    await dom.settle();

    assert.equal(posts, 1, 'the daemon was asked exactly once');
    const text = dom.logText();
    assert.match(text, /Discover failed: HTTP 403 Forbidden/);
    assert.doesNotMatch(
        text,
        /No Ingenic devices found/,
        'a refusal is not an empty list: the C-inherited fall-through said the opposite of the truth'
    );
    assert.equal(dom.status(), 'Error');
    assert.equal(dom.el('btn-connect').disabled, false, 'Connect is live, so a corrected token can be retried');

    // And the retry is a retry, not a disconnect: the client was dropped.
    dom.clearLog();
    globalThis.fetch = async () => {
        posts += 1;
        return { ok: false, status: 403, statusText: 'Forbidden', body: null };
    };
    await globalThis.connectDevice();
    await dom.settle();
    assert.equal(posts, 2, 'the second Connect asked the daemon again rather than disconnecting');
});

test('a hotplug attaches the arrival, not whatever the list ends with', async () => {
    /* Two authorized cameras of the same model. The engine interns by object
     * identity and appends, so the one that just re-enumerated holds the larger
     * id; getDevices() order is the browser's and carries no such meaning.
     * Taking the last element instead sends every later operation in the session
     * to the other camera. */
    // The daemon test above left the page in remote mode; this one is local.
    const radio = { value: 'dfu' };
    const priorQuery = dom.document.querySelector;
    dom.document.querySelector = (sel) =>
        sel === 'input[name="backend-mode"]:checked' ? radio : priorQuery.call(dom.document, sel);
    globalThis.saveSettings();
    dom.document.querySelector = priorQuery;

    const calls = [];
    globalThis.__TDFU_STUB__ = {
        calls,
        devices: [
            { id: 7, vid: 0xa108, pid: 0x4d44, stage: 'dfu', variant: null },
            { id: 3, vid: 0xa108, pid: 0x4d44, stage: 'dfu', variant: null },
        ],
    };
    dom.clearLog();

    await dom.usbConnect({ vendorId: 0xa108, productId: 0x4d44 });
    await dom.settle();
    assert.equal(dom.status(), 'Ready');

    calls.length = 0;
    await globalThis.doRead();
    await dom.settle();
    assert.deepEqual(calls, [['read', 7]], 'the read went to the camera that arrived');

    delete globalThis.__TDFU_STUB__;
});
