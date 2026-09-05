/**
 * The adapter over the seam, against the hand-made stub of it.
 *
 *   npm --prefix web test        (which forces the stub, then runs this)
 *
 * `--force` is not optional on a built checkout: `cargo xtask web` leaves the
 * real glue there, the stub refuses to replace it without being told to, and the
 * real glue's `init()` fetches its `.wasm` over `file:`, which Node answers with
 * `TypeError: fetch failed`. Forcing the stub also deletes that
 * wasm, so nothing here can leave a half-real tree behind; the next
 * `cargo xtask web` writes both again.
 *
 * This is not a test of the engine - it cannot be, there is no engine here. It
 * pins the page's half of it: the ordinal table reaching the page, `0xFF` reading
 * as `unknown`, log and progress frames arriving at
 * the page's own sinks, and every operation rejecting rather than throwing
 * before the engine is up.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import * as tdfu from '../src/tdfu.js';
import { wireVariantNames } from './make-seam-stub.mjs';

test('an operation before init rejects, and does not throw', async () => {
    const p = tdfu.discover();
    assert.ok(p instanceof Promise, 'nothing throws synchronously');
    await assert.rejects(p, /not loaded/);
    assert.equal(tdfu.isReady(), false);
    assert.equal(tdfu.version(), 'dev');
});

test('init wires the sinks and exposes the frozen ordinal table', async () => {
    const logs = [];
    const bars = [];
    const banner = await tdfu.initTdfu({
        log: (line, level) => logs.push([line, level]),
        progress: (phase, done, total) => bars.push([phase, done, total]),
    });

    assert.match(banner, /stub/);
    assert.equal(tdfu.isReady(), true);

    /* The whole table against the wire table's own source, not against the copy
     * that produced it. Appending a 60th loader to variant.rs used
     * to leave every assertion here green while the page rendered ordinal 59 as
     * `unknown`, because the stub's hand transcription and this test's literals
     * were the same transcription read twice. */
    const names = tdfu.variantNames();
    const wire = await wireVariantNames(new URL('../../crates/tdfu-proto/src/variant.rs', import.meta.url).pathname);
    assert.deepEqual(names, wire, 'the ordinal table is WireVariant::NAMES, entry for entry');

    // Three ordinals as literals, from the frozen table itself: a change to both
    // the Rust and the check above still has to explain these.
    assert.equal(names.length, 59, 'the table is 59 entries');
    assert.equal(names[0], 't10');
    assert.equal(names[6], 't31x');
    assert.equal(names[58], 'a1n');

    // 0xFF is outside the table on purpose, so that a daemon which
    // does not know a device's SoC says so instead of guessing t31x.
    assert.equal(tdfu.variantName(0xff), 'unknown');
    assert.equal(tdfu.variantName(58), 'a1n');
    assert.equal(tdfu.variantName(200), 'unknown');

    tdfu.setDebug(true);
    assert.deepEqual(logs.at(-1), ['debug logging on', 'debug']);
    tdfu.setDebug(false);

    globalThis.__TDFU_STUB__ = { devices: [{ id: 1, vid: 0xa108, pid: 0xc309, stage: 'dfu', variant: null }] };

    const devices = await tdfu.discover();
    assert.equal(devices.length, 1);
    assert.equal(devices[0].id, 1);

    logs.length = 0;
    bars.length = 0;
    await tdfu.write(1, { image: new Uint8Array(1024), verify: true });

    assert.ok(bars.length > 0, 'progress frames reach the page');
    assert.deepEqual(bars[0], ['download', 0, 1024]);
    assert.deepEqual(bars.at(-1), ['verify', 1024, 1024]);
    assert.deepEqual(logs.map((l) => l[1]), ['info', 'info']);
    assert.match(logs[0][0], /download complete/);
    assert.match(logs[1][0], /Verify OK/);
});

test('an engine failure rejects with the seam error shape', async () => {
    await tdfu.initTdfu();
    globalThis.__TDFU_STUB__ = { devices: [], failWith: 'NotDfu', failMessage: 'device 0 is not in DFU mode' };
    await assert.rejects(tdfu.read(0, {}), (e) => {
        assert.equal(e.kind, 'NotDfu');
        assert.equal(e.recoverable, false);
        assert.equal(e.message, 'device 0 is not in DFU mode');
        return true;
    });
    delete globalThis.__TDFU_STUB__;
});
