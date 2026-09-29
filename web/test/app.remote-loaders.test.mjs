/**
 * A remote bootstrap sends the page's own loader pair only to a daemon that has
 * none of its own - the ESP32 backpack - and the variant alone to one with a
 * tree, as before.
 *
 *   npm --prefix web test        (which forces the stub, then runs this)
 *
 * `fetch` is the daemon here, routed by the command byte of each POST, plus the
 * page's own `firmware/dfu/...` files for the loader pair it would send.
 * `dom-stub.mjs` installs the browser doubles and must be imported first.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { dom } from './dom-stub.mjs';

localStorage.setItem('tdfu_backend', 'remote');
localStorage.setItem('tdfu_remote_url', '192.0.2.10:5050');
localStorage.setItem('tdfu_debug', '0');
localStorage.setItem('tdfu_verify', '0');
localStorage.setItem('tdfu_reboot', '0');

await import('../src/app.js');
await dom.settle();
const { variantNames } = await import('../src/tdfu.js');
const T31X = variantNames().indexOf('t31x');

const MAGIC = 0x54444655;
const CMD_DISCOVER = 0x01;
const CMD_BOOTSTRAP = 0x02;
const CMD_INFO = 0x0a;

/** One response frame: the 10-byte header the daemon writes, then the body. */
function frame(status, body) {
    const payload = typeof body === 'string' ? new TextEncoder().encode(body) : body;
    const out = new Uint8Array(10 + payload.length);
    const dv = new DataView(out.buffer);
    dv.setUint32(0, MAGIC);
    out[4] = 1;
    out[5] = status;
    dv.setUint32(6, payload.length);
    out.set(payload, 10);
    return out;
}

/** A streamed HTTP answer carrying `frames`. */
function answer(frames) {
    const queue = frames.slice();
    return {
        ok: true,
        status: 200,
        statusText: 'OK',
        body: {
            getReader() {
                return {
                    async read() {
                        return queue.length ? { done: false, value: queue.shift() } : { done: true };
                    },
                    cancel() {},
                };
            },
        },
    };
}

/** A DISCOVER row: bus, address, VID, PID, stage, variant ordinal. */
function row(address, stage, variant) {
    return new Uint8Array([1, address, 0xa1, 0x08, 0xc3, 0x09, stage, variant]);
}

/**
 * The daemon: a T31X in the bootrom, then the gadget it comes back as, and
 * `info` as its answer to CMD_INFO. Records every command and every loader file
 * the page fetched.
 */
function daemon(info, variant) {
    const seen = { commands: [], files: [] };
    let discovers = 0;
    globalThis.fetch = async (url, options) => {
        if (typeof url === 'string' && url.startsWith('firmware/dfu/')) {
            seen.files.push(url);
            const bytes = new TextEncoder().encode('page:' + url.split('/').pop());
            return { ok: true, status: 200, arrayBuffer: async () => bytes.buffer };
        }
        const body = new Uint8Array(options.body);
        seen.commands.push([body[5], body.subarray(10)]);
        if (body[5] === CMD_DISCOVER) {
            discovers += 1;
            return answer([frame(0, discovers === 1 ? row(7, 0, variant) : row(8, 2, 0xff))]);
        }
        if (body[5] === CMD_INFO) return answer(info);
        if (body[5] === CMD_BOOTSTRAP) return answer([frame(0, 'OK')]);
        return answer([frame(1, 'unexpected command ' + body[5])]);
    };
    return seen;
}

/** Connect to the daemon afresh: a connected page's Connect disconnects first. */
async function connect() {
    dom.clearLog();
    await globalThis.connectDevice();
    await dom.settle();
    if (/Disconnected from daemon/.test(dom.logText())) {
        await globalThis.connectDevice();
        await dom.settle();
    }
}

/** The loader pair a BOOTSTRAP payload carries, or null: [idx][vlen][variant][spl][uboot]. */
function pairOf(payload) {
    let at = 2 + payload[1];
    if (at === payload.length) return null;
    const dv = new DataView(payload.buffer, payload.byteOffset, payload.length);
    const text = (n) => {
        const out = new TextDecoder().decode(payload.subarray(at + 4, at + 4 + n));
        at += 4 + n;
        return out;
    };
    const spl = text(dv.getUint32(at));
    const uboot = text(dv.getUint32(at));
    return { spl, uboot };
}

function bootstrapOf(seen) {
    const found = seen.commands.find(([command]) => command === CMD_BOOTSTRAP);
    return found ? found[1] : null;
}

test('a daemon with no loaders of its own is sent the page\'s pair', async () => {
    const seen = daemon([frame(0, 'version=2.0.1\nloaders=none\n')], T31X);
    await connect();
    await globalThis.doBootstrap();
    await dom.settle();

    const payload = bootstrapOf(seen);
    assert.ok(payload, 'the bootstrap went out');
    assert.deepEqual(pairOf(payload), { spl: 'page:tpl.bin', uboot: 'page:uboot.bin' });
    assert.deepEqual(seen.files, ['firmware/dfu/t31x/tpl.bin', 'firmware/dfu/t31x/uboot.bin']);
    assert.match(dom.logText(), /has no loaders of its own; sending this page's t31x pair/);
});

test('a daemon with a tree is sent the variant alone', async () => {
    const seen = daemon([frame(0, 'version=2.0.1\nloaders=tree\n')], T31X);
    await connect();
    await globalThis.doBootstrap();
    await dom.settle();

    const payload = bootstrapOf(seen);
    assert.ok(payload, 'the bootstrap went out');
    assert.equal(pairOf(payload), null, 'no pair: the daemon loads its own');
    assert.deepEqual(seen.files, [], 'and the page fetched none');
});

test('a daemon that predates the question is sent the variant alone, and no error is shown', async () => {
    const seen = daemon([frame(1, 'unknown command')], T31X);
    await connect();
    await globalThis.doBootstrap();
    await dom.settle();

    assert.equal(pairOf(bootstrapOf(seen)), null);
    assert.doesNotMatch(dom.logText(), /ERROR: unknown command/);
});

test('a pair chosen under Advanced is sent without asking', async () => {
    const seen = daemon([frame(0, 'loaders=none\n')], T31X);
    await connect();
    const file = (name) => ({ name, arrayBuffer: async () => new TextEncoder().encode('custom:' + name).buffer });
    globalThis.customSplSelected({ files: [file('my-spl.bin')] });
    globalThis.customUbootSelected({ files: [file('my-uboot.bin')] });
    await dom.settle();
    await globalThis.doBootstrap();
    await dom.settle();
    globalThis.clearCustomBootloader();

    assert.deepEqual(pairOf(bootstrapOf(seen)), { spl: 'custom:my-spl.bin', uboot: 'custom:my-uboot.bin' });
    assert.ok(!seen.commands.some(([command]) => command === CMD_INFO), 'the daemon was not asked');
});

test('with no loaders on the daemon and an SoC nobody named, nothing is sent', async () => {
    const seen = daemon([frame(0, 'loaders=none\n')], 0xff);
    await connect();
    await globalThis.doBootstrap();
    await dom.settle();

    assert.equal(bootstrapOf(seen), null, 'no bootstrap went out');
    assert.match(dom.logText(), /Remote bootstrap failed: .*Choose the SPL and U-Boot under Advanced/);
    assert.equal(dom.status(), 'Error');
});
