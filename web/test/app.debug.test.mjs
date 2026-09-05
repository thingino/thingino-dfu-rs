/**
 * The debug toggle, the daemon, and where narration ends up on the page.
 *
 *   npm --prefix web test
 *
 * The local backend puts the core's narration on the engine's debug channel and
 * the page renders it at level `debug`, which the toggle gates. Over the daemon
 * the same lines arrive as RESP_DEBUG frames on a response the page asked for
 * with `X-Debug: 1`, and they have to land in the same place: a remote flash
 * with the toggle on used to show none of it.
 *
 * Remote mode is a page-wide state and `app.js` reads it once while loading, so
 * this is its own file: `node --test` gives each file its own process.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { dom } from './dom-stub.mjs';

localStorage.setItem('tdfu_backend', 'remote');
localStorage.setItem('tdfu_remote_url', '192.0.2.10:5050');
localStorage.setItem('tdfu_debug', '1');
localStorage.setItem('tdfu_inject', '0');
localStorage.setItem('tdfu_verify', '0');
localStorage.setItem('tdfu_reboot', '0');

await import('../src/app.js');
await dom.settle();

const MAGIC = 0x54444655;
const RESP_OK = 0x00;
const RESP_DEBUG = 0x04;

/* One response frame, built here rather than imported: `remote.unit.test.mjs`
 * registers tests as it loads, so importing its helpers would run its whole
 * suite a second time in this process. */
function frame(status, body) {
    const payload = typeof body === 'string' ? new TextEncoder().encode(body) : body || new Uint8Array(0);
    const out = new Uint8Array(10 + payload.length);
    const dv = new DataView(out.buffer);
    dv.setUint32(0, MAGIC);
    out[4] = 1; // version
    out[5] = status;
    dv.setUint32(6, payload.length);
    out.set(payload, 10);
    return out;
}

/** One bootrom device, as DISCOVER answers: [bus][addr][vid:2][pid:2][stage][variant]. */
const ONE_BOOTROM = new Uint8Array([1, 2, 0xa1, 0x08, 0xc3, 0x09, 0x00, 0x02]);

/** Answer every POST with `frames`, recording the headers each one carried. */
function scriptDaemon(frames) {
    const seen = { headers: [] };
    globalThis.fetch = async (url, options) => {
        seen.headers.push(options.headers);
        const queue = frames.slice();
        return {
            ok: true,
            status: 200,
            statusText: 'OK',
            body: {
                getReader: () => ({
                    async read() {
                        return queue.length ? { done: false, value: queue.shift() } : { done: true };
                    },
                    cancel() {},
                }),
            },
        };
    };
    return seen;
}

test('the daemon is asked for narration, and it lands in the log at debug', async () => {
    const narration = 'GETSTATUS round 1: state=dfuIDLE poll=5ms';
    const seen = scriptDaemon([frame(RESP_DEBUG, narration + '\n'), frame(RESP_OK, ONE_BOOTROM)]);
    dom.clearLog();

    await globalThis.connectDevice();
    await dom.settle();

    assert.equal(seen.headers[0]['X-Debug'], '1', 'the toggle was on when the client was built');
    assert.ok(
        dom.logLines().some((l) => l.level === 'debug' && l.text === narration),
        'the narration line renders where the local backend renders its own'
    );
    assert.equal(dom.status(), 'Ready', 'and the command it rode in on still succeeded');
});

test('the toggle reaches the client that is already connected', async () => {
    /* The client outlives a toggle flip: it is built on Connect and used until
     * Disconnect, so a page that only passed the state at construction asked for
     * narration for the rest of the session, or never asked at all. */
    const narration = 'claimed alt 0 (flash)';

    globalThis.setDebug(false);
    let seen = scriptDaemon([frame(RESP_DEBUG, narration + '\n'), frame(RESP_OK, 'CPU: T31\n')]);
    dom.clearLog();
    await globalThis.doDiag();
    await dom.settle();

    assert.equal('X-Debug' in seen.headers[0], false, 'the daemon is not asked once the toggle is off');
    assert.equal(
        dom.logLines().some((l) => l.text === narration),
        false,
        'and a line that arrives anyway stays out of the panel'
    );
    assert.equal(dom.el('diag-output').textContent, 'CPU: T31', 'the readout itself still arrived');

    globalThis.setDebug(true);
    seen = scriptDaemon([frame(RESP_DEBUG, narration + '\n'), frame(RESP_OK, 'CPU: T31\n')]);
    dom.clearLog();
    await globalThis.doDiag();
    await dom.settle();

    assert.equal(seen.headers[0]['X-Debug'], '1', 'and it is asked again from the very next command');
    assert.ok(dom.logLines().some((l) => l.level === 'debug' && l.text === narration));
});
