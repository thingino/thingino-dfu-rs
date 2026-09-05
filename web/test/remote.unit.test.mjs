/**
 * `remote.js` against a scripted daemon: the four daemon divergences, pinned.
 *
 *   node --test web/test/remote.unit.test.mjs
 *
 * Nothing else in this repo exercises `remote.js`. `remote.spec.cjs` needs a
 * daemon and a device, so before this file every one of the changes made to
 * it could be deleted with `cargo test`, `npm test` and CI all green.
 * What is scripted here is `fetch`: the responses are real TDFU frames,
 * byte for byte as `crates/tdfu-remote` writes them, so a change to the framing
 * is a failing test rather than a browser that shows nothing.
 *
 * The four:
 *   `unknown` is sent as '' on BOOTSTRAP and unchanged on READ/WRITE
 *   exactly one trailing newline comes off a log frame
 *   a progress frame is drawn with its stage name
 *   an error body is displayed as it was sent, never matched on
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { RemoteClient, DEFAULT_PORT } from '../src/remote.js';

const MAGIC = 0x54444655;
const RESP_OK = 0x00;
const RESP_ERROR = 0x01;
const RESP_PROGRESS = 0x02;
const RESP_LOG = 0x03;

/** One response frame: the 10-byte header the daemon writes, then the body. */
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

/** A RESP_PROGRESS body: [percent][stage][msg_len:2][msg]. */
function progressBody(percent, stage, message) {
    const msg = new TextEncoder().encode(message);
    const body = new Uint8Array(4 + msg.length);
    body[0] = percent;
    body[1] = stage;
    body[2] = (msg.length >> 8) & 0xff;
    body[3] = msg.length & 0xff;
    body.set(msg, 4);
    return body;
}

/**
 * Install a `fetch` that answers with `frames` and records what was posted.
 *
 * Each frame arrives as its own stream chunk, which is what a chunked HTTP
 * response looks like and what `_command`'s reader has to reassemble.
 */
function scriptDaemon(frames, init) {
    const seen = { bodies: [], headers: [], urls: [] };
    globalThis.fetch = async (url, options) => {
        seen.urls.push(url);
        seen.bodies.push(new Uint8Array(options.body));
        seen.headers.push(options.headers);
        const queue = frames.slice();
        return {
            ok: true,
            status: 200,
            statusText: 'OK',
            ...(init || {}),
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
    };
    return seen;
}

/** A client with its two sinks captured. */
function client(resolver) {
    const logs = [];
    const bars = [];
    const c = new RemoteClient(
        (line) => logs.push(line),
        (percent, message, stage) => bars.push([percent, message, stage]),
        resolver || ((v) => (v === 0xff ? 'unknown' : ['t10', 't20', 't21'][v] || 'unknown'))
    );
    return { c, logs, bars };
}

/** A posted frame's payload, past the 10-byte command header. */
function payloadOf(frameBytes) {
    return frameBytes.subarray(10);
}

/** The variant field of a BOOTSTRAP / READ / WRITE payload: [idx][len][name]. */
function sentVariant(frameBytes) {
    const p = payloadOf(frameBytes);
    return new TextDecoder().decode(p.subarray(2, 2 + p[1]));
}

test('the default port is the daemon\'s', () => {
    assert.equal(DEFAULT_PORT, 5050);
});

test('a log frame loses exactly one newline, and only its own', async () => {
    scriptDaemon([
        frame(RESP_LOG, 'bootstrap: uploading stage 1\n'),
        frame(RESP_LOG, 'a note, then a blank line\n\n'),
        frame(RESP_LOG, 'no terminator at all'),
        frame(RESP_OK, new Uint8Array(0)),
    ]);
    const { c, logs } = client();
    await c.connect('192.0.2.10:5050', '');
    await c.reboot(0);

    assert.deepEqual(logs, [
        'bootstrap: uploading stage 1',
        'a note, then a blank line\n',
        'no terminator at all',
    ]);
});

test('a progress frame is drawn with its stage', async () => {
    scriptDaemon([
        frame(RESP_PROGRESS, progressBody(0, 3, '0 / 16777216 bytes')),
        frame(RESP_PROGRESS, progressBody(50, 6, '8388608 / 16777216 bytes')),
        // Stage 0 is Phase::Unknown, which renders with no prefix at all.
        frame(RESP_PROGRESS, progressBody(99, 0, 'nearly there')),
        // A stage this client is too old to know still shows its message.
        frame(RESP_PROGRESS, progressBody(100, 200, 'from a newer daemon')),
        frame(RESP_OK, new Uint8Array(0)),
    ]);
    const { c, bars } = client();
    await c.connect('192.0.2.10:5050', '');
    await c.reboot(0);

    assert.deepEqual(bars, [
        [0, 'download: 0 / 16777216 bytes', 'download'],
        [50, 'verify: 8388608 / 16777216 bytes', 'verify'],
        [99, 'nearly there', ''],
        [100, 'from a newer daemon', ''],
    ]);
});

test('an error body reaches the user as it was sent', async () => {
    const detail = 'invalid input: variant "t99": unknown SoC, see --cpu';
    scriptDaemon([frame(RESP_ERROR, detail + '\n')]);
    const { c, logs } = client();
    await c.connect('192.0.2.10:5050', '');

    assert.equal(await c.bootstrap(0, 't31x', null, null), false, 'an ERROR frame is a failed command');
    assert.deepEqual(logs, ['ERROR: ' + detail], 'shown whole, never matched on');
});

test('an empty error body still says something', async () => {
    scriptDaemon([frame(RESP_ERROR, new Uint8Array(0))]);
    const { c, logs } = client();
    await c.connect('192.0.2.10:5050', '');
    await c.reboot(0);
    assert.deepEqual(logs, ['ERROR: unknown error']);
});

test('BOOTSTRAP turns "unknown" into auto-detect; READ and WRITE do not', async () => {
    const ok = () => [frame(RESP_OK, new Uint8Array(0))];

    let seen = scriptDaemon(ok());
    let { c } = client();
    await c.connect('192.0.2.10:5050', '');
    await c.bootstrap(3, 'unknown', null, null);
    assert.equal(sentVariant(seen.bodies[0]), '', 'the daemon is asked to detect it, not refused over --cpu');
    assert.equal(payloadOf(seen.bodies[0])[0], 3, 'and the device index rides in front of it');

    seen = scriptDaemon(ok());
    ({ c } = client());
    await c.connect('192.0.2.10:5050', '');
    await c.bootstrap(0, 't31x', null, null);
    assert.equal(sentVariant(seen.bodies[0]), 't31x', 'a name the daemon knows is sent as it stands');

    // READ answers data + a CRC32; the payload only has to survive the check.
    const data = new Uint8Array([1, 2, 3, 4]);
    const body = new Uint8Array(8);
    body.set(data, 0);
    new DataView(body.buffer).setUint32(4, 0xb63cfbcd); // crc32 of 01 02 03 04
    seen = scriptDaemon([frame(RESP_OK, body)]);
    ({ c } = client());
    await c.connect('192.0.2.10:5050', '');
    assert.deepEqual(await c.readFirmware(0, 'unknown'), data);
    assert.equal(sentVariant(seen.bodies[0]), 'unknown', 'READ sends the field unchanged: the daemon ignores it');

    seen = scriptDaemon(ok());
    ({ c } = client());
    await c.connect('192.0.2.10:5050', '');
    await c.writeFirmware(0, 'unknown', new Uint8Array(16), true);
    assert.equal(sentVariant(seen.bodies[0]), 'unknown', 'and so does WRITE');
});

test('a wrong token reaches the caller as the HTTP status', async () => {
    globalThis.fetch = async () => ({ ok: false, status: 403, statusText: 'Forbidden', body: null });
    const { c } = client();
    await c.connect('192.0.2.10:5050', 'wrong');
    await assert.rejects(c.discover(), /HTTP 403 Forbidden/);
});

test('the token rides in the header and the frame is the daemon\'s', async () => {
    const seen = scriptDaemon([frame(RESP_OK, new Uint8Array([1, 2, 0xa1, 0x08, 0xc3, 0x09, 0x00, 0x02]))]);
    const { c } = client();
    await c.connect('camera.example:5050', 's3cret');

    const devices = await c.discover();
    assert.equal(seen.urls[0], 'http://camera.example:5050');
    assert.equal(seen.headers[0]['X-Auth-Token'], 's3cret');

    const sent = seen.bodies[0];
    assert.equal(new DataView(sent.buffer).getUint32(0), MAGIC);
    assert.equal(sent[4], 1, 'protocol version');
    assert.equal(sent[5], 0x01, 'CMD_DISCOVER');
    assert.equal(new DataView(sent.buffer).getUint32(6), 0, 'no payload');

    assert.deepEqual(devices, [
        {
            bus: 1,
            address: 2,
            vendor: 0xa108,
            product: 0xc309,
            stage: 0,
            variant: 2,
            variantName: 't21',
            stageName: 'bootrom',
        },
    ]);
});

test('an unbracketed IPv6 literal is bracketed before it is parsed', async () => {
    const seen = scriptDaemon([frame(RESP_OK, new Uint8Array(0))]);
    const { c } = client();
    await c.connect('2001:db8::10', '');
    await c.reboot(0);
    assert.equal(seen.urls[0], 'http://[2001:db8::10]');
});

/** A header declaring `plen` bytes of payload, with nothing behind it. */
function oversizedHeader(plen) {
    const out = new Uint8Array(10);
    const dv = new DataView(out.buffer);
    dv.setUint32(0, MAGIC);
    out[4] = 1;
    out[5] = RESP_OK;
    dv.setUint32(6, plen);
    return out;
}

test('a frame that declares more than the protocol carries is refused unread', async () => {
    /* The daemon URL is free text in Settings, so the four length bytes come off
     * a socket the page cannot vouch for. Without a cap the reader pumps every
     * chunk into the queue until the declared length is reached, which for
     * 0xFFFFFFFF is the renderer being killed. */
    let chunks = 0;
    globalThis.fetch = async () => ({
        ok: true,
        status: 200,
        body: {
            getReader: () => ({
                async read() {
                    chunks += 1;
                    return { done: false, value: chunks === 1 ? oversizedHeader(0xffffffff) : new Uint8Array(1 << 20) };
                },
                cancel() {},
            }),
        },
    });

    const { c } = client();
    await c.connect('192.0.2.10:5050', '');
    await assert.rejects(() => c.reboot(0), /over the .* protocol maximum/);
    assert.equal(chunks, 1, 'not one byte of the declared payload was buffered');
});

test('a refusal is not a success and not an empty bus', async () => {
    scriptDaemon([frame(RESP_ERROR, 'device 0 is busy')]);
    let { c } = client();
    await c.connect('192.0.2.10:5050', '');
    assert.equal(await c.reboot(0), false, 'a refused reboot must not read as one that happened');

    scriptDaemon([frame(RESP_ERROR, 'unauthorized')]);
    ({ c } = client());
    await c.connect('192.0.2.10:5050', '');
    assert.equal(await c.discover(), null, 'a refused listing is not a bus with no devices on it');
});
