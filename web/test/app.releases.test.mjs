/**
 * The release picker, against the device that is actually attached.
 *
 *   npm --prefix web test        (which forces the stub, then runs this)
 *
 * Two rules are pinned here, because between them they decide what gets written
 * to a camera's flash from one click:
 *
 *   - an image built for another SoC is not flashable at this device, however
 *     the selection came to be there;
 *   - an image whose published sha256sum could not be read is not flashed.
 *
 * Both are asserted against what an operator sees (the log panel, the Flash
 * button) and against what reached the engine (the stub's call list), not
 * against a return value.
 *
 * `dom-stub.mjs` installs the browser doubles and must be imported first.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { dom } from './dom-stub.mjs';

localStorage.setItem('tdfu_backend', 'dfu');
localStorage.setItem('tdfu_releases', '1');
localStorage.setItem('tdfu_inject', '0');
localStorage.setItem('tdfu_verify', '0');
localStorage.setItem('tdfu_reboot', '0');

await import('../src/app.js');
await dom.settle();

const TAG = 'master-2026-09-01';
const T31_IMAGE = 'thingino-wyze_cp1_t31x_sc2336_atbm6031.bin';
const T20_IMAGE = 'thingino-jooan_a5_t20n_jxf22_rtl8189ftv.bin';

const T31_BOOTROM = { id: 1, vid: 0xa108, pid: 0xc309, stage: 'bootrom', variant: 't31x', chip: 'T31X' };
const T20_BOOTROM = { id: 2, vid: 0xa108, pid: 0xc309, stage: 'bootrom', variant: 't20n', chip: 'T20N' };

/** What the page reads out of the GitHub releases API, and nothing else. */
const RELEASES = [
    {
        tag_name: TAG,
        draft: false,
        prerelease: false,
        published_at: '2026-09-01T00:00:00Z',
        assets: [{ name: T31_IMAGE }, { name: T20_IMAGE }],
    },
];

/** A fetch double that records every URL and answers by what is being asked for. */
function stubFetch(routes) {
    const seen = [];
    globalThis.fetch = async (url) => {
        seen.push(String(url));
        for (const [match, answer] of routes) {
            if (String(url).includes(match)) return answer(String(url));
        }
        return { ok: false, status: 404, statusText: 'Not Found' };
    };
    return seen;
}

/** A Response-shaped answer whose body streams `bytes` back in one chunk. */
function bodyOf(bytes) {
    let sent = false;
    return {
        ok: true,
        status: 200,
        headers: { get: () => String(bytes.length) },
        body: {
            getReader: () => ({
                read: async () => (sent ? { done: true } : ((sent = true), { done: false, value: bytes })),
            }),
        },
    };
}

const releasesRoute = [
    'api.github.com',
    () => ({ ok: true, status: 200, json: async () => RELEASES }),
];
/** Loader images for a local bootstrap. */
const loaderRoute = ['firmware/dfu/', () => ({ ok: true, arrayBuffer: async () => new ArrayBuffer(64) })];

/** Open the release panel and list its releases (the panel starts collapsed). */
async function loadReleasePanel() {
    globalThis.toggleReleases();
    globalThis.toggleReleases();
    await dom.settle();
}

/** Pick a release and then an image, exactly as the two <select>s do. */
function pick(image) {
    dom.el('rel-release').value = TAG;
    globalThis.releaseChanged();
    const dev = dom.el('rel-device');
    dev.value = image;
    dev.onchange();
    return dev;
}

test('an image for another SoC is neither listed, nor selectable, nor flashable', async () => {
    globalThis.__TDFU_STUB__ = { devices: [T31_BOOTROM] };
    stubFetch([releasesRoute]);

    await dom.usbConnect({ vendorId: 0xa108, productId: 0xc309 });
    await dom.settle();
    assert.equal(dom.status(), 'Ready');

    await loadReleasePanel();
    pick(T31_IMAGE);
    assert.equal(dom.el('rel-flash').disabled, false, 'the T31 image fits the T31 that is attached');

    /* The device is swapped for another SoC. Nothing but this re-runs the
     * filter: before it did, the list kept the T31 image, the connect
     * re-enabled Flash, and one click wrote a T31 image onto a T20. */
    dom.clearLog();
    globalThis.__TDFU_STUB__ = { devices: [T20_BOOTROM] };
    await dom.usbConnect({ vendorId: 0xa108, productId: 0xc309 });
    await dom.settle();
    assert.equal(dom.status(), 'Ready');

    const dev = dom.el('rel-device');
    assert.equal(dev.value, '', 'the selection made for the T31 was dropped');
    assert.equal(dom.el('rel-flash').disabled, true, 'and Flash is not live on nothing');
    assert.deepEqual(
        dev.children.map((o) => o.value).filter(Boolean),
        [T20_IMAGE],
        'the list is the attached T20 device, not the release'
    );

    /* "Show all devices" puts the whole release back in the list. Selecting the
     * wrong SoC there still cannot be flashed at this device. */
    dom.el('rel-all').checked = true;
    globalThis.releaseChanged();
    dev.value = T31_IMAGE;
    dev.onchange();
    assert.equal(dom.el('rel-flash').disabled, true, 'a mismatched selection does not arm Flash');

    /* And the click itself refuses, naming both, before a byte is fetched. */
    dom.clearLog();
    const seen = stubFetch([releasesRoute, loaderRoute]);
    await globalThis.flashFromRelease();
    await dom.settle();
    const text = dom.logText();
    assert.match(text, /Refusing to flash/);
    assert.match(text, /T31X/, 'the message names what the image is built for');
    assert.match(text, /T20N/, 'and what is attached');
    assert.equal(
        seen.filter((u) => u.includes('workers.dev')).length,
        0,
        'nothing was downloaded for an image that cannot be flashed here'
    );

    dom.el('rel-all').checked = false;
    delete globalThis.__TDFU_STUB__;
});

test('an image whose sha256sum cannot be read is not flashed', async () => {
    const calls = [];
    globalThis.__TDFU_STUB__ = { devices: [T31_BOOTROM], calls };
    stubFetch([releasesRoute]);

    await dom.usbConnect({ vendorId: 0xa108, productId: 0xc309 });
    await dom.settle();
    await loadReleasePanel();
    pick(T31_IMAGE);
    assert.equal(dom.el('rel-flash').disabled, false);

    /* The image downloads; the sums request next to it does not. That is the
     * fault the check exists for, so it must refuse rather than shrug. */
    const image = new Uint8Array(4096);
    stubFetch([
        releasesRoute,
        loaderRoute,
        ['.sha256sum', () => ({ ok: false, status: 502, statusText: 'Bad Gateway' })],
        ['workers.dev', () => bodyOf(image)],
    ]);

    dom.clearLog();
    calls.length = 0;
    await globalThis.flashFromRelease();
    await dom.settle();

    const text = dom.logText();
    assert.match(text, /NOT verified/, 'the log says the image was not verified, not that a check was skipped');
    assert.ok(
        dom.logLines().some((l) => l.level === 'error'),
        'at error, so it is not a warn line under a running download'
    );
    assert.deepEqual(
        calls.filter((c) => c[0] === 'write' || c[0] === 'bootstrap'),
        [],
        'nothing was written and nothing was bootstrapped for it'
    );

    delete globalThis.__TDFU_STUB__;
});
