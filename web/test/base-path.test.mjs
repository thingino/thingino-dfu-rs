/**
 * The page under a base path.
 *
 * A GitHub Pages project site serves from `https://<user>.github.io/<repo>/`,
 * which `vite.config.js` has always supported through PAGES_BASE, while two
 * files went on hard-coding the site root: the overlay injectors' import URL and
 * the service worker's revalidation match. Under a base path the first 404s (the
 * whole Pre-configure panel fails) and the second matches nothing (the
 * injectors, which are not content-hashed, stay on whatever the HTTP cache
 * holds). Both are byte-identical to the C's, so this is a deliberate divergence
 * and these are the pins for it.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';

import { wasmBaseFor, wasmBase, setWasmBase } from '../src/inject.js';

test('the injector base follows the page base', () => {
    assert.equal(wasmBaseFor('/'), '/wasm/', 'root hosting, the default');
    assert.equal(wasmBaseFor('/thingino-dfu-rs/'), '/thingino-dfu-rs/wasm/');
    assert.equal(wasmBaseFor('/deep/path/'), '/deep/path/wasm/');
    assert.equal(wasmBaseFor('/no-slash'), '/no-slash/wasm/', 'a base without its trailing slash still works');
});

test('outside a vite build the root is the answer', () => {
    // import.meta.env does not exist under node, which is where this test runs.
    assert.equal(wasmBase(), '/wasm/');
    assert.equal(wasmBaseFor(undefined), '/wasm/');
    assert.equal(wasmBaseFor(''), '/wasm/');
});

test('setWasmBase still overrides it', () => {
    setWasmBase('https://example.invalid/w/');
    assert.equal(wasmBase(), 'https://example.invalid/w/');
    setWasmBase('/wasm/');
});

test('inject.js reads the base vite substitutes, not a constant', async () => {
    const source = await readFile(new URL('../src/inject.js', import.meta.url), 'utf8');
    assert.match(source, /import\.meta\.env(\s|&)/, 'the wiring vite replaces at build time is still there');
});

/** Run public/sw.js with a fake worker global at `swPath`, and return its listeners. */
async function loadServiceWorker(swPath) {
    const source = await readFile(new URL('../public/sw.js', import.meta.url), 'utf8');
    const listeners = {};
    const self = {
        location: { pathname: swPath, origin: 'https://example.invalid' },
        addEventListener: (type, fn) => {
            listeners[type] = fn;
        },
        skipWaiting() {},
        clients: { claim() {} },
    };
    vm.createContext(self);
    self.self = self;
    self.URL = URL;
    self.fetch = async () => ({ ok: true });
    vm.runInContext(source, self, { filename: 'sw.js' });
    return listeners;
}

/** Which URLs the worker takes over, for a plain (non-navigation) request. */
function revalidated(listeners, urls) {
    const taken = [];
    for (const url of urls) {
        let handled = false;
        listeners.fetch({
            request: { url, mode: 'no-cors' },
            respondWith() {
                handled = true;
            },
        });
        if (handled) taken.push(url);
    }
    return taken;
}

test('the service worker revalidates /wasm/ at the root', async () => {
    const listeners = await loadServiceWorker('/sw.js');
    assert.deepEqual(
        revalidated(listeners, [
            'https://example.invalid/wasm/mkfs_jffs2_memfs.mjs',
            'https://example.invalid/assets/index-abc123.js',
            'https://example.invalid/elsewhere/wasm/x.mjs',
        ]),
        ['https://example.invalid/wasm/mkfs_jffs2_memfs.mjs']
    );
});

test('and under a project-site base path', async () => {
    const listeners = await loadServiceWorker('/thingino-dfu-rs/sw.js');
    assert.deepEqual(
        revalidated(listeners, [
            'https://example.invalid/thingino-dfu-rs/wasm/ubinize_memfs.mjs',
            // The old hard-coded match: right at the root, wrong here.
            'https://example.invalid/wasm/ubinize_memfs.mjs',
            'https://example.invalid/thingino-dfu-rs/assets/index-abc123.js',
        ]),
        ['https://example.invalid/thingino-dfu-rs/wasm/ubinize_memfs.mjs']
    );
});

test('a navigation is network-first wherever the page lives', async () => {
    const listeners = await loadServiceWorker('/thingino-dfu-rs/sw.js');
    let handled = false;
    listeners.fetch({
        request: { url: 'https://example.invalid/thingino-dfu-rs/', mode: 'navigate' },
        respondWith() {
            handled = true;
        },
    });
    assert.equal(handled, true);
});
