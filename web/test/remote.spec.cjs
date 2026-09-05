#!/usr/bin/env node
/**
 * The flasher in remote mode, in headless Chromium, against a running daemon.
 *
 * This is the browser half of the daemon check, as a script rather than as a
 * driver written from scratch each time. It serves `web/dist` locally, puts the
 * page into remote mode
 * through localStorage, and drives the real buttons: Connect, Read, and Write
 * with verify. Nothing is stubbed - the daemon does the USB work.
 *
 *   TDFU_DAEMON=<host:port> node web/test/remote.spec.cjs
 *
 * With no TDFU_DAEMON it says why and exits 0, so CI is unaffected. A daemon
 * with no device attached exits 0 too, as SKIPPED (transport only): discover was
 * proven and the read and write legs were not, which is not the same as PASSED.
 *
 * Environment:
 *   TDFU_DAEMON     host:port of the daemon. Required, or this skips.
 *   TDFU_TOKEN      the daemon's --token, if it has one.
 *   TDFU_IMAGE      an image to write. Default: write back exactly what the
 *                   read step just pulled off the chip, which is a real write
 *                   of the device's own content.
 *   TDFU_BOOTSTRAP  =1 to click Bootstrap when the device is still a bootrom.
 *                   Off by default: a hardware run bootstraps with the CLI first.
 *   TDFU_HEADED     =1 to watch it.
 *   NODE_PATH       must contain `playwright`. There is no path baked in here.
 *
 * Two traps this script exists to stop anyone rediscovering:
 *
 *   1. **The Write button only opens the file chooser.** The write itself starts
 *      from the file input's change handler, so choosing the file IS the click.
 *      Clicking Write and then waiting for a button to enable times out, and a
 *      browser closed at that moment kills a download that is already running.
 *   2. **The daemon must not be on loopback.** Chrome refuses `remote.js`'s
 *      `fetch({targetAddressSpace: 'local'})` against 127.0.0.1, so point this
 *      at the daemon's private-network address - which is where it lives anyway.
 */

'use strict';

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

const DAEMON = process.env.TDFU_DAEMON || '';
const DIST = path.join(__dirname, '..', 'dist');

/* A read of a 16 MiB chip is about 11 s and a write with verify about 42 s on
 * the bench, so these are minutes, not seconds. A hung transfer should fail the
 * run, not sit there. */
const OP_TIMEOUT = 10 * 60 * 1000;
const CONNECT_TIMEOUT = 60 * 1000;

const MIME = {
    '.html': 'text/html; charset=utf-8',
    '.js': 'text/javascript; charset=utf-8',
    '.mjs': 'text/javascript; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.wasm': 'application/wasm',
    '.json': 'application/json',
    '.svg': 'image/svg+xml',
    '.ico': 'image/x-icon',
    '.woff': 'font/woff',
    '.woff2': 'font/woff2',
    '.bin': 'application/octet-stream',
};

function skip(why) {
    console.log('remote.spec: SKIPPED - ' + why);
    process.exit(0);
}

/* A run that proved something, but not the read and write legs it exists for.
 *
 * This is a distinct word on purpose. "PASSED (discover only)" gets pasted into
 * a results table as PASSED, and the read and write legs this script exists for
 * are exactly the ones that did not run. The exit code stays 0: a daemon
 * with no device attached is a legitimate transport check, not a failure.
 *
 * Thrown rather than returned, so the browser and the server are still closed on
 * the way out: an early `return` from inside the try would skip everything after
 * the cleanup, which is where the verdict is printed. */
class Partial extends Error {}

function partial(what) {
    console.log('remote.spec: SKIPPED (transport only) - ' + what);
    process.exit(0);
}

function fail(why) {
    console.error('remote.spec: FAILED - ' + why);
    process.exit(1);
}

/** Serve `dist` read-only on an ephemeral loopback port. */
function serve(root) {
    const server = http.createServer((req, res) => {
        const url = new URL(req.url, 'http://localhost');
        let file = path.join(root, decodeURIComponent(url.pathname));
        // No traversal out of dist, and a directory means its index.
        if (!path.resolve(file).startsWith(path.resolve(root))) {
            res.writeHead(403).end();
            return;
        }
        try {
            if (fs.statSync(file).isDirectory()) file = path.join(file, 'index.html');
        } catch {
            res.writeHead(404).end();
            return;
        }
        let body;
        try {
            body = fs.readFileSync(file);
        } catch {
            res.writeHead(404).end();
            return;
        }
        res.writeHead(200, {
            'Content-Type': MIME[path.extname(file)] || 'application/octet-stream',
            'Cache-Control': 'no-store',
        });
        res.end(body);
    });
    return new Promise((resolve) => {
        server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port }));
    });
}

/** Everything the page has logged, oldest first. */
async function logLines(page) {
    return page.$$eval('#log div', (els) => els.map((e) => e.textContent));
}

/** Wait for a log line matching `re`, or throw with everything that was logged. */
async function waitForLog(page, re, timeout, what) {
    const deadline = Date.now() + timeout;
    for (;;) {
        const lines = await logLines(page);
        const hit = lines.find((l) => re.test(l));
        if (hit) return hit;
        if (Date.now() > deadline) {
            throw new Error(
                'timed out waiting for ' + what + ' (' + re + ') after ' + timeout + ' ms\n' +
                lines.map((l) => '  | ' + l).join('\n')
            );
        }
        await new Promise((r) => setTimeout(r, 250));
    }
}

async function main() {
    if (!DAEMON) {
        skip(
            'no TDFU_DAEMON. Set it to a daemon\'s host:port to run this, e.g.\n' +
            '  TDFU_DAEMON=192.0.2.10:5050 node web/test/remote.spec.cjs\n' +
            '  (a daemon with no device attached answers discover with an empty list,\n' +
            '   which is enough to prove the transport end to end)'
        );
    }
    if (!fs.existsSync(path.join(DIST, 'index.html'))) {
        fail(DIST + ' has no index.html - run `cargo xtask web` first');
    }
    if (/^(127\.|localhost|\[?::1\]?)/.test(DAEMON)) {
        fail(
            'TDFU_DAEMON is on loopback. Chrome refuses remote.js\'s\n' +
            '  fetch({targetAddressSpace: "local"}) there; bind the daemon to its\n' +
            '  private-network address instead (dfu-remote --bind <addr>).'
        );
    }

    let playwright;
    try {
        playwright = require('playwright');
    } catch (e) {
        fail(
            'cannot load playwright (' + e.message + ').\n' +
            '  Point NODE_PATH at a node_modules containing it, e.g. an npx cache:\n' +
            '  NODE_PATH=<dir> node web/test/remote.spec.cjs'
        );
    }

    let pageException = null;
    let partialRun = null;
    const { server, port } = await serve(DIST);
    const base = 'http://127.0.0.1:' + port + '/';
    console.log('remote.spec: serving ' + DIST + ' at ' + base);
    console.log('remote.spec: daemon ' + DAEMON);

    const browser = await playwright.chromium.launch({ headless: !process.env.TDFU_HEADED });
    const context = await browser.newContext({ acceptDownloads: true });
    let failure = null;
    try {
        const page = await context.newPage();
        page.on('console', (m) => {
            if (m.type() === 'error') console.log('  [page error] ' + m.text());
        });
        /* An unhandled rejection in the page used to be printed and ignored, so a
         * run could report PASSED over one, and one of the page's own defects was
         * exactly that. It is a
         * failure of the run now: nothing the page throws is expected here. */
        page.on('pageerror', (e) => {
            console.log('  [page exception] ' + (e && e.stack ? e.stack : e));
            if (!pageException) pageException = e;
        });

        // Before any page script runs, or app.js reads the defaults instead.
        await page.addInitScript(
            ([url, token]) => {
                localStorage.setItem('tdfu_backend', 'remote');
                localStorage.setItem('tdfu_remote_url', url);
                localStorage.setItem('tdfu_remote_token', token);
                localStorage.setItem('tdfu_verify', '1');
                // Explicitly off: an overlay injection would change the bytes
                // between the read and the write and the verify would be right
                // to fail.
                localStorage.setItem('tdfu_inject', '0');
                localStorage.setItem('tdfu_reboot', '0');
                localStorage.setItem('tdfu_debug', '1');
            },
            ['http://' + DAEMON, process.env.TDFU_TOKEN || '']
        );

        await page.goto(base, { waitUntil: 'domcontentloaded' });
        await page.waitForSelector('#btn-connect');

        // --- discover -------------------------------------------------------
        console.log('remote.spec: connect');
        await page.click('#btn-connect');
        const found = await waitForLog(
            page,
            /Found \d+ device\(s\)|No Ingenic devices found on the daemon|Connection failed|Discover failed/,
            CONNECT_TIMEOUT,
            'discover'
        );
        console.log('remote.spec: ' + found);
        if (/Connection failed|Discover failed/.test(found)) {
            throw new Error('the daemon did not answer discover: ' + found);
        }
        if (/No Ingenic devices found/.test(found)) {
            throw new Partial(
                'the daemon answered discover with an empty list, so the read and write ' +
                'legs did not run. Attach a device to the daemon to exercise them.'
            );
        }

        // --- bootstrap, only when asked ------------------------------------
        let dfu = await page.$eval('#btn-read', (b) => !b.disabled);
        if (!dfu && process.env.TDFU_BOOTSTRAP === '1') {
            console.log('remote.spec: bootstrap');
            await page.click('#btn-bootstrap');
            await waitForLog(page, /ready to Read\/Write|did not reappear|bootstrap failed/i, OP_TIMEOUT, 'bootstrap');
            dfu = await page.$eval('#btn-read', (b) => !b.disabled);
        }
        if (!dfu) {
            throw new Error(
                'the device is not a DFU gadget, so Read and Write are not live. ' +
                'Bootstrap it first (the bench does this with the CLI), or set TDFU_BOOTSTRAP=1.'
            );
        }

        // --- read -----------------------------------------------------------
        console.log('remote.spec: read');
        const downloading = page.waitForEvent('download', { timeout: OP_TIMEOUT });
        await page.click('#btn-read');
        const download = await downloading;
        const dump = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'tdfu-remote-')), download.suggestedFilename());
        await download.saveAs(dump);
        const readLine = await waitForLog(page, /Read \d+ bytes; saved as|Remote read (failed|error)/, OP_TIMEOUT, 'read');
        if (/failed|error/.test(readLine)) throw new Error(readLine);
        const golden = fs.readFileSync(dump);
        console.log('remote.spec: ' + readLine + ' (' + golden.length + ' bytes at ' + dump + ')');

        // --- write with verify ----------------------------------------------
        // The image is what the chip just held unless one was named, so the
        // write is real and the device ends up as it started.
        const image = process.env.TDFU_IMAGE ? fs.readFileSync(process.env.TDFU_IMAGE) : golden;
        const name = process.env.TDFU_IMAGE ? path.basename(process.env.TDFU_IMAGE) : download.suggestedFilename();
        if (!image.length) throw new Error('the image to write is empty');
        console.log('remote.spec: write ' + name + ' (' + image.length + ' bytes) with verify');

        // Trap 1: choosing the file IS the click. #btn-write only calls
        // .click() on this input; firmwareSelected() starts the write.
        await page.setInputFiles('#firmware-file', {
            name,
            mimeType: 'application/octet-stream',
            buffer: image,
        });
        const wrote = await waitForLog(page, /Remote write complete|Remote write (failed|error)/, OP_TIMEOUT, 'write');
        if (/failed|error/.test(wrote)) throw new Error(wrote);
        console.log('remote.spec: ' + wrote);

        const lines = await logLines(page);
        if (!lines.some((l) => /Verify OK/.test(l))) {
            throw new Error('the write reported no verify, but tdfu_verify was set:\n' +
                lines.map((l) => '  | ' + l).join('\n'));
        }
        console.log('remote.spec: PASSED (discover, read, write with verify)');
    } catch (e) {
        if (e instanceof Partial) partialRun = e.message;
        else failure = e;
    } finally {
        await context.close();
        await browser.close();
        server.close();
    }
    if (failure) fail(failure.message);
    if (pageException) {
        fail('the page threw and nothing caught it: ' + (pageException.message || pageException));
    }
    if (partialRun) partial(partialRun);
}

main().catch((e) => fail(e && e.stack ? e.stack : String(e)));
