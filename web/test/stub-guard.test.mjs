/**
 * The build's refusal to ship a page with no engine.
 *
 * The decision is a pure function so it can be pinned here rather than by
 * running vite; the plugin around it is four lines. The marker is checked
 * against the writer's own copy, because two constants that must be equal and
 * live in different files are exactly the kind of pair that drifts.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

import { isStubGlue, stubRefusal, STUB_MARKER } from '../build/stub-guard.mjs';
import { STUB_MARKER as WRITER_MARKER } from './make-seam-stub.mjs';

const REAL_GLUE = `let wasm;\n\nexport class Engine {\n}\n`;
const STUB_GLUE = `${STUB_MARKER}\n * A stand-in.\n */\nexport class Engine {}\n`;

test('the guard and the writer agree on the marker', () => {
    assert.equal(STUB_MARKER, WRITER_MARKER);
});

test('the marker is the first line the writer actually writes', async () => {
    const source = await readFile(new URL('./make-seam-stub.mjs', import.meta.url), 'utf8');
    assert.match(source, /const SOURCE = `\$\{STUB_MARKER\}/, 'the stub is written from the same constant');
});

test('a stub glue is refused, and the message says how to fix it', () => {
    const refusal = stubRefusal(STUB_GLUE, false);
    assert.ok(refusal, 'a stub must not be bundled by accident');
    assert.match(refusal, /cargo xtask web --release/);
    assert.match(refusal, /TDFU_ALLOW_STUB=1/);
});

test('the real glue and a missing glue are not refused', () => {
    assert.equal(stubRefusal(REAL_GLUE, false), null);
    assert.equal(stubRefusal(null, false), null, 'a missing glue is rollup\'s error to report');
});

test('TDFU_ALLOW_STUB=1 is the way to build one on purpose', () => {
    assert.equal(stubRefusal(STUB_GLUE, true), null);
});

test('isStubGlue does not match on the words alone', () => {
    assert.equal(isStubGlue('// see web/test/make-seam-stub.mjs for the stub\n' + STUB_MARKER), false);
    assert.equal(isStubGlue(STUB_GLUE), true);
});
