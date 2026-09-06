/* The firmware proxy's allow-list (web/worker/src/index.js) is its security model:
 * which release tags and asset names it will fetch from GitHub on the caller's behalf.
 * The tag rule widened on 2026-09-03 for the branch menu; this pins what it admits and,
 * more importantly, what it still refuses. Run with `npm test`. */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { allowed } from '../worker/src/index.js';

const IMAGE = 'thingino-wyze_cam3_t31x_gc2053_atbm6031.bin';

test('the two tag lines the menu offers are served, with a thingino image name', () => {
    assert.equal(allowed('firmware-2026-08-14', IMAGE), true, 'the stable line, as before');
    assert.equal(allowed('master-2026-08-25', IMAGE), true, 'a master build, new');
    assert.equal(allowed('firmware-2026-08-14', IMAGE + '.sha256sum'), true, 'and its checksum');
});

test('everything else is refused, other branches included', () => {
    assert.equal(allowed('unstable-2026-08-01', IMAGE), false, 'a branch the menu does not offer');
    assert.equal(allowed('ciao-2026-08-14', IMAGE), false, 'ciao publishes as firmware-, not ciao-');
    assert.equal(allowed('ccache', IMAGE), false, 'a build cache');
    assert.equal(allowed('update_cache', IMAGE), false);
    assert.equal(allowed('firmware', IMAGE), false, 'no date');
    assert.equal(allowed('firmware-2026-08', IMAGE), false, 'not a whole date');
    assert.equal(allowed('Master-2026-08-25', IMAGE), false, 'tags are lowercase');
    assert.equal(allowed('../firmware-2026-08-14', IMAGE), false, 'no path games');
    assert.equal(allowed('', IMAGE), false);
});

test('the name rule is unchanged: only thingino images and their checksums', () => {
    assert.equal(allowed('master-2026-08-25', 'thingino-x.bin'), true);
    assert.equal(allowed('master-2026-08-25', 'thingino-x.bin.sha256sum'), true);
    assert.equal(allowed('master-2026-08-25', 'x.bin'), false);
    assert.equal(allowed('master-2026-08-25', 'thingino-x.tar.gz'), false);
    assert.equal(allowed('master-2026-08-25', 'thingino-../x.bin'), false);
    assert.equal(allowed('master-2026-08-25', ''), false);
});
