/* The prebuilt-release picker's grouping (web/src/releases.js), against the shape
 * thingino-firmware's releases API really has. Run with `npm test`. */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { BRANCHES, DEFAULT_BRANCH, branchOf, dateOf, groupByBranch, menuBranchOf, releaseLabel } from '../src/releases.js';

/* A slice of the real listing from 2026-09-03: two branches, two build caches, a draft. */
const LISTING = [
    { tag_name: 'master-2026-08-25', prerelease: true, draft: false, assets: [{ name: 'a.bin' }] },
    { tag_name: 'firmware-2026-08-14', prerelease: false, draft: false, assets: [{ name: 'b.bin' }] },
    { tag_name: 'master-2026-08-13', prerelease: true, draft: false, assets: [] },
    { tag_name: 'firmware-2026-08-12', prerelease: false, draft: true, assets: [] },
    { tag_name: 'ccache', prerelease: false, draft: false, assets: [] },
    { tag_name: 'update_cache', prerelease: false, draft: false, assets: [] },
    { tag_name: 'unstable-2026-08-01', prerelease: true, draft: false, assets: [] },
];

test('a tag is <branch>-<date>, or it is not a firmware release', () => {
    assert.equal(branchOf('firmware-2026-08-14'), 'firmware');
    assert.equal(branchOf('master-2026-08-25'), 'master');
    assert.equal(branchOf('fix-shell-injection-2026-09-01'), 'fix-shell-injection');
    assert.equal(branchOf('ccache'), null);
    assert.equal(branchOf('update_cache'), null);
    assert.equal(branchOf('firmware-2026-08'), null, 'a date is a whole date');
    assert.equal(branchOf(''), null);
    assert.equal(branchOf(undefined), null);
    assert.equal(dateOf('master-2026-08-25'), '2026-08-25');
});

test('the menu offers master and ciao, master first and by default', () => {
    assert.deepEqual(BRANCHES.map((b) => b.name), ['master', 'ciao']);
    assert.equal(DEFAULT_BRANCH, 'master');
    assert.equal(menuBranchOf('master-2026-08-25'), 'master');
    assert.equal(menuBranchOf('firmware-2026-08-14'), 'ciao', 'the stable line is built from ciao');
    assert.equal(menuBranchOf('unstable-2026-08-01'), null, 'no other branch is offered');
    assert.equal(menuBranchOf('ccache'), null);
});

test('the listing groups by menu branch, newest first, caches, drafts and other branches dropped', () => {
    const { branches, byBranch } = groupByBranch(LISTING);
    assert.deepEqual(branches, ['master', 'ciao']);
    assert.deepEqual(byBranch.ciao.map((e) => e.tag), ['firmware-2026-08-14'], 'the draft is gone');
    assert.deepEqual(byBranch.master.map((e) => e.tag), ['master-2026-08-25', 'master-2026-08-13']);
    assert.equal(byBranch.master[0].prerelease, true);
    assert.equal(byBranch.ciao[0].prerelease, false);
    assert.deepEqual(byBranch.ciao[0].assets, [{ name: 'b.bin' }]);
    assert.equal('unstable' in byBranch, false, 'hidden');
    assert.equal('ccache' in byBranch, false);
});

test('a listing with one of the two branches lists just that one', () => {
    const { branches } = groupByBranch(LISTING.filter((r) => !r.tag_name.startsWith('firmware-')));
    assert.deepEqual(branches, ['master']);
    assert.deepEqual(groupByBranch(LISTING.filter((r) => !r.tag_name.startsWith('master-'))).branches, ['ciao']);
    assert.deepEqual(groupByBranch([]).branches, []);
    assert.deepEqual(groupByBranch(undefined).branches, []);
});

test('the release menu shows the date, and says prerelease when GitHub does', () => {
    assert.equal(releaseLabel({ tag: 'firmware-2026-08-14', prerelease: false }), '2026-08-14');
    assert.equal(releaseLabel({ tag: 'master-2026-08-25', prerelease: true }), '2026-08-25 (prerelease)');
    assert.equal(releaseLabel({ tag: 'master-2026-08-25', prerelease: true }, 'Vorabversion'), '2026-08-25 (Vorabversion)');
});
