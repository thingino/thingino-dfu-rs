/**
 * The four overlays close the two ways a dialog is expected to.
 *
 *   npm --prefix web test
 *
 * Each overlay had only its own buttons; Escape and a click on the dimmed
 * backdrop did nothing. The page drives both from one table, so this checks
 * every entry of it, and that a click inside the card is not a dismissal.
 *
 * `app.js` wires the listeners while loading, so this is its own file:
 * `node --test` gives each file its own process.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { dom } from './dom-stub.mjs';

await import('../src/app.js');
await dom.settle();

const OVERLAYS = ['settings-overlay', 'about-overlay', 'diag-overlay', 'windows-help-overlay'];

function open(id) {
    dom.el(id).classList.remove('d-none');
}
function isOpen(id) {
    return !dom.el(id).classList.contains('d-none');
}

test('Escape closes every open overlay', () => {
    OVERLAYS.forEach(open);
    dom.press('Escape');
    for (const id of OVERLAYS) assert.equal(isOpen(id), false, id);
});

test('a key other than Escape closes nothing', () => {
    open('about-overlay');
    dom.press('Enter');
    assert.equal(isOpen('about-overlay'), true);
    dom.press('Escape');
    assert.equal(isOpen('about-overlay'), false);
});

test('a click on the backdrop closes the overlay, a click inside the card does not', () => {
    for (const id of OVERLAYS) {
        open(id);
        const card = dom.document.createElement('div');
        dom.click(dom.el(id), card);
        assert.equal(isOpen(id), true, id + ' must stay open for a click inside it');
        dom.click(dom.el(id));
        assert.equal(isOpen(id), false, id + ' must close for a click on the backdrop');
    }
});
