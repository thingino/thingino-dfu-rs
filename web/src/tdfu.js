/**
 * The page's side of the tdfu-wasm seam.
 *
 * `tdfu-wasm` is a wasm32-unknown-unknown cdylib behind wasm-bindgen, so every
 * entry point below returns a real promise. That is the whole reason the
 * Emscripten machinery is gone: there is no Asyncify stack to unwind, so there
 * is no single-call-at-a-time mutex, no `{async: true}` ccall, no MEMFS to stage
 * a file through, and no hand-written libusb-to-WebUSB shim. A transfer is an
 * awaited future like any other, and two of them can be in flight if a caller
 * ever wants that.
 *
 * This module is the only file that imports the generated glue. Everything else
 * in the page calls these functions, so the day the glue's shape changes, one
 * file moves.
 */

import init, { Engine, variantNames as wasmVariantNames, version as wasmVersion }
    from './wasm/tdfu_wasm.js';

/* The live engine, and the promise that is building it. `ready()` is idempotent:
 * every entry point awaits it, so the page never has to sequence the load. */
let engine = null;
let booting = null;

/* Where log and progress frames go once the page registers for them. Set by
 * init(); until then they are dropped rather than queued - nothing interesting
 * happens before the page is listening. */
let onLog = function () {};
let onProgress = function () {};

/* The 59-entry ordinal table, fetched once at init. It is the
 * frozen wire table, not a JS copy: `remote.js` resolves DISCOVER's ordinals
 * through variantName() so there is no hand-kept list here to drift from the
 * protocol as loaders are added. */
let names = [];

/**
 * Load the engine. Safe to call more than once; later calls await the first.
 *
 * @param {{log?: function(string, string), progress?: function(string, number, number|null)}} sinks
 * @returns {Promise<string>} the version banner, e.g. "2.0.0-alpha.0 (abc1234)"
 */
export async function initTdfu(sinks) {
    if (sinks) {
        if (sinks.log) onLog = sinks.log;
        if (sinks.progress) onProgress = sinks.progress;
    }
    if (!booting) {
        booting = (async function () {
            await init();
            names = wasmVariantNames();
            // The sinks are read through the closures above rather than captured,
            // so registering a handler after the engine exists still works.
            engine = new Engine({
                log: function (line, level) { onLog(line, level || 'info'); },
                progress: function (phase, done, total) { onProgress(phase, done, total); },
            });
            return wasmVersion();
        })();
    }
    return booting;
}

/** Is the engine up? Cheap, synchronous, and false until initTdfu() resolves. */
export function isReady() {
    return engine !== null;
}

/** The version banner, or 'dev' before the engine is up. */
export function version() {
    return engine ? wasmVersion() : 'dev';
}

/**
 * The variant ordinal table, as the engine reports it.
 * @returns {string[]}
 */
export function variantNames() {
    return names;
}

/**
 * Resolve a wire variant ordinal to its name.
 *
 * `0xFF` is deliberately outside the table: it means "the daemon
 * does not know what this is", and every client renders it `unknown`. So does
 * anything else out of range, which is what a client compiled before a new
 * ordinal sees.
 *
 * @param {number} ordinal
 * @returns {string}
 */
export function variantName(ordinal) {
    return names[ordinal] || 'unknown';
}

/** Await the engine, or fail with something a user can act on. */
async function ready() {
    if (!booting) throw new Error('the flasher engine is not loaded');
    await booting;
    if (!engine) throw new Error('the flasher engine is not loaded');
    return engine;
}

/**
 * Verbose diagnostics, the browser's -d. Fire-and-forget: a failure here is
 * never worth failing a flash over.
 * @param {boolean} on
 */
export function setDebug(on) {
    if (engine) engine.setDebug(!!on);
}

/**
 * Open the browser's device chooser with the Ingenic filters. Needs a user
 * gesture, and resolves null when the chooser is dismissed.
 * @returns {Promise<object|null>} DeviceInfo
 */
export async function requestDevice() {
    return (await ready()).requestDevice();
}

/**
 * Devices this origin is already authorised for. No chooser, no gesture.
 * @returns {Promise<object[]>} DeviceInfo[]
 */
export async function discover() {
    return (await ready()).discover();
}

/**
 * SoC detection: three bootrom register reads, nothing uploaded or executed.
 * @param {number} id
 * @returns {Promise<{variant: string, chip: string, family: string, dram: string, evidence: string, caveat: string|null}>}
 */
export async function detect(id) {
    return (await ready()).detect(id);
}

/**
 * USB-boot a stage 1 and U-Boot into the bootrom.
 *
 * `spl` and `uboot` are both-or-neither; the page fetches the
 * bundled pair for a detected variant, or passes the user's own from the
 * Advanced panel.
 *
 * @param {number} id
 * @param {{variant?: string, spl?: Uint8Array, uboot?: Uint8Array}} opts
 */
export async function bootstrap(id, opts) {
    return (await ready()).bootstrap(id, opts || {});
}

/**
 * Write an image to an alt, optionally reading it back to compare.
 * @param {number} id
 * @param {{alt?: string|number, image: Uint8Array, verify?: boolean}} opts
 */
export async function write(id, opts) {
    return (await ready()).write(id, opts);
}

/**
 * Read an alt back. Without `size`, the whole alt.
 * @param {number} id
 * @param {{alt?: string|number, size?: number}} opts
 * @returns {Promise<Uint8Array>}
 */
export async function read(id, opts) {
    return (await ready()).read(id, opts || {});
}

/**
 * Read an alt back and compare it against an image.
 * @param {number} id
 * @param {{alt?: string|number, image: Uint8Array}} opts
 */
export async function verify(id, opts) {
    return (await ready()).verify(id, opts);
}

/** Erase the flash: the loader's wipe token, then a blank check. */
export async function erase(id) {
    return (await ready()).erase(id);
}

/** Reset the SoC through the loader's reboot alt. */
export async function reboot(id) {
    return (await ready()).reboot(id);
}

/**
 * The eFuse and secure-boot readout, as text.
 * @param {number} id
 * @returns {Promise<string>}
 */
export async function diag(id) {
    return (await ready()).diag(id);
}
