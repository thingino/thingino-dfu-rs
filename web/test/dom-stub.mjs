/**
 * A browser double just big enough to import `web/src/app.js` under `node --test`.
 *
 * `app.js` is where the page's error handling lives, so pinning it needs the page,
 * not the adapter: the interesting behaviour is what a rejection does to the log
 * panel and to which buttons are live. Everything here is the smallest honest
 * stand-in for the one browser API `app.js` actually uses; nothing simulates
 * layout, styling or events the page does not listen for.
 *
 * Importing this module installs the globals. Import it before `../src/app.js`,
 * which reads `localStorage`, `location` and `navigator.usb` while it is loading.
 *
 *   import { dom } from './dom-stub.mjs';
 *   const app = await import('../src/app.js');
 */

/** `Element.classList`, including `toggle`'s "is it on now" answer. */
class ClassList {
    constructor() {
        this._on = new Set();
    }
    add(...names) {
        names.forEach((n) => this._on.add(n));
    }
    remove(...names) {
        names.forEach((n) => this._on.delete(n));
    }
    contains(name) {
        return this._on.has(name);
    }
    toggle(name, force) {
        const on = force === undefined ? !this._on.has(name) : !!force;
        if (on) this._on.add(name);
        else this._on.delete(name);
        return on;
    }
}

/** One element. Properties the page sets are plain fields, as in a real DOM. */
class El {
    constructor(tag, id) {
        this.tagName = (tag || 'div').toUpperCase();
        this.id = id || '';
        this.classList = new ClassList();
        this.className = '';
        this.textContent = '';
        this._html = '';
        this.style = {};
        this.children = [];
        this.disabled = false;
        this.checked = false;
        this.value = '';
        this.files = null;
        this.scrollTop = 0;
        this.scrollHeight = 0;
        this._attrs = new Map();
    }
    /* Assigning markup replaces what is under the element, and the page uses
     * exactly that to empty a <select> before refilling it. A field would leave
     * the old options in place and a test would read a list the page had
     * already thrown away. */
    get innerHTML() {
        return this._html;
    }
    set innerHTML(value) {
        this._html = String(value);
        if (this.children) this.children.length = 0;
    }
    appendChild(child) {
        this.children.push(child);
        return child;
    }
    append(...kids) {
        kids.forEach((k) => this.children.push(k));
    }
    remove() {}
    setAttribute(key, value) {
        this._attrs.set(key, String(value));
    }
    getAttribute(key) {
        return this._attrs.has(key) ? this._attrs.get(key) : null;
    }
    removeAttribute(key) {
        this._attrs.delete(key);
    }
    hasAttribute(key) {
        return this._attrs.has(key);
    }
    querySelector() {
        return null;
    }
    querySelectorAll() {
        return [];
    }
    closest() {
        return null;
    }
    click() {
        if (this.onclick) this.onclick();
    }
    getBoundingClientRect() {
        return { left: 0, top: 0, right: 0, bottom: 0, width: 0, height: 0 };
    }
}

/** `new Option(text, value)` - how the page builds every <select> it fills in JS. */
class OptionEl extends El {
    constructor(text, value) {
        super('option');
        this.textContent = text === undefined ? '' : String(text);
        this.value = value === undefined ? this.textContent : String(value);
    }
}

/* Elements are created on demand and remembered by id, so a test can read back
 * whatever the page wrote to one without listing them all up front. */
const byId = new Map();

const document = {
    body: new El('body'),
    getElementById(id) {
        if (!byId.has(id)) byId.set(id, new El('div', id));
        return byId.get(id);
    },
    createElement(tag) {
        return new El(tag);
    },
    querySelector(selector) {
        return byId.has(selector) ? byId.get(selector) : null;
    },
    querySelectorAll() {
        return [];
    },
    addEventListener() {},
    elementFromPoint() {
        return null;
    },
};

/** `localStorage`, backed by a Map. Seed it before importing `app.js`. */
class Storage {
    constructor() {
        this._items = new Map();
    }
    getItem(key) {
        return this._items.has(key) ? this._items.get(key) : null;
    }
    setItem(key, value) {
        this._items.set(key, String(value));
    }
    removeItem(key) {
        this._items.delete(key);
    }
    clear() {
        this._items.clear();
    }
}

/* The `connect` / `disconnect` listeners `app.js` registers on navigator.usb.
 * `dom.usbConnect(device)` is how a test delivers a hotplug. */
const usbListeners = new Map();

const navigator = {
    usb: {
        addEventListener(type, fn) {
            if (!usbListeners.has(type)) usbListeners.set(type, []);
            usbListeners.get(type).push(fn);
        },
        removeEventListener() {},
    },
    platform: 'Linux x86_64',
    userAgent: 'node',
    clipboard: null,
};

/** `FileReader`, the one path the Write button really takes (remote.spec.cjs trap 1). */
class FileReader {
    readAsArrayBuffer(file) {
        Promise.resolve(file.arrayBuffer()).then(
            (result) => {
                if (this.onload) this.onload({ target: { result } });
            },
            (e) => {
                if (this.onerror) this.onerror(e);
            }
        );
    }
}

globalThis.window = globalThis;
globalThis.document = document;
globalThis.localStorage = new Storage();
// Node 21 and newer define `globalThis.navigator` as a getter-only property, so a plain
// assignment throws there and the stub must replace the property instead.
Object.defineProperty(globalThis, 'navigator', { value: navigator, configurable: true, writable: true });
globalThis.location = { search: '', hash: '', href: 'http://localhost/' };
globalThis.FileReader = FileReader;
globalThis.Option = OptionEl;
globalThis.alert = function (text) {
    dom.alerts.push(text);
};
globalThis.innerWidth = 1024;
globalThis.innerHeight = 768;
if (!URL.createObjectURL) URL.createObjectURL = () => 'blob:stub';
if (!URL.revokeObjectURL) URL.revokeObjectURL = () => {};

export const dom = {
    document,
    alerts: [],

    /** The element the page keeps under this id, creating it if it has not yet. */
    el(id) {
        return document.getElementById(id);
    },

    /** Every log line the page has written, as `{ level, text }`, oldest first. */
    logLines() {
        return document.getElementById('log').children.map((c) => ({ level: c.className, text: c.textContent }));
    },

    /** The text of every log line, joined - handy for one `assert.match`. */
    logText() {
        return this.logLines()
            .map((l) => l.text)
            .join('\n');
    },

    /** Forget the log so a later assertion cannot read an earlier step's lines. */
    clearLog() {
        document.getElementById('log').children.length = 0;
    },

    /** The status badge's text: Idle, Detecting..., Error, Ready and friends. */
    status() {
        return document.getElementById('status-badge').textContent;
    },

    /** Deliver a WebUSB `connect` event, as the browser would on a hotplug. */
    async usbConnect(device) {
        for (const fn of usbListeners.get('connect') || []) fn({ device });
    },

    /** Choose a file, which is what actually starts a write (not the button). */
    async chooseFirmware(bytes, name) {
        const input = document.getElementById('firmware-file');
        input.files = [
            {
                name: name || 'firmware.bin',
                arrayBuffer: async () => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength),
            },
        ];
        globalThis.firmwareSelected(input);
    },

    /** Let queued microtasks and the page's own short timers run. */
    async settle(ms) {
        await new Promise((r) => setTimeout(r, ms === undefined ? 25 : ms));
    },
};
