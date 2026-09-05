/*
 * Minimal service worker: keep the fixed-name resources fresh on a normal reload
 * so a redeploy is picked up without a hard-reload. GitHub Pages serves everything
 * with cache-control: max-age=600, which otherwise sticks for ~10 minutes.
 *
 *  - Page navigations: network-first (cache: 'reload') so new HTML lands at once.
 *  - /wasm/*: the three vendored overlay injectors (mkfs.jffs2, mkfs.ubifs, ubinize
 *    as MEMFS ES modules). inject.js imports them by a runtime URL, so Vite leaves
 *    them alone and they are NOT content-hashed like the /assets/* bundles - a normal
 *    reload would keep a stale cached copy, and a stale mkfs writes an overlay the
 *    on-device kernel may not mount. Revalidate on each load (cache: 'no-cache' => a
 *    conditional GET: a cheap 304 when nothing changed, a fresh fetch when it did).
 *
 *    The engine is no longer here. It used to be /wasm/tdfu.js + tdfu.wasm under a
 *    ?v=<git describe> cache-buster, because those were fixed names too; it is now an
 *    ES module imported by the bundle, so Vite hashes it and a changed build is a
 *    changed URL. This revalidation covers what is left.
 *
 * Content-hashed /assets/* change name per build, so they're left to the normal HTTP
 * cache. The worker caches nothing itself, so it can't get stuck on a stale page. To
 * retire it, deploy a sw.js whose fetch handler is empty (or unregister()s).
 */
/* The page's own directory, taken from this worker's URL: sw.js is served beside
 * index.html, so its directory IS the deployed base. A hard-coded '/wasm/'
 * matches nothing on a GitHub Pages project site at /<repo>/, which leaves the
 * injectors on whatever stale copy the HTTP cache holds - a deliberate
 * divergence from the C, which hard-codes the root while its own pages.yml sets
 * a base path. '/sw.js' -> '/', '/repo/sw.js' -> '/repo/'. */
const BASE = self.location.pathname.replace(/[^/]*$/, '');

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (event) => event.waitUntil(self.clients.claim()));
self.addEventListener('fetch', (event) => {
    const req = event.request;
    if (req.mode === 'navigate') {
        event.respondWith(fetch(req, { cache: 'reload' }).catch(() => fetch(req)));
        return;
    }
    const url = new URL(req.url);
    if (url.origin === self.location.origin && url.pathname.startsWith(BASE + 'wasm/')) {
        event.respondWith(fetch(req, { cache: 'no-cache' }).catch(() => fetch(req)));
    }
});
