/**
 * thingino-dfu firmware proxy.
 *
 * GitHub serves release assets from a blob host that sends no
 * Access-Control-Allow-Origin, so a browser cannot read their bytes: not from the
 * github.com download link, not from the signed URL it redirects to, and not via
 * the REST asset endpoint (whose 302 does carry CORS, but redirects to a blob that
 * does not). Listing releases needs no help - api.github.com sends CORS - so only
 * the bytes need this hop.
 *
 * This Worker is that hop. It fetches the asset server-side, where CORS does not
 * apply, and re-serves it with the header the browser needs. The body is streamed
 * straight through, never buffered, so a 16 MB image costs almost no CPU and no
 * memory. Workers bill no egress, so this stays inside the free tier.
 *
 *   GET /fw?tag=firmware-2026-06-22&name=thingino-360_ap1pa3_t31x_gc4653.bin
 *   GET /fw?tag=...&name=<same>.bin.sha256sum
 */

const REPO = 'themactep/thingino-firmware';

/* The allow-list IS the security model. Without it this would be an open proxy
 * that anyone could aim at any URL, on someone else's bandwidth. Only the two tag
 * lines the flasher's branch menu offers (`firmware-<date>`, the stable releases built
 * from ciao, and `master-<date>`, master's builds), only thingino-* .bin images and
 * their .sha256sum, and only from REPO. The tag rule was `firmware-` alone until
 * 2026-09-03, when the flasher gained the menu; offering another branch there means
 * widening this rule and redeploying. */
const TAG_RE = /^(firmware|master)-\d{4}-\d{2}-\d{2}$/;
const NAME_RE = /^thingino-[A-Za-z0-9._-]{1,128}\.bin(\.sha256sum)?$/;

export function allowed(tag, name) {
    if (!TAG_RE.test(tag) || !NAME_RE.test(name)) return false;
    return !tag.includes('..') && !name.includes('..'); /* no path games */
}

function cors(origin) {
    return {
        'Access-Control-Allow-Origin': origin,
        'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS',
        'Access-Control-Max-Age': '86400',
    };
}

export default {
    async fetch(request, env, ctx) {
        const origin = env.ALLOW_ORIGIN || '*';
        const url = new URL(request.url);

        if (request.method === 'OPTIONS')
            return new Response(null, { status: 204, headers: cors(origin) });
        if (request.method !== 'GET' && request.method !== 'HEAD')
            return new Response('method not allowed\n', { status: 405, headers: cors(origin) });
        if (url.pathname !== '/fw')
            return new Response('not found\n', { status: 404, headers: cors(origin) });

        const tag = url.searchParams.get('tag') || '';
        const name = url.searchParams.get('name') || '';
        if (!allowed(tag, name))
            return new Response('bad tag/name\n', { status: 400, headers: cors(origin) });

        /* Key the cache on our own canonical URL. Caching the upstream URL would
         * never hit: GitHub 302s to a signed blob URL whose query string differs
         * on every request. Verified working on workers.dev - a repeat fetch of
         * the same asset comes back X-Fw-Cache: HIT, so a popular image is served
         * from the edge instead of re-pulled from GitHub every time. */
        const key = new Request(`${url.origin}/fw?tag=${tag}&name=${name}`, { method: 'GET' });
        const cache = caches.default;
        const hit = await cache.match(key);
        if (hit) {
            const h = new Headers(hit.headers);
            for (const [k, v] of Object.entries(cors(origin))) h.set(k, v);
            h.set('X-Fw-Cache', 'HIT');
            return new Response(hit.body, { status: hit.status, headers: h });
        }

        const upstream = await fetch(
            `https://github.com/${REPO}/releases/download/${encodeURIComponent(tag)}/${encodeURIComponent(name)}`,
            { method: request.method, redirect: 'follow' });

        if (!upstream.ok)
            return new Response(`upstream ${upstream.status}\n`,
                                { status: upstream.status === 404 ? 404 : 502, headers: cors(origin) });

        const h = new Headers(cors(origin));
        h.set('Content-Type', 'application/octet-stream');
        /* Pass the length through, or the browser's download bar goes indeterminate. */
        const len = upstream.headers.get('Content-Length');
        if (len) h.set('Content-Length', len);
        /* A published release asset never changes, so it can be cached hard. */
        h.set('Cache-Control', 'public, max-age=86400');

        const res = new Response(upstream.body, { status: 200, headers: h });
        /* clone() tees the stream: the client and the cache each get a copy, and
         * the bytes are still never held in memory. cache.put only takes GETs. */
        if (request.method === 'GET') ctx.waitUntil(cache.put(key, res.clone()));
        res.headers.set('X-Fw-Cache', 'MISS'); /* after clone: cached copy stays clean */
        return res;
    },
};
