/**
 * HTTP client for the dfu-remote daemon (TDFU binary protocol over fetch()).
 *
 * Each command is one POST whose body is the TDFU command frame; the daemon
 * replies with a chunked stream of TDFU response frames (progress/log then
 * OK/ERROR), which we parse as a byte stream. fetch() is used (not WebSocket)
 * because Chrome's Local Network Access only exempts fetch({targetAddressSpace:
 * 'local'}) from mixed-content blocking - so the HTTPS flasher can reach a
 * local/LAN daemon over plain http:// with a one-time permission, no TLS.
 */

const MAGIC = 0x54444655; // "TDFU"
const VERSION = 1;
export const DEFAULT_PORT = 5050;

const CMD_DISCOVER = 0x01;
const CMD_BOOTSTRAP = 0x02;
const CMD_WRITE = 0x03;
const CMD_READ = 0x04;
const CMD_DIAG = 0x07;
const CMD_REBOOT = 0x08;

const RESP_OK = 0x00;
const RESP_ERROR = 0x01;
const RESP_PROGRESS = 0x02;
const RESP_LOG = 0x03;

/* The largest payload this protocol carries, in both directions
 * (crates/tdfu-proto/src/lib.rs: MAX_PAYLOAD). The daemon refuses a frame that
 * declares more, and so does this: a length is four bytes off a socket the
 * operator typed the address of, so a corrupt or hostile one asking for 4 GiB
 * would otherwise be buffered chunk by chunk until the tab is killed. */
const MAX_PAYLOAD = 64 * 1024 * 1024;

/* No hardcoded variant-name table here: the daemon sends a wire ordinal, and that
 * space grows as per-variant loaders are added, so the names are resolved through
 * the engine's copy of the frozen table (passed in as variantResolver) rather than
 * a JS copy that silently drifts.
 *
 * The ordinal 0xFF is deliberately outside that table and resolves
 * to "unknown": it is what the daemon reports for a DFU gadget whose SoC it never
 * detected, which is the ordinary state after a daemon restart. */
const UNKNOWN_VARIANT = 'unknown';

/* The stage byte of a progress frame. The values are `Phase`'s own
 * discriminants, crates/tdfu-core/src/progress.rs:27-44: eight today, and one
 * this table is too old to know renders with no prefix, which is why `Phase` is
 * #[non_exhaustive] (progress.rs:26) and why nothing here refuses an unknown
 * byte. Ordinal 0 is Phase::Unknown, deliberately blank rather than "working":
 * "working: 4096 / 16777216 bytes" says less than the count alone.
 *
 * (The C's protocol.h never named a stage value at all - its clients parsed the
 * frame and its daemon never sent one - so there is no C citation to
 * carry here.) */
const STAGE_NAMES = ['', 'stage1', 'u-boot', 'download', 'manifest', 'upload', 'verify', 'erase'];

/* Drop the frame's own line terminator, and only that one.
 *
 * A RESP_LOG frame carries a whole line and now ends in a newline: this daemon
 * terminates it where it frames it, which the C's did too and an
 * earlier build of this one did not. Exactly one is removed, so a note that
 * deliberately ends in a blank line still shows one. */
function stripOneNewline(text) {
    return text.endsWith('\n') ? text.slice(0, -1) : text;
}

/* CRC-32 (IEEE, reflected) - matches the daemon's remote_crc32 / zlib crc32. */
function crc32(bytes) {
    let crc = 0xffffffff;
    for (let i = 0; i < bytes.length; i++) {
        crc ^= bytes[i];
        for (let j = 0; j < 8; j++) crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
    }
    return (~crc) >>> 0;
}

/* Accept ws://, wss://, http://, https:// or a bare host[:port]; the transport
 * is plain HTTP (LNA can't exempt ws://). */
function normalizeUrl(url) {
    url = (url || '').trim();
    if (url.startsWith('ws://')) url = 'http://' + url.slice(5);
    else if (url.startsWith('wss://')) url = 'https://' + url.slice(6);
    if (!/^https?:\/\//.test(url)) {
        /* A bare IPv6 literal has to be bracketed or the URL parser reads its
         * first colon as the port separator. Two or more colons means a v6
         * literal, since a bare host[:port] can only hold one. Pairing a
         * literal with a port is ambiguous unbracketed, so that case is the
         * user's to write as [addr]:port. */
        if (url.indexOf(':') !== url.lastIndexOf(':') && url[0] !== '[')
            url = '[' + url + ']';
        url = 'http://' + url;
    }
    return url;
}

export class RemoteClient {
    constructor(onLog, onProgress, variantResolver) {
        this.url = '';
        this.token = '';
        this.onLog = onLog || function () {};
        this.onProgress = onProgress || function () {};
        // Resolve a variant index -> name. The caller wires this to the C
        // tdfu_variant_to_string (via the WASM) so there is no hardcoded variant
        // table on the JS side to drift from the enum.
        this.variantResolver = variantResolver || function () { return 'unknown'; };
        this.connected = false;
    }

    async connect(url, token) {
        this.url = normalizeUrl(url);
        this.token = token || '';
        this.connected = true; // fetch() is stateless; the first command validates connectivity.
        return true;
    }

    disconnect() { this.connected = false; }
    isConnected() { return this.connected; }

    /* POST a TDFU command and parse the streamed TDFU responses, surfacing
     * PROGRESS/LOG, returning the OK payload (or null on ERROR). */
    async _command(command, payload) {
        const cmd = command;
        const pl = payload || new Uint8Array(0);
        const frame = new Uint8Array(10 + pl.length);
        const dv = new DataView(frame.buffer);
        dv.setUint32(0, MAGIC);
        frame[4] = VERSION;
        frame[5] = cmd;
        dv.setUint32(6, pl.length);
        frame.set(pl, 10);

        const headers = { 'Content-Type': 'application/octet-stream' };
        if (this.token) headers['X-Auth-Token'] = this.token;

        const resp = await fetch(this.url, {
            method: 'POST',
            headers,
            body: frame,
            // Tell Chrome this targets the local network so LNA exempts it from
            // mixed-content blocking (ignored by browsers without LNA).
            targetAddressSpace: 'local',
        });
        if (!resp.ok) throw new Error('HTTP ' + resp.status + ' ' + resp.statusText);
        if (!resp.body) throw new Error('no response body');

        const reader = resp.body.getReader();
        const queue = [];
        let queued = 0;
        let streamDone = false;
        const pump = async () => {
            const { done, value } = await reader.read();
            if (done) { streamDone = true; return false; }
            queue.push(value);
            queued += value.length;
            return true;
        };
        const readExact = async (n) => {
            while (queued < n) {
                if (!(await pump())) throw new Error('stream ended early');
            }
            const out = new Uint8Array(n);
            let o = 0;
            while (o < n) {
                const head = queue[0];
                const take = Math.min(head.length, n - o);
                out.set(head.subarray(0, take), o);
                o += take;
                queued -= take;
                if (take === head.length) queue.shift();
                else queue[0] = head.subarray(take);
            }
            return out;
        };

        for (;;) {
            const hdr = await readExact(10);
            const hv = new DataView(hdr.buffer, hdr.byteOffset, 10);
            if (hv.getUint32(0) !== MAGIC) throw new Error('bad response magic');
            const status = hdr[5];
            const plen = hv.getUint32(6);
            /* Checked before a byte of it is read: readExact() pumps the socket
             * until it has the whole thing, so an unchecked length is the page's
             * heap in someone else's hands. */
            if (plen > MAX_PAYLOAD) {
                try { reader.cancel(); } catch (e) { /* ignore */ }
                throw new Error('response frame declares ' + plen + ' bytes, over the ' +
                                MAX_PAYLOAD + '-byte protocol maximum');
            }
            const body = plen > 0 ? await readExact(plen) : new Uint8Array(0);
            if (status === RESP_PROGRESS) {
                /* These arrive now. The C daemon parsed a progress frame in both
                 * of its clients and never sent one, so
                 * remote flashing showed byte counts only as log prose; this
                 * daemon sends one per byte count on BOOTSTRAP, WRITE and READ.
                 * percent is 0 where there is no knowable total - a DFU upload
                 * ends on a short block - and the message still carries the live
                 * count, so the caller keeps an indeterminate bar there. */
                if (body.length >= 4) {
                    const percent = body[0];
                    const stage = STAGE_NAMES[body[1]] || '';
                    const msgLen = (body[2] << 8) | body[3];
                    const msg = msgLen > 0 && body.length >= 4 + msgLen
                        ? new TextDecoder().decode(body.subarray(4, 4 + msgLen)) : '';
                    this.onProgress(percent, stage ? stage + ': ' + msg : msg, stage);
                }
            } else if (status === RESP_LOG) {
                this.onLog(stripOneNewline(new TextDecoder().decode(body)));
            } else if (status === RESP_OK) {
                try { reader.cancel(); } catch (e) { /* ignore */ }
                return body;
            } else {
                /* The body is "<class>: <detail>" - a message to show, never a
                 * string to branch on: no shipped client matched one, which is
                 * why the daemon was free to make them richer. */
                const m = body.length ? new TextDecoder().decode(body) : 'unknown error';
                this.onLog('ERROR: ' + stripOneNewline(m));
                try { reader.cancel(); } catch (e) { /* ignore */ }
                return null;
            }
        }
    }

    /* The devices the daemon sees, or null when it refused to say.
     *
     * A refusal is not an empty bus: the commonest one is a wrong --token, and
     * answering [] for it makes the caller report "no devices found", which is
     * the opposite of the truth. The two are told apart here so the caller can
     * tell them apart too. */
    async discover() {
        const payload = await this._command(CMD_DISCOVER);
        if (!payload) return null;
        const dv = new DataView(payload.buffer, payload.byteOffset, payload.length);
        const devs = [];
        for (let off = 0; off + 8 <= payload.length; off += 8) {
            const variant = dv.getUint8(off + 7);
            const stage = dv.getUint8(off + 6);
            devs.push({
                bus: dv.getUint8(off), address: dv.getUint8(off + 1),
                vendor: dv.getUint16(off + 2), product: dv.getUint16(off + 4),
                stage, variant,
                variantName: this.variantResolver(variant),
                stageName: stage === 0 ? 'bootrom' : (stage === 2 ? 'dfu' : 'firmware'),
            });
        }
        return devs;
    }

    /* The readout, as text. This daemon's DIAG payload carries no trailing
     * newline (the C's did); the page puts it in textContent where either is
     * invisible, so the strip is belt and braces for a third-party daemon. */
    async diag(deviceIndex) {
        const body = await this._command(CMD_DIAG, new Uint8Array([deviceIndex & 0xff]));
        if (!body) return null;
        return stripOneNewline(new TextDecoder().decode(body));
    }
    /* Reset the SoC (used after a flash). The daemon runs tdfu_dfu_reboot, which
     * tolerates the reset disconnect and replies OK. False means it refused:
     * answering true regardless printed "Reboot triggered" for a reboot that
     * never happened, one line under the daemon's own ERROR. */
    async reboot(deviceIndex) {
        return (await this._command(CMD_REBOOT, new Uint8Array([deviceIndex & 0xff]))) !== null;
    }

    _variantPayload(deviceIndex, variant) {
        const vb = new TextEncoder().encode(variant || '');
        const p = new Uint8Array(2 + vb.length);
        p[0] = deviceIndex & 0xff;
        p[1] = vb.length;
        p.set(vb, 2);
        return p;
    }

    async bootstrap(deviceIndex, variant, splData, ubootData) {
        /* BOOTSTRAP is the one command that turns this name into a loader, so it
         * is the one command that refuses a name it does not know.
         * "unknown" is what a device whose SoC the daemon never detected reads
         * as, and sending it back would be refused with a message about --cpu;
         * an empty variant asks the daemon to detect it, which is the honest
         * request. READ and WRITE ignore the field and take it either way. */
        if (variant === UNKNOWN_VARIANT) variant = '';
        var base = this._variantPayload(deviceIndex, variant);
        // Optional custom SPL + U-Boot (both-or-neither), appended as the daemon
        // expects: [4:spl_len][spl][4:uboot_len][uboot], big-endian lengths.
        if (splData && ubootData) {
            var buf = new Uint8Array(base.length + 4 + splData.length + 4 + ubootData.length);
            buf.set(base, 0);
            var dv = new DataView(buf.buffer);
            var off = base.length;
            dv.setUint32(off, splData.length); off += 4;
            buf.set(splData, off); off += splData.length;
            dv.setUint32(off, ubootData.length); off += 4;
            buf.set(ubootData, off);
            return (await this._command(CMD_BOOTSTRAP, buf)) !== null;
        }
        return (await this._command(CMD_BOOTSTRAP, base)) !== null;
    }

    /* The variant travels but is not used: this daemon logs an unrecognised name
     * on READ and WRITE and ignores it, because nothing downstream
     * reads it there. It is sent unchanged so that what the browser puts on the
     * wire stays the payload the daemon's own tests replay. */
    async readFirmware(deviceIndex, variant) {
        const resp = await this._command(CMD_READ, this._variantPayload(deviceIndex, variant));
        if (!resp || resp.length < 4) return null;
        const data = resp.subarray(0, resp.length - 4);
        const recvCrc = new DataView(resp.buffer, resp.byteOffset + resp.length - 4, 4).getUint32(0) >>> 0;
        if (crc32(data) !== recvCrc) { this.onLog('ERROR: CRC32 mismatch on read\n'); return null; }
        return data.slice();
    }

    async writeFirmware(deviceIndex, variant, firmwareData, verify) {
        const vb = new TextEncoder().encode(variant || '');
        // Wire format the daemon parses:
        //   [idx][variant_len][variant][alt_len][alt][fw_len][fw][crc][verify?]
        // alt is empty here (alt_len = 0 => daemon's default alt 0 = flash).
        // The trailing verify byte is optional (older daemons stop after crc).
        const buf = new Uint8Array(2 + vb.length + 1 + 4 + firmwareData.length + 4 + (verify ? 1 : 0));
        const dv = new DataView(buf.buffer);
        buf[0] = deviceIndex & 0xff;
        buf[1] = vb.length;
        buf.set(vb, 2);
        let off = 2 + vb.length;
        buf[off] = 0; // alt_len = 0
        off += 1;
        dv.setUint32(off, firmwareData.length);
        off += 4;
        buf.set(firmwareData, off);
        off += firmwareData.length;
        dv.setUint32(off, crc32(firmwareData));
        off += 4;
        if (verify) buf[off] = 1;
        return (await this._command(CMD_WRITE, buf)) !== null;
    }
}
