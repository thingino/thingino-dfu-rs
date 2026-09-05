/*
 * Client-side overlay injection for thingino images.
 *
 * Right before flashing, the loaded image bytes are already in hand, so we bake
 * a small set of files into the writable overlay and hand the modified bytes
 * back to the flasher - no upload, no rebuild. Used for Wi-Fi credentials, an
 * SSH key, and anything else that belongs in the overlay.
 *
 *   NOR  (flat 'data' partition): repack the JFFS2 overlay        (mkfs.jffs2)
 *   NAND ('-(ubi)' partition):    rebuild the UBI with a fresh    (mkfs.ubifs
 *                                 UBIFS overlay volume             + ubinize)
 *
 * The overlayfs upperdir differs by kernel: NOR (3.10) mounts the overlay root
 * as upperdir; NAND (4.4) uses <overlay>/root. injectNand adds the 'root/'
 * prefix so a file targeting /etc/foo lands at /etc/foo either way.
 *
 * The WASM engines live in <base>wasm/, loaded on first use; see WASM_BASE.
 */
const ALIGN = 0x10000;                         // JFFS2 eraseblock (NOR)
const OVERLAY_MAX_LEBS = 8192;                 // generous UBIFS -c; autoresize fills the real chip
const MT = 1000000000 * 1000;                  // fixed mtime -> deterministic output

/* Where the three vendored injector modules live, relative to the deployed page.
 *
 * Vite replaces import.meta.env.BASE_URL with the base the page was built for
 * (PAGES_BASE, '/' by default), so a Pages project site served from /<repo>/
 * loads /<repo>/wasm/mkfs_jffs2_memfs.mjs instead of 404ing at the site root and
 * failing the whole Pre-configure panel. This is a DELIBERATE divergence from
 * the C, whose inject.js hard-codes '/wasm/' while its own pages.yml sets
 * PAGES_BASE from the Pages path: the C ships the bug, and
 * copying it would be Type 2 contamination. Outside a vite build - the Node
 * tests - there is no import.meta.env, and the root is right there. */
export function wasmBaseFor(baseUrl) {
  if (typeof baseUrl !== 'string' || !baseUrl) return '/wasm/';
  return (baseUrl.endsWith('/') ? baseUrl : baseUrl + '/') + 'wasm/';
}
let WASM_BASE = wasmBaseFor(import.meta.env && import.meta.env.BASE_URL);
export function setWasmBase(b) { WASM_BASE = b; }   // override for tests / non-root hosting
export function wasmBase() { return WASM_BASE; }
const _mods = {};
async function engine(name) {
  if (!_mods[name]) { const url = WASM_BASE + name + '.mjs'; _mods[name] = (await import(/* @vite-ignore */ url)).default; }
  return _mods[name];
}

/* One mtdparts size or offset, in bytes.
 *
 * The kernel's cmdline parser reads these with memparse: a decimal or
 * 0x-prefixed count, optionally scaled by k, m or g, all powers of 1024. A
 * number with no suffix is a byte count, which is why an offset is read the
 * same way a size is rather than assumed to be in KiB. Returns null for
 * anything this does not describe, so the caller can refuse the segment rather
 * than guess at its length. */
function parseMtdSize(text) {
  const m = /^(0x[0-9a-f]+|\d+)([kmg]?)$/i.exec(String(text).trim());
  if (!m) return null;
  const digits = m[1].toLowerCase().startsWith('0x') ? parseInt(m[1], 16) : parseInt(m[1], 10);
  if (!Number.isSafeInteger(digits)) return null;
  const scale = { k: 1024, m: 1048576, g: 1073741824 }[m[2].toLowerCase()] || 1;
  return digits * scale;
}

// --- read the flash layout straight from the image (mtdparts in the U-Boot env) ---
export function parseMtdparts(u8) {
  const needle = 'mtdparts=';
  let start = -1;
  for (let i = 0; i + needle.length < u8.length; i++) {
    let ok = true;
    for (let j = 0; j < needle.length; j++) if (u8[i + j] !== needle.charCodeAt(j)) { ok = false; break; }
    if (ok) { start = i; break; }
  }
  if (start < 0) throw new Error('no mtdparts in image (not a thingino flash image?)');
  let end = start;
  while (end < u8.length && u8[end] !== 0 && u8[end] > 0x20) end++;
  let s = ''; for (let i = start; i < end; i++) s += String.fromCharCode(u8[i]);
  const spec = s.split(':')[1] || '';
  /* A partition's offset is the sum of the sizes before it, so a segment this
   * cannot read is not one to skip: skipping it leaves the running offset short
   * by that partition's length, and every partition after it is then placed too
   * early - including the one the overlay gets written into. Refuse the whole
   * spec instead, and let the caller abort the flash. */
  const parts = {}; let off = 0;
  for (const seg of spec.split(',')) {
    const text = seg.trim();
    if (!text) continue;
    // <size>[@<offset>](<name>)[ro], or "-" for whatever is left of the chip.
    // A name is whatever stands between the parentheses: uboot-env and its like
    // are ordinary thingino partition names and are not made of word characters.
    const m = /^(-|[^@(]+?)(?:@([^(]+))?\(([^)]+)\)(ro)?$/.exec(text);
    if (!m) throw new Error('mtdparts: cannot read the partition "' + text + '"');
    const name = m[3];
    let at = null;
    if (m[2] !== undefined) {
      at = parseMtdSize(m[2]);
      if (at === null) throw new Error('mtdparts: cannot read the offset of "' + text + '"');
    }
    if (m[1] === '-') {                                  // "rest of chip" (NAND ubi)
      parts[name] = { offset: at === null ? off : at, size: -1 };
      continue;
    }
    const size = parseMtdSize(m[1]);
    if (size === null) throw new Error('mtdparts: cannot read the size of "' + text + '"');
    // An @ anchors a partition somewhere of its own: it overlaps the layout
    // rather than extending it, so it does not move the running offset.
    if (at !== null) { parts[name] = { offset: at, size, alias: true }; continue; }
    parts[name] = { offset: off, size }; off += size;
  }
  return { parts, raw: s };
}

export function overlayInfo(u8) {
  const { parts } = parseMtdparts(u8);
  if (parts.data) return { ok: true, type: 'nor', offset: parts.data.offset, size: parts.data.size };
  if (parts.ubi)  return { ok: true, type: 'nand', ubiStart: parts.ubi.offset };
  return { ok: false, reason: 'No writable overlay partition found in this image.' };
}

/* wpa_supplicant's quoted string runs from the first double quote on the line
 * to the last one, with no escape for a quote in between, and a newline ends the
 * directive outright. A value carrying either cannot be written that way.
 *
 * An SSID always has a second spelling: unquoted hex, which carries any byte, so
 * a difficult SSID becomes that. A passphrase has no such spelling - unquoted
 * psk is the 64-hex pre-shared key itself, not the words it is derived from - so
 * a passphrase the quoted form cannot carry is refused by name, rather than
 * baked in truncated to flash a camera that then never joins the network. */
const WPA_UNQUOTABLE = /["\\]|[\x00-\x1f\x7f]/;

function wpaHex(text) {
  let hex = '';
  for (const b of new TextEncoder().encode(text)) hex += b.toString(16).padStart(2, '0');
  return hex;
}

/** `ssid=` as wpa_supplicant reads it back: quoted where it can be, hex where not. */
function wpaSsid(ssid) {
  return WPA_UNQUOTABLE.test(ssid) ? wpaHex(ssid) : `"${ssid}"`;
}

/** `psk=`: the 64-hex key unquoted, the passphrase quoted, or nothing doing. */
function wpaPsk(psk) {
  if (/^[0-9a-fA-F]{64}$/.test(psk)) return psk.toLowerCase();
  if (WPA_UNQUOTABLE.test(psk))
    throw new Error('The Wi-Fi passphrase contains a character wpa_supplicant.conf cannot carry ' +
                    '(a double quote, a backslash, or a control character). Use the 64-character ' +
                    'hex key instead, or change the passphrase.');
  return `"${psk}"`;
}

// --- build the files that Wi-Fi + SSH map to (client-mode wpa block; root's keys) ---
export function overlayFilesFor({ ssid, psk, sshKey }) {
  const files = {};
  if (ssid) files['/etc/wpa_supplicant.conf'] =
    `ctrl_interface=/run/wpa_supplicant\nupdate_config=1\nap_scan=1\n\nnetwork={\n\tssid=${wpaSsid(ssid)}\n\tpsk=${wpaPsk(psk || '')}\n}\n`;
  if (sshKey && sshKey.trim()) files['/root/.ssh/authorized_keys'] = sshKey.trim() + '\n';
  return files;
}

// Write { '/etc/foo': content } into the MEMFS overlay tree under `base`+`prefix`.
// Everything is chowned root:root with sane perms (0644 files / 0755 dirs) so the
// files are valid overlay content - and so dropbear accepts authorized_keys.
function writeFiles(FS, base, prefix, entries) {
  const dirs = new Set();
  for (const [p, content] of entries) {
    const full = base + prefix + '/' + p.replace(/^\/+/, '');
    const dir = full.slice(0, full.lastIndexOf('/'));
    FS.mkdirTree(dir);
    FS.writeFile(full, content);
    FS.chmod(full, 0o644); FS.chown(full, 0, 0); FS.utime(full, MT, MT);
    let d = dir; while (d.length > base.length) { dirs.add(d); d = d.slice(0, d.lastIndexOf('/')); }
  }
  for (const d of dirs) { FS.chmod(d, 0o755); FS.chown(d, 0, 0); FS.utime(d, MT, MT); }
}

async function injectNor(u8, info, entries) {
  const M = await (await engine('mkfs_jffs2_memfs'))({ print: () => {}, printErr: () => {} });
  writeFiles(M.FS, '/in', '', entries);
  M.callMain(['--little-endian', '--squash', `--eraseblock=0x${ALIGN.toString(16)}`,
              `--pad=0x${info.size.toString(16)}`, '-d', '/in', '-o', '/out.jffs2']);
  const overlay = M.FS.readFile('/out.jffs2');
  if (overlay.length > info.size) throw new Error('too much data for the NOR overlay partition');
  const out = new Uint8Array(u8); out.set(overlay, info.offset); return out;
}

// --- NAND UBI reader (extract kernel/rootfs/uboot-env volumes for the rebuild) ---
const EC_MAGIC = 0x55424923, VID_MAGIC = 0x55424921;
export function readUbiVolumes(ubi) {
  const be32 = o => ((ubi[o] << 24) | (ubi[o+1] << 16) | (ubi[o+2] << 8) | ubi[o+3]) >>> 0;
  let first = -1;
  for (let b = 0; b + 4 <= ubi.length; b += 0x800) { if (be32(b) === EC_MAGIC) { first = b; break; } }
  if (first < 0) throw new Error('no UBI in image');
  const dataOff = be32(first + 20);
  let peb = 0;
  for (let b = first + 0x800; b + 4 <= ubi.length; b += 0x800) { if (be32(b) === EC_MAGIC) { peb = b - first; break; } }
  if (!peb) peb = 0x20000;
  const vols = {};
  for (let base = first; base + 64 <= ubi.length; base += peb) {
    if (be32(base) !== EC_MAGIC) continue;
    const vidOff = be32(base + 16), dOff = be32(base + 20), vb = base + vidOff;
    if (be32(vb) !== VID_MAGIC) continue;
    const type = ubi[vb + 5], volId = be32(vb + 8), lnum = be32(vb + 12), dataSize = be32(vb + 20);
    const leb = ubi.subarray(base + dOff, base + dOff + (peb - dOff));
    (vols[volId] = vols[volId] || { type, lebs: {} }).lebs[lnum] = { leb, dataSize };
  }
  const out = {};
  for (const [vid, v] of Object.entries(vols)) {
    if (+vid >= 0x7fffef00) continue;
    const lnums = Object.keys(v.lebs).map(Number).sort((a, b) => a - b);
    const parts = lnums.map(ln => { const { leb, dataSize } = v.lebs[ln]; return v.type === 2 ? leb.subarray(0, dataSize) : leb; });
    const n = parts.reduce((s, a) => s + a.length, 0), image = new Uint8Array(n);
    let p = 0; for (const a of parts) { image.set(a, p); p += a.length; }
    out[vid] = { type: v.type, image };
  }
  return { vols: out, peb, dataOff, lebSize: peb - dataOff };
}

async function injectNand(u8, info, entries) {
  const { vols, peb, lebSize, dataOff } = readUbiVolumes(u8.subarray(info.ubiStart));
  if (!vols[0] || !vols[1] || !vols[2]) throw new Error('unexpected UBI layout (need uboot-env/kernel/rootfs)');
  const page = dataOff / 2;

  const mk = await (await engine('mkfs_ubifs_memfs'))({ print: () => {}, printErr: () => {} });
  writeFiles(mk.FS, '/in', '/root', entries);          // NAND upperdir = <overlay>/root
  mk.callMain(['-m', String(page), '-e', String(lebSize), '-c', String(OVERLAY_MAX_LEBS), '-r', '/in', '-o', '/ov.ubifs']);
  const overlay = mk.FS.readFile('/ov.ubifs');

  const ub = await (await engine('ubinize_memfs'))({ print: () => {}, printErr: () => {} });
  ub.FS.writeFile('/v0', vols[0].image); ub.FS.writeFile('/v1', vols[1].image);
  ub.FS.writeFile('/v2', vols[2].image); ub.FS.writeFile('/ov.ubifs', overlay);
  const ovSize = Math.ceil(overlay.length / lebSize) * lebSize;
  ub.FS.writeFile('/c.cfg',
    `[uboot-env]\nmode=ubi\nvol_id=0\nvol_type=dynamic\nvol_name=uboot-env\nvol_size=256KiB\nimage=/v0\n\n` +
    `[kernel]\nmode=ubi\nvol_id=1\nvol_type=static\nvol_name=kernel\nimage=/v1\n\n` +
    `[rootfs]\nmode=ubi\nvol_id=2\nvol_type=static\nvol_name=rootfs\nimage=/v2\n\n` +
    `[overlay]\nmode=ubi\nvol_id=3\nvol_type=dynamic\nvol_name=overlay\nvol_size=${ovSize}\nvol_flags=autoresize\nimage=/ov.ubifs\n`);
  ub.callMain(['-o', '/out.ubi', '-p', '0x' + peb.toString(16), '-m', '0x' + page.toString(16), '/c.cfg']);
  const newUbi = ub.FS.readFile('/out.ubi');

  const out = new Uint8Array(info.ubiStart + newUbi.length);
  out.set(u8.subarray(0, info.ubiStart), 0);
  out.set(newUbi, info.ubiStart);
  return out;
}

// --- public entry: inject { '/abs/path': content, ... } into the overlay --------
export async function injectOverlay(u8, files) {
  const entries = Object.entries(files).filter(([, v]) => v != null && v !== '');
  if (!entries.length) return u8;                      // nothing to inject -> unchanged
  const info = overlayInfo(u8);
  if (!info.ok) throw new Error(info.reason);
  return info.type === 'nand' ? injectNand(u8, info, entries) : injectNor(u8, info, entries);
}
