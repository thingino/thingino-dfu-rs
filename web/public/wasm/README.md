# Vendored overlay injectors

These six files are **prebuilt binaries**. Nothing in this repository compiles them, and
nothing here should: they are C, built with Emscripten, and keeping that toolchain out of
this tree is the whole point of vendoring them.

| file | what it is |
|---|---|
| `mkfs_jffs2_memfs.mjs` / `.wasm` | `mkfs.jffs2`, repacking the NOR JFFS2 overlay |
| `mkfs_ubifs_memfs.mjs` / `.wasm` | `mkfs.ubifs`, a fresh UBIFS overlay volume (NAND) |
| `ubinize_memfs.mjs` / `.wasm` | `ubinize`, reassembling the NAND UBI image |

`web/src/inject.js` imports the `.mjs` at run time from `/wasm/`, on first use of the
Pre-configure panel; each `.mjs` loads its `.wasm` sibling. Both halves of a pair belong
together, so replace them together.

## Source

They come from **mtd-utils 2.3.1**, built by `web/wasm-inject/build-wasm.sh` in the C
repository (`thingino-dfu`), which extracts the pinned `mtd-utils-2.3.1.tar.bz2` beside it,
applies the small musl/Emscripten compat stubs in `web/wasm-inject/stubs/`, configures with
a libuuid stub, and relinks the three tools as MEMFS ES modules
(`-sMODULARIZE=1 -sEXPORT_ES6=1 -sEXPORTED_RUNTIME_METHODS=callMain,FS -sINVOKE_RUN=0
-sEXIT_RUNTIME=0 -sFORCE_FILESYSTEM=1 -sALLOW_MEMORY_GROWTH=1`).

**That script is the only place they are rebuilt.** To refresh them: run it in a checkout
of the C repository with an Emscripten environment active, then copy its output
(`web/public/wasm/`) over this directory and update the hashes below.

Built 2026-09-03 with Emscripten 5.0.4 (`62e22652509fbe7a00609ce48a653d0d66f27ba5`). The C
repository's `web/build.sh` pins EMSDK 6.0.1, but that pin exists for the shape of the glue
that its post-link TextDecoder patch rewrites, a file this repository does not have and
does not build. These three modules take no such patch.

```
667ca69b93dacc6b3766422b5825b33e2a5fe6630d551a8ee770de5cf95de647  mkfs_jffs2_memfs.mjs
3357879667b26f981d5b4a5827394e55b88000f2963a5e5b807f4ac1f109de68  mkfs_jffs2_memfs.wasm
38674b21348e0876f684c0f5c868938d32e341ff01a2559bfbfd6c888380c5a8  mkfs_ubifs_memfs.mjs
d0dad73fb4839fa871c7974ddb6ba45e5e8c5a03df0986a647e5ec436a93aeb2  mkfs_ubifs_memfs.wasm
1ce06e40eabe1ee67df6cc51309e5a7757b180310656e5814040b2981d833a7d  ubinize_memfs.mjs
5f3e801819972e4e64c9b8c270c33cace1ec432bc2f655282eaf1d77d224b3e8  ubinize_memfs.wasm
```

## Why they are committed and not fetched

The C repository gitignores `web/public/wasm/`, and its GitHub Pages workflow never runs
`build-wasm.sh`, so there is no published copy of these anywhere to fetch, and the live
site's Pre-configure panel loads nothing. Committing them is what makes the feature work
here: prebuilt, vendored artifacts, rebuilt only by the script above.
