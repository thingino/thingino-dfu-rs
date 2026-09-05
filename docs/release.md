# Cutting a release

`v2.0.0` ships from this repository. Pre-parity builds tag as
`v2.0.0-alpha.N` / `-rc.N` and publish as prereleases, so they never show as Latest;
the final `v2.0.0` drops the suffix and does.

Two steps are the maintainer's and nobody else's: **pushing `main`** and **creating the
tag**. Everything else is a workflow or an `xtask` command anyone can run.

---

## What ships

Six archives, in the C tool's layout and under the C tool's names, because a user's
download link has to survive the cutover unchanged:

| archive | contains |
|---|---|
| `thingino-dfu-linux-x86_64.tar.gz` | `thingino-dfu`, `dfu-remote`, `README.md`, `firmware/dfu/<variant>/` |
| `thingino-dfu-linux-aarch64.tar.gz` | the same |
| `thingino-dfu-windows-x64.zip` | the same, with `.exe` |
| `thingino-dfu-macos-universal.tar.gz` | the same, `lipo`'d for arm64 and x86_64 |
| `thingino-dfu-web.tar.gz` | `thingino-dfu-web/` = the built flasher, which carries its own `firmware/dfu/` |
| `libtdfu-android-<version>.tar.gz` | `./`{`README`, `jniLibs/<abi>/libtdfu_jni.so` for arm64-v8a and armeabi-v7a, `firmware/dfu/<variant>/`}, the drop-in `thingino-app` unpacks |

plus `SHA256SUMS` over all six. The Android tarball is built by its own `release.yml` job
with the runner's NDK, and unlike the five `thingino-dfu-*` archives it carries the version
in its name (what the app pins). Its gate, `thingino-app` pinning the tarball, building and
flashing a device, is the maintainer's.

Every archive is built by one command:

```
cargo xtask package --target <triple or name> [--out dist] [--no-build]
```

and the release workflow's job bodies are that command and nothing else, so a local
archive and a published one cannot drift. `--target` takes either spelling
(`linux-aarch64` or `aarch64-unknown-linux-gnu`); `web` and `macos-universal` have only
the name. An unknown target is refused with the list of six, never defaulted.

The archives are **deterministic**: fixed timestamps, fixed modes, owner 0:0. The same
commit packaged twice gives byte-identical files. That is what makes "never reuse a tag
with different bytes" (below) checkable rather than a promise.

---

## Before you tag

1. **The gate is green.** `cargo fmt --all --check`, host clippy,
   `cargo test --locked --workspace --all-features`, wasm clippy, `cargo deny check`,
   `typos`, `cargo machete --skip-target-dir`. The pre-push hook runs the first four of
   those, in that order, and skips the wasm leg when the target is not installed; the last
   three it never runs, so run them by hand if you are not pushing. A tag runs the whole
   of `ci.yml` before anything is built, so a tag on an ungated commit fails there rather
   than shipping.
2. **The hardware pass is green on every SoC in the table.** The maintainers run it
   outside this repository, with the `linux-aarch64` archive's own binaries rather than a
   `cargo build`, because the archive is what a user gets; the register captures it
   produced are under `crates/tdfu-core/tests/fixtures/results/`.
3. **Windows and macOS have been run against a device**, on a maintainer's desktop, and
   recorded with the rest. Those two targets are cross-compiled here and have never been
   on hardware otherwise.
4. **The version line says what you are about to tag:**

   ```
   cargo xtask package --print-version        # 2.0.0-alpha.1
   cargo xtask package --check-tag v2.0.0-alpha.1
   ```

   The second exits non-zero, printing both values, if the tag and
   `workspace.package.version` are not the same release. The release job runs the same
   check, so a mismatch stops the publish rather than shipping an archive that calls
   itself something else.
5. **A dry run has passed on this commit** (below), so the first tag run is a repeat of
   something that already worked.

### Bumping the version

`workspace.package.version` in the root `Cargo.toml` is the only place the version is
written; every crate inherits it and `crates/tdfu-cli/src/banner.rs` reads it through
`CARGO_PKG_VERSION`. Bump it **in its own commit**, with `Cargo.lock` and
`fuzz/Cargo.lock` regenerated in the same commit:

```
# edit Cargo.toml: version = "2.0.0-alpha.2", and the three workspace.dependencies pins
cargo update -w --offline
cargo update --manifest-path fuzz/Cargo.toml -w --offline
git add Cargo.toml Cargo.lock fuzz/Cargo.lock
git commit -m "release: workspace version 2.0.0-alpha.2"
```

Which number to bump: `-alpha.N` while the hardware pass is still being filled in,
`-rc.N` once it is green and only release mechanics are left, and `2.0.0` for the release
itself. Anything with a `-` publishes with `--prerelease`; that rule is semver's, read off
the tag, so a suffix nobody has used yet needs no code change.

---

## The dry run

The whole file is exercised on a branch, without a tag, before any tag exists:

```
gh workflow run release.yml --ref <branch> -f dry_run=true
gh run watch
```

It builds all six archives, uploads them as run artifacts, downloads them again, merges
the six `SHA256SUMS` lines, verifies them with `sha256sum -c`, runs the version check
against the tag this tree *would* need, and then stops at a step that says nothing is
published. What the run's artifact list must show, and nothing else:

```
thingino-dfu-linux-x86_64      thingino-dfu-linux-x86_64.tar.gz      + SHA256SUMS
thingino-dfu-linux-aarch64     thingino-dfu-linux-aarch64.tar.gz     + SHA256SUMS
thingino-dfu-windows-x64       thingino-dfu-windows-x64.zip          + SHA256SUMS
thingino-dfu-macos-universal   thingino-dfu-macos-universal.tar.gz   + SHA256SUMS
thingino-dfu-web               thingino-dfu-web.tar.gz               + SHA256SUMS
libtdfu-android                libtdfu-android-<version>.tar.gz      + SHA256SUMS
```

The `release` job's **Gather** step counts them: six archives, no more and no fewer, or
it fails. A leg that silently produced nothing must not become a release with a download
missing.

`-f dry_run=false` on a branch still publishes nothing, because the publish step also
requires a tag ref. The two conditions are deliberately separate.

---

## Cutting it

The two maintainer steps are marked.

1. **Maintainer: push `main`.** Nothing is tagged that is not on `main`.

   ```
   git push origin main
   ```

2. **Maintainer: tag and push the tag.** Annotated, never lightweight: the tag message is what
   `git show` gives a reader six months later.

   ```
   git tag -a v2.0.0-alpha.1 -m "thingino-dfu 2.0.0-alpha.1"
   git push origin v2.0.0-alpha.1
   ```

3. Watch the run:

   ```
   gh run watch
   gh run view --log-failed        # if it stops
   ```

4. The release appears at `gh release view v2.0.0-alpha.1`, marked **Pre-release**, with
   the six archives, `SHA256SUMS`, and the notes `--generate-notes` wrote.

5. Check what a user gets, on the archive from the release rather than the one in `dist/`:

   ```
   gh release download v2.0.0-alpha.1 -p 'thingino-dfu-linux-x86_64.tar.gz' -p SHA256SUMS
   sha256sum -c --ignore-missing SHA256SUMS
   tar xzf thingino-dfu-linux-x86_64.tar.gz
   ./thingino-dfu-linux-x86_64/thingino-dfu -l      # banner shows the tag's short hash
   ```

   The banner is `thingino-dfu <version> (<hash>)` on stderr, and `dfu-remote` prints the
   same with its own name. A local `cargo build` says `(unknown)` instead, which is
   correct: `TDFU_GIT_HASH` is set by the workflow and by `cargo xtask package`, and
   nothing guesses.

---

## Release notes

`--generate-notes` writes the commit list, and it is the whole of the notes. It also sets
the release title from the tag. Nothing is hand-written, so the commit messages are the
release notes: write them for the person reading the release page.

---

## Re-cutting a broken prerelease

**Never reuse a tag with different bytes.** Somebody has already downloaded the first one,
and a tag that points at two different trees is unfixable afterwards. If a prerelease is
wrong:

```
gh release delete v2.0.0-alpha.1 --yes      # the release, and its assets
git push origin :refs/tags/v2.0.0-alpha.1   # the remote tag
git tag -d v2.0.0-alpha.1                   # the local one
```

then fix the problem, **bump to `-alpha.2`** and cut that. Deleting is for a tag nobody
could have used yet -- a failed workflow that published a half-set, a tag pushed by
mistake minutes ago. It is not a way to change what an existing version contains.

If the tag is right and only the workflow failed, re-run the failed jobs
(`gh run rerun --failed`); nothing needs a new tag for that, and the archives are
deterministic, so a re-run produces the same bytes.

---

## What this workflow does not do

- **It does not deploy the flasher.** Where the browser flasher is served is a cutover
  question. `thingino-dfu-web.tar.gz` is published as a download and nothing is
  pushed to Pages from here.
- **It does not build or flash the Android app.** `release.yml` builds the
  `libtdfu-android-<version>.tar.gz` drop-in: `tdfu-jni` as `libtdfu_jni.so`
  per ABI plus the loader assets, in the layout the app unpacks. Pinning that tarball,
  building `thingino-app` and flashing a device is the maintainer's gate, not this
  workflow's.
- **It does not choose the loaders.** Every build fetches the current `usbboot` release of
  `gtxaspec/u-boot`, so a release ships whatever that release held when the job ran. Each
  archive's `README.md` names the U-Boot commit its loaders were built from, so which
  loaders a user has is a fact they can read rather than infer. To ship different loaders,
  roll that release first.
