# thingino-dfu

USB flashing for Ingenic XBurst cameras, in Rust: the `thingino-dfu` command-line tool,
the `dfu-remote` daemon for flashing over the network, the browser flasher on WebUSB, and
the Android library that [thingino-app](https://github.com/thingino/thingino-app) loads.

Based on the original thingino-dfu by wltechblog,
[wltechblog/thingino-dfu](https://github.com/wltechblog/thingino-dfu): the C tool whose
behaviour this rewrite reproduces, whose USB loaders it still uses, and whose device
protocols, command line, daemon wire format and browser flasher it keeps compatible. That
repository is archived; this one continues it. The USB loaders are the thingino USB-boot
builds of U-Boot published by [gtxaspec/u-boot](https://github.com/gtxaspec/u-boot) in its
`usbboot` release: every build fetches the latest ones, and each release archive names
the U-Boot commit its loaders were built from.

## What it does

- Identifies the SoC of a camera in USB boot mode from three register reads, with nothing
  uploaded and nothing executed on the device. Every family the loaders cover is known:
  T10, T20, T21, T23, T30, T31, T32, T33, T40, T41 and A1, 34 loader variants in all.
- Bootstraps the camera: uploads the stage-1 image and U-Boot, which re-enumerates as a
  DFU gadget.
- Reads the flash, writes an image with an optional read-back verify, erases, and reboots,
  all over DFU.
- Reads the eFuse, serial and secure-boot state of a bootrom device, read-only (`--diag`).
- Does all of it locally over USB, through a daemon on another machine, or from a browser.

## Install

Releases carry six archives. Four of them hold `thingino-dfu`, `dfu-remote`, the
`firmware/dfu/` loader tree and a README for that platform. The web archive is the browser
flasher, a static site with no binary in it, and the Android one is the library
`thingino-app` loads. `SHA256SUMS` is published beside them all.

| download | for |
|---|---|
| `thingino-dfu-linux-x86_64.tar.gz` | Linux, Intel or AMD |
| `thingino-dfu-linux-aarch64.tar.gz` | Linux, arm64 |
| `thingino-dfu-windows-x64.zip` | Windows |
| `thingino-dfu-macos-universal.tar.gz` | macOS, arm64 and x86_64 in one binary |
| `thingino-dfu-web.tar.gz` | the browser flasher, served rather than installed |
| `libtdfu-android-<version>.tar.gz` | the Android library and loaders, for thingino-app |

Unpack and run; there is nothing to build. Keep the directory whole: both binaries look
for `firmware/dfu/` beside themselves.

```
tar xzf thingino-dfu-linux-x86_64.tar.gz
./thingino-dfu-linux-x86_64/thingino-dfu -l
```

**Linux** needs a udev rule for raw USB access. A camera is two USB devices over one
flash cycle, the bootrom before bootstrap and the U-Boot DFU gadget after, both under
Ingenic's vendor id `a108`, so one rule covers both. The browser flasher needs the same
rule.

```
sudo tee /etc/udev/rules.d/99-thingino-dfu.rules >/dev/null <<'EOF'
# bootrom a108:c309, U-Boot DFU gadget a108:4d44
SUBSYSTEM=="usb", ATTR{idVendor}=="a108", MODE="0666", TAG+="uaccess"
# X series bootrom
SUBSYSTEM=="usb", ATTR{idVendor}=="601a", MODE="0666", TAG+="uaccess"
EOF
sudo udevadm control --reload-rules && sudo udevadm trigger
```

Then unplug and replug the camera; without the rule the tool reports access denied.

**Windows** has no built-in driver the tool can claim, so install WinUSB with
[Zadig](https://zadig.akeo.ie/), once for each of the two USB devices. Remove the Ingenic
vendor driver (`libusb0.sys`) first if it is installed; then Zadig on **Ingenic USB Boot
Device** (`A108:C309`), bootstrap with `thingino-dfu.exe -b`, and Zadig again on the **USB
download gadget** (`A108:4D44`) that appears. One time, per machine.

**macOS** needs nothing: the binaries are universal and macOS grants USB access to the
user. A downloaded archive is quarantined, so `xattr -dr com.apple.quarantine
thingino-dfu-macos-universal` if Gatekeeper refuses to run it.

**The browser flasher** is served, not installed: unpack it under any document root and
open it in Chrome or Edge. WebUSB needs a secure context, which means HTTPS, and
`http://localhost` counts as one. The hosted copy is at
[webflash.thingino.com](https://webflash.thingino.com/).

## Usage

```
thingino-dfu -l                         # list every Ingenic device on the bus
thingino-dfu -b                         # bootstrap a bootrom into U-Boot DFU mode
thingino-dfu -r backup.bin              # read the whole flash
thingino-dfu -w image.bin --verify      # write, then read back and compare
thingino-dfu --erase -w image.bin       # erase the whole flash first (NAND, or a smaller image)
thingino-dfu -w image.bin --reboot      # reboot when everything else is done
thingino-dfu --diag                     # eFuse, serial and secure-boot state, read-only
```

Operations run in a fixed order whatever order they are typed in: bootstrap, erase, write,
verify, read, reboot. A write or a read bootstraps a bootrom device first when it has to.
`-i` picks a device by the number `-l` gave it, `--alt` a DFU alt setting by name or
number, `--cpu` forces the SoC variant instead of detecting it, `--spl` and `--uboot`
substitute your own loader images, `--firmware-dir` points at another loader tree, and
`--size` stops a read after that many bytes. `--help` has the full list.

### Over the network

Run the daemon on the machine the camera is plugged into and point the tool at it:

```
dfu-remote --port 5050 --token secret          # on the machine with the camera
thingino-dfu --host camera-host:5050 -w image.bin --verify
```

`dfu-remote` listens on every interface unless `--bind` names one, and `-d` turns on
debug output. The wire is plaintext: there is no TLS, and without `--token` there is no
authentication either, so anything that can reach the port can read the camera's flash or
write to it. Use `--bind 127.0.0.1` or a `--token` on anything but a trusted network.

The defences it does have:

- **Origin.** A browser request carrying an `Origin` header is refused unless
  `--allow-origin` named that origin (repeat the flag for more than one), so a page you
  did not serve cannot drive your daemon. `--allow-any-origin` turns that off deliberately.
  A client that sends no `Origin` at all, which is every non-browser client, is unaffected.
- **The token.** `--token` requires the secret from every client. It is checked before the
  request body is read, and a wrong one costs the connection a delay that grows with each
  wrong answer, so guessing over the network is slow.
- **Timeouts.** A client that connects and says nothing, that goes quiet part way through a
  frame, or that holds a connection idle is dropped, and a whole request has a deadline of
  its own so a peer that keeps trickling bytes cannot hold the daemon for ever. `0`
  switches any of them off.

The browser flasher's remote mode talks to the same daemon.

### The browser flasher

Chrome or Edge, on WebUSB: the page identifies the camera, bootstraps it from the loaders it
serves, reads and writes the flash, and can flash a prebuilt thingino firmware release
picked by branch. Its remote mode drives a `dfu-remote` daemon instead of a local device.

### Android

`libtdfu-android-<version>.tar.gz` holds `jniLibs/<abi>/libtdfu_jni.so` for `arm64-v8a`
and `armeabi-v7a`, linked for 16 KB page sizes, plus the loader tree. thingino-app pins a
version of it in its Gradle build and loads the library unchanged.

## Building from source

The toolchain is pinned in `rust-toolchain.toml`.

```
git config core.hooksPath .githooks              # once per clone
cargo xtask fetch-loaders                        # the current loaders from the usbboot release
cargo build --release                            # thingino-dfu and dfu-remote
cargo xtask package --target linux-x86_64        # a release archive from this tree
cargo xtask web --release                        # the browser flasher into web/dist
cargo xtask package --target android             # the Android library (needs an NDK)
```

The web build needs the `wasm32-unknown-unknown` target and the `wasm-bindgen` CLI at the
version `Cargo.lock` names; the build prints the install command when they are missing.
The Android build needs an NDK (`ANDROID_NDK_HOME`) and the `aarch64-linux-android` and
`armv7-linux-androideabi` targets. Cutting a release is [`docs/release.md`](docs/release.md).

## Development

The pre-push hook runs the first part of the CI gate locally, in CI's order: `cargo fmt
--all --check`, `clippy` with pedantic lints and warnings denied, the workspace tests, and
the same clippy again for `wasm32-unknown-unknown` when that target is installed. It does
not run `cargo deny`, `typos` or `cargo machete`; those run in CI, and `docs/release.md`
lists them for anyone checking a tree by hand. It also refuses a push that would put a
private address or home path into a tracked file, in the working tree and in every commit
being pushed alike; `.githooks/test-pre-push` drives that scan.

| document | what it is |
|---|---|
| [`AGENTS.md`](AGENTS.md) | The engineering rules for anyone, human or coding agent, working on this tree: what is not negotiable, the standards, the decisions already made, and how to work on the bench. |
| [`docs/release.md`](docs/release.md) | How a release is cut. |

## License

GPL-2.0-or-later, the same as the original thingino-dfu it is based on. See
[`LICENSE`](LICENSE).
