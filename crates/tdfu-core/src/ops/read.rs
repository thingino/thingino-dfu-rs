//! Read a flash alt back.
//!
//! The whole operation is one streaming loop, and both of the C's read bugs are
//! designed out of it rather than fixed in it:
//!
//! * **A failed write to the sink does not restart the chip read.** `dfu.c:839-842`
//!   sets `TDFU_ERROR_FILE_IO` and breaks with `block` still 0, so `dfu.c:855`'s
//!   `r == TDFU_SUCCESS || block != 0` reads it as a stale block-0 transaction and
//!   re-reads the entire flash — 256 MiB of it on a T40XP — into a sink that has
//!   already said it cannot take bytes.
//! * **A byte cap is exact.** `dfu.c:839` writes the whole block and only then tests
//!   `total >= size` at `:852`, so `--size` overshoots by up to `transfer_size - 1`.
//!   Here the cap is applied to the block *before* it reaches `out`.

use tdfu_usb::LocalUsbTransport;

use crate::clock::Sleeper;
use crate::dfu::FLASH_ALT;
use crate::dfu::descriptors::read_info;
use crate::dfu::host::{self, Transaction};
use crate::error::{Error, Result};
use crate::model::{AltSel, DfuInfo};
use crate::progress::{Phase, Progress, ProgressSink};

/// Upload from `alt` into `out`, at most `limit` bytes, returning how many were read.
///
/// `UPLOAD` blocks of `wTransferSize` bytes with **no `GETSTATUS` between them**, and a
/// short block ends the read (`dfu.c:830-854`; pin
/// `op_read_short_block_ends`). Every block is streamed into `out` as it arrives, so a
/// 256 MiB NAND alt never buffers — that case is real, and it is why
/// this operation exists in this shape: a T40XP whole-chip read is four times the
/// daemon's payload cap.
///
/// `limit` is a cap on what reaches `out`, not on what is asked for: every request is
/// still a full `wTransferSize` block, exactly as the C sends it, and the **last block
/// is truncated before it is written**. `Some(0)` therefore reads nothing and issues no
/// `UPLOAD` at all; the C cannot express that, because its `size` argument collapses
/// "no cap" and "a cap of zero" into one value (`dfu.c:852`).
///
/// **A retry can only happen while nothing has reached `out`.** The C affords a full
/// re-run because it owns the file — `rewind(f)` per attempt (`dfu.c:826`) and a
/// truncating `fopen(path, "wb")` on reopen (`:801`) — while a `Write` sink has
/// neither. Bounding retries to "nothing emitted yet" covers every failure the bus
/// reset and the block 0 retry were written for (a wedged EP0 fails the descriptor
/// read, the claim, `make_idle`, or block 0) and can never duplicate output.
/// Both retries announce themselves, through [`reset_and_retry_once`] and
/// [`retry_stale_block0`] respectively.
///
/// [`reset_and_retry_once`]: crate::dfu::host::reset_and_retry_once
/// [`retry_stale_block0`]: crate::dfu::host::retry_stale_block0
///
/// The count is both returned **and** announced as a [`Progress::Note`], because
/// completion lines live in core so that every frontend gets them once from
/// one place.
/// The CLI must not print a second one: it is wired (`Session::read`) and it
/// does not — it discards the returned count and renders core's notes
/// verbatim, and its own doc says why.
///
/// # Errors
/// [`Error::MissingAlt`] or [`Error::Invalid`] if `alt` names nothing on the device,
/// [`Error::Io`] if `out` refuses a block — naming the offset it refused at — or the
/// transport's own error.
pub async fn read<T: LocalUsbTransport, C: Sleeper>(
    dev: &T,
    clock: &C,
    alt: &AltSel,
    limit: Option<u64>,
    out: &mut dyn std::io::Write,
    progress: ProgressSink<'_>,
) -> Result<u64> {
    let mut output = Output::new(out, limit);

    // The recovery reset, gated on nothing having reached `out`. The gate is the
    // inner `Result`: an `Err` is a failure the helper may answer with a bus reset and
    // one more attempt, and an `Ok(Err(_))` is a failure that is already the answer.
    // Expressing it this way keeps the reset in its one home instead of growing a
    // second, subtly different copy here — the reset/re-open seam is a scheduled
    // change to that home, and a copy would not receive it.
    let attempted = host::reset_and_retry_once(
        dev,
        clock,
        &mut *progress,
        async |_attempt, progress| match one_attempt(dev, alt, &mut output, progress).await {
            Err(error) if !output.touched() => Err(error),
            answered => Ok(answered),
        },
    )
    .await?;

    let total = attempted?;
    progress(Progress::Note(complete_note(total)));
    Ok(total)
}

/// The C's `DFU upload complete: %u bytes` (`dfu.c:861`), the one completion line.
/// Kept in one place so a frontend can recognise it and a test can pin it.
fn complete_note(total: u64) -> String {
    format!("DFU upload complete: {total} bytes")
}

/// One whole attempt: descriptors, alt, claim, transfer, release.
///
/// The claim is per attempt because the bus reset drops it (USB 9.1.1.5), and the
/// release runs on **every** path out — an interface
/// left claimed by a failed read is what the next run trips over.
///
/// The descriptors are re-read per attempt too, as the C's `dfu_upload_impl` does by
/// re-entering `tdfu_dfu_read_device` (`dfu.c:979-989`): after a bus reset the previous
/// `DfuInfo` describes a device that no longer exists.
async fn one_attempt<T: LocalUsbTransport>(
    dev: &T,
    selection: &AltSel,
    output: &mut Output<'_>,
    progress: ProgressSink<'_>,
) -> Result<u64> {
    let info = read_info(dev).await?;
    // The descriptors, then one line per alt, then which alt is being claimed and why:
    // the C's `dfu.c:794`, `:808` and `core.c:159`, `:162`, `:177`, and the facts an
    // operator otherwise has to guess at when a read lands on the wrong part of a chip.
    progress(Progress::Debug(descriptors_line(&info)));
    for entry in &info.alts {
        progress(Progress::Debug(alt_line(entry)));
    }
    let alt = crate::dfu::resolve_alt(&info, selection)?;
    progress(Progress::Debug(claiming_line(&info, selection, alt)));
    // A claim that failed *part way* still has to be undone: `host::claim` sends
    // `SET_INTERFACE` after `claim_interface`, so a stalled alt select leaves the
    // interface held (over WebUSB a stalled `SET_INTERFACE` is exactly that). Releasing
    // an interface that is not claimed is `Ok(())`, so this costs nothing
    // on the paths where nothing was taken.
    if let Err(error) = host::claim(dev, &info, alt).await {
        drop(host::release(dev, info.interface).await);
        return Err(error);
    }
    progress(Progress::Debug(
        "the interface and alt are claimed; starting the upload".to_owned(),
    ));

    let outcome = transfer(dev, &info, output, progress).await;
    let released = host::release(dev, info.interface).await;

    // The transfer's failure is the interesting one; a release that also failed after it
    // tells the operator nothing they can act on.
    match outcome {
        Ok(total) => released.map(|()| total),
        Err(error) => Err(error),
    }
}

/// What the device's DFU descriptors said, for the debug channel.
///
/// The four facts the C put down its debug stream at `dfu.c:808` and `core.c:159`, which
/// are the four that decide how a transfer runs: the block size every request will use,
/// the DFU revision, how many alts there are to choose between, and which interface
/// carries them.
pub(crate) fn descriptors_line(info: &DfuInfo) -> String {
    format!(
        "DFU descriptors: transfer size {}, bcdDFU {:#06x}, {} alt(s), interface {}",
        info.transfer_size,
        info.bcd_dfu,
        info.alts.len(),
        info.interface
    )
}

/// One alt, by index and name (`core.c:162`).
///
/// A nameless alt is said to be nameless rather than printed as `""`: the C's own comment
/// blamed WebUSB for empty names, which was wrong, and a bare pair of
/// quotes reads like a bug in this tool rather than a descriptor the device did not
/// answer for.
pub(crate) fn alt_line(entry: &crate::model::DfuAlt) -> String {
    if entry.name.is_empty() {
        format!("alt {}: unnamed", entry.alt)
    } else {
        format!("alt {}: {}", entry.alt, entry.name)
    }
}

/// Which alt is about to be claimed, and why that one (`core.c:177`, `dfu.c:794`).
///
/// The "why" is the half worth having. An operator looking at a read that came back from
/// the wrong part of a chip wants to know whether this tool chose the alt or they did.
pub(crate) fn claiming_line(info: &DfuInfo, selection: &AltSel, alt: u8) -> String {
    let why = match selection {
        AltSel::Name(name) => format!("asked for by name, {name}"),
        AltSel::Index(index) => format!("asked for by index, {index}"),
        AltSel::Default if !info.is_multi_alt() => "the default, and the only alt this loader has".to_owned(),
        // `dfu::alt::default_alt` matches the *name* first and falls back to the first
        // alt only when the loader named none of them, so "the first alt" is false on
        // any loader that lists `flash` second or third — and telling the operator
        // which alt this tool chose, and by what rule, is the whole point of the line.
        AltSel::Default if info.alts.iter().any(|entry| entry.name == FLASH_ALT) => {
            format!("the default: the alt named {FLASH_ALT}")
        }
        AltSel::Default => "the default: the first alt, since this loader named none of them".to_owned(),
    };
    format!("claiming alt {alt} on interface {} ({why})", info.interface)
}

/// The transfer itself, with the claim in force, inside the block 0 retry.
///
/// [`retry_stale_block0`](crate::dfu::host::retry_stale_block0) supplies `make_idle`
/// before every attempt — which is what clears the STALL a stale block sequence causes
/// — and retries once if block 0 failed. Its gate is
/// [`Transaction::first_block_done`], which [`upload_loop`] sets **before** the first
/// write rather than after it, so a sink that fails on block 0 is never answered by
/// re-reading the chip.
async fn transfer<T: LocalUsbTransport>(
    dev: &T,
    info: &DfuInfo,
    output: &mut Output<'_>,
    progress: ProgressSink<'_>,
) -> Result<u64> {
    host::retry_stale_block0(dev, info.interface, progress, async |transaction, progress| {
        // Said once per attempt: a retry restarts the byte counter at zero, and a
        // frontend drawing a bar has to know that without inferring it.
        progress(Progress::Phase(Phase::Upload));
        upload_loop(dev, info, output, transaction, progress).await
    })
    .await
}

/// `UPLOAD` until a short block, the cap, or a failure.
///
/// **No `GETSTATUS` between blocks.** An `UPLOAD` needs none — the device answers with
/// the data or stalls — and a differential USB capture confirmed the C
/// request-for-request on this loop (4097 `UPLOAD`s and one `GETSTATUS` for a 16 MiB
/// read).
///
/// The block number is `u16` and is advanced with `wrapping_add`, because at 65536
/// blocks — 256 MiB at `wTransferSize` 4096, a T40XP whole-chip read — it wraps back
/// through 0. Nothing here tests it for 0: that test is the C's bug in all three of its
/// transfer loops (`dfu.c:602`, `:855`, `:955`).
async fn upload_loop<T: LocalUsbTransport>(
    dev: &T,
    info: &DfuInfo,
    output: &mut Output<'_>,
    transaction: &Transaction,
    progress: ProgressSink<'_>,
) -> Result<u64> {
    let asked = info.transfer_size;
    let mut block: u16 = 0;
    // Whether the device's last answer left its read transaction open, which is the
    // case for every full block. A short block is the loader's own end of transaction
    // and needs nothing from the host.
    let mut left_open = false;

    while !output.is_full() {
        // Narrated rather than propagated bare: which block died, and how far the read
        // had got, are what an operator needs to tell a bad cable from a bad chip
        // (`dfu.c:834`). One line per *failure*, never per block.
        let data = match host::upload(dev, info.interface, block, asked).await {
            Ok(data) => data,
            Err(err) => {
                progress(Progress::Debug(format!(
                    "upload: block {block} failed after {} bytes ({err})",
                    output.written()
                )));
                return Err(err);
            }
        };
        let got = data.len();

        if got > 0 {
            // Before the write, not after it: `write_all` may fail having already moved
            // bytes, and a retry that ran after that would duplicate them. This is the
            // explicit "nothing emitted" fact the block 0 gate is built on — never
            // `block == 0`.
            transaction.first_block_done();
            output.write(&data)?;
            progress(Progress::Bytes {
                phase: Phase::Upload,
                done: output.written(),
                total: output.limit(),
            });
        }

        let answered = block;
        block = block.wrapping_add(1);

        // A short block is the end of the upload (`dfu.c:847-850`). `got == 0` is the
        // same end, and testing it is also what stops a `wTransferSize` of 0 from
        // looping for ever on `0 < 0` — the parser substitutes 1024 for it, as
        // the C does at `dfu.c:282-283`, so it is unreachable, but a flashing tool that
        // can hang on a malformed descriptor is not one to have on a bench.
        if got == 0 || got < usize::from(asked) {
            // The one line that explains a read's length. A whole-chip read has no
            // knowable total, so this is where the total comes from, and
            // `dfu.c:848` narrated the same four facts for the same reason.
            progress(Progress::Debug(format!(
                "upload: block {answered} answered {got} of {asked} bytes, so the upload ends at {} bytes",
                output.written()
            )));
            return Ok(output.written());
        }
        left_open = true;
    }

    if left_open {
        // The cap ended the read, not the device: `--size` on a block boundary stops
        // after a full block, which leaves U-Boot's read transaction inited with its
        // sequence counter part way along — and on a loader without `3d4848fe0dc` that
        // survives `DFU_ABORT`, an alt switch and a bus reset. Closing it here is what
        // stops the next operation paying a stale-block-0 retry it did not earn. Best
        // effort, as `erase`'s close-out is: the bytes are already in `out`, and a
        // tidy-up request that stalled says nothing about them.
        drop(host::abort(dev, info.interface).await);
    }
    Ok(output.written())
}

/// The read's output, and the two facts about it that decide what may be retried.
///
/// Both are needed and they are not the same fact: [`written`](Output::written) is what
/// `out` has accepted, and is the count the operation returns; [`touched`](Output::touched)
/// is whether `out` has been *handed* anything, which becomes true one instant earlier —
/// before a `write_all` that may fail part-way through.
struct Output<'a> {
    out: &'a mut dyn std::io::Write,
    limit: Option<u64>,
    written: u64,
    touched: bool,
}

impl<'a> Output<'a> {
    fn new(out: &'a mut dyn std::io::Write, limit: Option<u64>) -> Self {
        Self {
            out,
            limit,
            written: 0,
            touched: false,
        }
    }

    /// Bytes `out` has accepted.
    const fn written(&self) -> u64 {
        self.written
    }

    /// The cap, which is also `Progress::Bytes`'s `total`: a read with no cap has no
    /// knowable total, because a DFU upload ends on a short block.
    const fn limit(&self) -> Option<u64> {
        self.limit
    }

    /// Has anything been handed to `out`? Once this is true, nothing may be retried.
    const fn touched(&self) -> bool {
        self.touched
    }

    /// Is the cap reached? Checked before each `UPLOAD`, which is what makes
    /// `Some(0)` read nothing at all.
    const fn is_full(&self) -> bool {
        match self.limit {
            Some(cap) => self.written >= cap,
            None => false,
        }
    }

    /// Write a block, truncated to the cap.
    ///
    /// # Errors
    /// [`Error::Io`], naming the offset the sink refused at.
    fn write(&mut self, block: &[u8]) -> Result<()> {
        // `saturating_sub` and `get`, not `-` and `[..]`. Both are safe here — the loop
        // only calls this while `!is_full()`, so `written < cap`, and `take` is capped
        // by `block.len()` — but the invariants live in the caller, and a library crate
        // does not get to abort on one. Over the cap the answer is
        // "nothing more fits", which is the same thing the subtraction would have said.
        let take = match self.limit {
            Some(cap) => usize::try_from(cap.saturating_sub(self.written))
                .unwrap_or(usize::MAX)
                .min(block.len()),
            None => block.len(),
        };
        if take == 0 {
            return Ok(());
        }
        let Some(chunk) = block.get(..take) else {
            return Ok(());
        };

        let offset = self.written;
        self.touched = true;
        self.out
            .write_all(chunk)
            .map_err(|cause| write_failed(offset, take, &cause))?;
        self.written = self.written.saturating_add(u64::try_from(take).unwrap_or(u64::MAX));
        Ok(())
    }
}

/// A sink that refused a block, with the offset it refused at.
///
/// The C has nowhere to put the offset and nothing to do with it — it returns
/// `TDFU_ERROR_FILE_IO` and restarts the read (`dfu.c:839-842`, `:855`). Keeping the
/// `ErrorKind` means a caller can still tell a full disk from a broken pipe
/// programmatically, and quoting the cause keeps its own wording; what is not kept is
/// the ability to downcast to the original, which nothing does.
fn write_failed(offset: u64, len: usize, cause: &std::io::Error) -> Error {
    Error::Io(std::io::Error::new(
        cause.kind(),
        format!("writing {len} bytes of the DFU upload at offset {offset:#x} to the output: {cause}"),
    ))
}

#[cfg(test)]
mod tests {
    use std::io::{self, Write};

    use tdfu_usb::gadget::{AltConfig, Event, FakeGadget, Fault, GadgetConfig, Loader, When, request};
    use tdfu_usb::mock::{Call, MockTransport, Recorded, Reply, block_on};
    use tdfu_usb::{ControlIn, ControlType, DeviceDescriptors, InterfaceSpec, Recipient, pid, vid};

    use super::{complete_note, read};
    use crate::clock::RecordingClock;
    use crate::dfu::descriptors::fixtures::T32LQ_CONFIG;
    use crate::dfu::host::{self, CONTROL_TIMEOUT, DNLOAD_TIMEOUT, POST_RESET_SETTLE};
    use crate::error::Error;
    use crate::model::AltSel;
    use crate::progress::{Phase, Progress};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// The shipped loader's three alts, with a boot flash of `size` bytes.
    fn gadget(size: u64) -> FakeGadget {
        FakeGadget::new(GadgetConfig::new(vec![
            AltConfig::flash("flash", size),
            AltConfig::erase(),
            AltConfig::reboot(),
        ]))
    }

    /// A recognisable medium: `preload` writes the prefix, and everything past it reads
    /// as `0xFF` the way an erased flash does.
    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|at| u8::try_from(at % 251).unwrap_or(0)).collect()
    }

    /// The sink every test that reads real bytes uses: a `Vec` that refuses to take
    /// anything after the read should have stopped.
    ///
    /// **The bound is not decoration.** A DFU entity's read transaction is *cleaned* by
    /// the short block that ends it (`dfu.c:527-534`), and the next `UPLOAD` re-initiates
    /// it at offset 0 — so a host that fails to stop on a short block does not error, it
    /// reads the same medium round and round for ever. Against a plain `Vec` sink that
    /// makes the whole test binary hang rather than fail, which is a strictly worse
    /// signal, and it is what happened to three descriptor-walk mutants.
    /// Three mutations of [`upload_loop`]'s break condition do exactly this; with the
    /// bound they fail in milliseconds and say why.
    ///
    /// A block shorter than `wTransferSize` is the end whether it came from the device
    /// or from the cap, so one rule covers both.
    struct BoundedSink {
        bytes: Vec<u8>,
        ended: bool,
    }

    impl BoundedSink {
        const fn new() -> Self {
            Self {
                bytes: Vec::new(),
                ended: false,
            }
        }
    }

    impl Write for BoundedSink {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            assert!(
                !self.ended,
                "the read went on past the short block that ended it, and the device has \
                 restarted the transaction at offset 0: these {} bytes are the same medium again",
                buf.len()
            );
            if buf.len() < usize::from(tdfu_usb::gadget::DEFAULT_TRANSFER_SIZE) {
                self.ended = true;
            }
            self.bytes.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Collect everything an operation says.
    fn record(sink: &mut Vec<Progress>) -> impl FnMut(Progress) {
        move |progress| sink.push(progress)
    }

    /// Just the [`Progress::Note`] lines.
    fn notes(said: &[Progress]) -> Vec<&String> {
        said.iter()
            .filter_map(|step| match step {
                Progress::Note(text) => Some(text),
                _ => None,
            })
            .collect()
    }

    /// Everything a user sees without asking: [`Progress::Debug`] filtered out.
    ///
    /// The two sequence assertions below are about what a run *shows*, and core's debug
    /// narration is behind every frontend's switch. Filtering rather than deleting keeps
    /// both pinned: the shown sequence there, the narration in
    /// [`a_read_narrates_the_descriptors_the_claim_and_the_short_block`].
    fn shown(said: &[Progress]) -> Vec<Progress> {
        said.iter()
            .filter(|step| !matches!(step, Progress::Debug(_)))
            .cloned()
            .collect()
    }

    /// Just the [`Progress::Debug`] lines.
    fn debug_lines(said: &[Progress]) -> Vec<&str> {
        said.iter()
            .filter_map(|step| match step {
                Progress::Debug(text) => Some(text.as_str()),
                _ => None,
            })
            .collect()
    }

    /// The `wValue` of every `UPLOAD`, which is the sequence the read loop is about.
    fn uploads(gadget: &FakeGadget) -> Vec<u16> {
        gadget
            .class_requests()
            .into_iter()
            .filter_map(|(req, value)| (req == request::UPLOAD).then_some(value))
            .collect()
    }

    // -----------------------------------------------------------------
    // The loop.
    // -----------------------------------------------------------------

    /// **The loop's pin.** A short block ends the read, and nothing polls between
    /// blocks.
    ///
    /// 10 000 bytes at `wTransferSize` 4096 is 4096 + 4096 + 1808, and the third block
    /// is short, which is the whole termination condition (`dfu.c:847-850`) — there is
    /// no length anywhere on the wire to compare against.
    ///
    /// The full class-request sequence is asserted rather than just the count, because
    /// what is being pinned is an **absence**: an `UPLOAD` needs no `GETSTATUS` (a
    /// differential capture measured 4097 `UPLOAD`s and exactly one `GETSTATUS`
    /// for a 16 MiB read), and a stray poll per block would double
    /// the request count on a 256 MiB read without failing any assertion about bytes.
    /// A claim that fails **after** `claim_interface` — a stalled `SET_INTERFACE`, which
    /// is the WebUSB case — must not leave the interface held.
    ///
    /// `AccessDenied` so that the bus reset cannot paper over it with a second
    /// attempt that would release on its own way out. The three transfer ops that lacked
    /// this branch (`read`, `erase`, `reboot`) each have it and each have this pin now:
    /// one op holding the interface is enough to make the *next* run's claim fail, and
    /// the failure lands on an operator who did nothing wrong.
    #[test]
    fn a_claim_that_fails_half_way_still_releases() {
        let device = gadget(4096);
        device.preload(0, pattern(4096));
        let clock = RecordingClock::new();
        device.inject(When::SetAlt, Fault::AccessDenied);

        let mut out = Vec::new();
        let outcome = block_on(read(&device, &clock, &AltSel::Default, None, &mut out, &mut |_| {}));

        assert!(matches!(outcome, Err(Error::Usb(_))), "{outcome:?}");
        assert_eq!(device.claimed(), None, "the interface was given back");
        assert!(out.is_empty(), "nothing was read");
    }

    #[test]
    fn op_read_short_block_ends() -> TestResult {
        let device = gadget(10_000);
        device.preload(0, pattern(10_000));
        let clock = RecordingClock::new();
        let mut out = BoundedSink::new();
        let mut said = Vec::new();

        let total = block_on(read(
            &device,
            &clock,
            &AltSel::Default,
            None,
            &mut out,
            &mut record(&mut said),
        ))?;

        assert_eq!(total, 10_000);
        assert_eq!(out.bytes, pattern(10_000));

        // One `GETSTATUS` — `make_idle`'s, which sees dfuIDLE and stops — then three
        // `UPLOAD`s and nothing else.
        assert_eq!(
            device.class_requests(),
            vec![
                (request::GETSTATUS, 0),
                (request::UPLOAD, 0),
                (request::UPLOAD, 1),
                (request::UPLOAD, 2),
            ]
        );
        Ok(())
    }

    /// Every `UPLOAD` asks for a whole `wTransferSize`, including the last one.
    ///
    /// The device decides the length, not the host: asking for less would still read as
    /// a short answer by the `got < wTransferSize` test and would end the read early on
    /// hardware, and it would diverge from the request-for-request capture.
    #[test]
    fn op_read_asks_for_a_whole_block_every_time() -> TestResult {
        let device = gadget(5_000);
        device.preload(0, pattern(5_000));
        let clock = RecordingClock::new();
        let mut out = BoundedSink::new();
        let mut said = Vec::new();

        block_on(read(
            &device,
            &clock,
            &AltSel::Default,
            None,
            &mut out,
            &mut record(&mut said),
        ))?;

        let asked: Vec<u16> = device
            .events()
            .into_iter()
            .filter_map(|event| match event {
                Event::ControlIn {
                    control_type: ControlType::Class,
                    request,
                    len,
                    ..
                } if request == request::UPLOAD => Some(len),
                _ => None,
            })
            .collect();
        assert_eq!(asked, vec![4096, 4096], "the last block asked for less than a block");
        Ok(())
    }

    /// An empty medium is a legitimate answer: block 0 comes back with nothing and the
    /// read ends having written nothing.
    ///
    /// The whole progress stream is asserted, and that is what pins the `got > 0` guard
    /// (`dfu.c:838`): a loop that handed every block to the sink regardless would put a
    /// `Bytes { done: 0 }` here for a block that carried nothing. Nothing else in the
    /// suite can see the difference, because an empty write is a no-op everywhere else.
    #[test]
    fn op_read_an_empty_alt_reads_nothing() -> TestResult {
        let device = gadget(0);
        let clock = RecordingClock::new();
        let mut out = BoundedSink::new();
        let mut said = Vec::new();

        let total = block_on(read(
            &device,
            &clock,
            &AltSel::Default,
            None,
            &mut out,
            &mut record(&mut said),
        ))?;

        assert_eq!(total, 0);
        assert!(out.bytes.is_empty());
        assert_eq!(uploads(&device), vec![0], "one request, answered short");
        assert_eq!(
            shown(&said),
            vec![
                Progress::Phase(Phase::Upload),
                Progress::Note("DFU upload complete: 0 bytes".to_owned()),
            ],
            "an empty block was counted as progress"
        );
        Ok(())
    }

    // -----------------------------------------------------------------
    // Streaming.
    // -----------------------------------------------------------------

    /// A sink that refuses to be handed more than one block at a time.
    ///
    /// It also watches the device's own request count, so the assertion is not just
    /// "the writes were small" but "the writes were **interleaved** with the transfer" —
    /// a read that buffered the whole alt and wrote it out in 4096-byte pieces at the
    /// end would pass the first and fail the second.
    struct BlockSink<'a> {
        gadget: &'a FakeGadget,
        block: usize,
        writes: usize,
        total: u64,
        biggest: usize,
        /// Device requests seen before the first write; a buffering read would have made
        /// all of them by then.
        requests_at_first_write: Option<usize>,
    }

    impl<'a> BlockSink<'a> {
        fn new(gadget: &'a FakeGadget, block: usize) -> Self {
            Self {
                gadget,
                block,
                writes: 0,
                total: 0,
                biggest: 0,
                requests_at_first_write: None,
            }
        }
    }

    impl Write for BlockSink<'_> {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            assert!(
                buf.len() <= self.block,
                "the read handed the sink {} bytes, more than one {}-byte block",
                buf.len(),
                self.block
            );
            if self.requests_at_first_write.is_none() {
                self.requests_at_first_write = Some(self.gadget.class_requests().len());
            }
            self.writes += 1;
            self.biggest = self.biggest.max(buf.len());
            self.total += u64::try_from(buf.len()).unwrap_or(0);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// **The core half of streaming.** A whole alt is streamed a block at a time and never
    /// accumulated.
    ///
    /// The bench case is a T40XP NAND alt 0 — 256 MiB, four times the daemon's payload
    /// cap — and it is why `read` takes a `&mut dyn Write` rather than returning a
    /// `Vec`. The daemon's own end of it is `op_read_streams`; this is
    /// the half that lives in core.
    ///
    /// 4 MiB rather than 256 MiB because the property is per-block and does not improve
    /// with size, and a test double is not the place to spend a minute proving it.
    #[test]
    fn op_read_streams_one_block_at_a_time() -> TestResult {
        const SIZE: u64 = 4 * 1024 * 1024;
        let device = gadget(SIZE);
        let clock = RecordingClock::new();
        let mut said = Vec::new();
        let mut sink = BlockSink::new(&device, 4096);

        let total = block_on(read(
            &device,
            &clock,
            &AltSel::Default,
            None,
            &mut sink,
            &mut record(&mut said),
        ))?;

        assert_eq!(total, SIZE);
        assert_eq!(sink.total, SIZE);
        assert_eq!(sink.writes, 1024, "1024 blocks of 4096");
        assert_eq!(sink.biggest, 4096);
        // The first write happened after `make_idle`'s poll and one `UPLOAD`, not after
        // all 1024 of them.
        assert_eq!(sink.requests_at_first_write, Some(2));
        Ok(())
    }

    // -----------------------------------------------------------------
    // The byte cap — the C overshoots, we do not.
    // -----------------------------------------------------------------

    /// **`limit` is exact.** The C writes the whole block and only then tests the cap
    /// (`dfu.c:839` before `:852`), so its size argument overshoots by up to
    /// `transfer_size - 1`; here the last block is truncated before it reaches `out`.
    ///
    /// The wire is unchanged by the fix: the same three `UPLOAD`s, each asking for a
    /// whole 4096-byte block.
    #[test]
    fn op_read_limit_is_exact() -> TestResult {
        const LIMIT: u64 = 4096 * 2 + 1000;
        let device = gadget(1024 * 1024);
        device.preload(0, pattern(1024 * 1024));
        let clock = RecordingClock::new();
        let mut out = BoundedSink::new();
        let mut said = Vec::new();

        let total = block_on(read(
            &device,
            &clock,
            &AltSel::Default,
            Some(LIMIT),
            &mut out,
            &mut record(&mut said),
        ))?;

        let limit = usize::try_from(LIMIT)?;
        assert_eq!(total, LIMIT, "the C would have answered {}", 4096 * 3);
        assert_eq!(out.bytes.len(), limit);
        assert_eq!(out.bytes, pattern(1024 * 1024)[..limit]);
        assert_eq!(uploads(&device), vec![0, 1, 2], "the cap changed the wire");
        Ok(())
    }

    /// A cap that falls exactly on a block boundary stops without asking for one more.
    #[test]
    fn op_read_a_cap_on_a_block_boundary_asks_for_no_more() -> TestResult {
        let device = gadget(1024 * 1024);
        let clock = RecordingClock::new();
        let mut out = BoundedSink::new();
        let mut said = Vec::new();

        let total = block_on(read(
            &device,
            &clock,
            &AltSel::Default,
            Some(8192),
            &mut out,
            &mut record(&mut said),
        ))?;

        assert_eq!(total, 8192);
        assert_eq!(uploads(&device), vec![0, 1]);
        Ok(())
    }

    /// `Some(0)` reads nothing and issues no `UPLOAD`.
    ///
    /// The C cannot say this: its `size` is a `uint32_t` where 0 means "no cap"
    /// (`dfu.c:852`), so "absent" and "a cap of zero" are one value — the same collapse
    /// `Write { verify }` avoids by being an `Option<bool>`. The
    /// CLI refuses `--size 0` at parse time and says why, so this is the library
    /// answering a caller that meant it.
    #[test]
    fn op_read_a_zero_cap_reads_nothing() -> TestResult {
        let device = gadget(1024 * 1024);
        let clock = RecordingClock::new();
        let mut out = BoundedSink::new();
        let mut said = Vec::new();

        let total = block_on(read(
            &device,
            &clock,
            &AltSel::Default,
            Some(0),
            &mut out,
            &mut record(&mut said),
        ))?;

        assert_eq!(total, 0);
        assert!(out.bytes.is_empty());
        assert!(uploads(&device).is_empty(), "a zero cap still read the flash");
        // It got as far as a real DFU session, though: the claim and `make_idle` ran.
        assert_eq!(device.class_requests(), vec![(request::GETSTATUS, 0)]);
        Ok(())
    }

    /// A device with less data than the cap answers short, and that is not an error.
    #[test]
    fn op_read_a_device_shorter_than_the_limit_is_not_an_error() -> TestResult {
        let device = gadget(8192);
        device.preload(0, pattern(8192));
        let clock = RecordingClock::new();
        let mut out = BoundedSink::new();
        let mut said = Vec::new();

        let total = block_on(read(
            &device,
            &clock,
            &AltSel::Default,
            Some(64 * 1024),
            &mut out,
            &mut record(&mut said),
        ))?;

        assert_eq!(total, 8192);
        assert_eq!(out.bytes, pattern(8192));
        assert_eq!(uploads(&device), vec![0, 1, 2], "the third block ends it, empty");
        Ok(())
    }

    // -----------------------------------------------------------------
    // The sink fails — the C re-reads the whole chip, we do not.
    // -----------------------------------------------------------------

    /// A sink that refuses its `fail_on`-th write, the way a full disk does.
    struct FailingSink {
        fail_on: usize,
        writes: usize,
        total: u64,
    }

    impl FailingSink {
        const fn new(fail_on: usize) -> Self {
            Self {
                fail_on,
                writes: 0,
                total: 0,
            }
        }
    }

    impl Write for FailingSink {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.writes += 1;
            if self.writes == self.fail_on {
                return Err(io::Error::new(io::ErrorKind::StorageFull, "no space left on device"));
            }
            self.total += u64::try_from(buf.len()).unwrap_or(0);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// The [`Error::Io`] a run failed with, or the run's own failure to fail.
    fn io_failure(outcome: crate::error::Result<u64>) -> Result<io::Error, Box<dyn std::error::Error>> {
        match outcome {
            Ok(total) => Err(format!("the sink refused a block and the read answered {total}").into()),
            Err(Error::Io(cause)) => Ok(cause),
            Err(other) => Err(format!("expected Error::Io, got {other}").into()),
        }
    }

    /// **A full disk does not restart the chip read.**
    ///
    /// The C sets `TDFU_ERROR_FILE_IO` and breaks with `block` still 0 (`dfu.c:839-842`),
    /// so `dfu.c:855`'s `r == TDFU_SUCCESS || block != 0` reads the failure as a stale
    /// block-0 transaction, `rewind`s the file and re-reads the **entire** flash into a
    /// sink that has already said it has no room. On a T40XP that is 256 MiB of wasted
    /// bus time before the same failure.
    ///
    /// Three things are asserted: the read stopped where it was, the error says where
    /// and why, and the device was neither re-read nor bus-reset.
    #[test]
    fn op_read_a_sink_failure_does_not_restart_the_read() -> TestResult {
        let device = gadget(1024 * 1024);
        let clock = RecordingClock::new();
        let mut said = Vec::new();
        let mut sink = FailingSink::new(2);

        let cause = io_failure(block_on(read(
            &device,
            &clock,
            &AltSel::Default,
            None,
            &mut sink,
            &mut record(&mut said),
        )))?;

        // Where, and why. The C has nowhere to put either.
        assert_eq!(cause.kind(), io::ErrorKind::StorageFull, "the kind was thrown away");
        let message = cause.to_string();
        assert!(message.contains("offset 0x1000"), "{message}");
        assert!(message.contains("no space left on device"), "{message}");

        // Two blocks asked for, two blocks read: no re-read, no recovery reset.
        assert_eq!(uploads(&device), vec![0, 1]);
        assert_eq!(device.resets(), 0, "a full disk was answered with a bus reset");
        assert_eq!(sink.total, 4096);
        assert!(notes(&said).is_empty(), "a retry was announced that must not happen");
        // And the interface did not stay claimed.
        assert!(device.events().contains(&Event::ReleaseInterface(0)));
        Ok(())
    }

    /// The same on **block 0**, which is the case the stale-transaction retry would otherwise
    /// take.
    ///
    /// This is why [`Transaction::first_block_done`](crate::dfu::Transaction::first_block_done)
    /// is called *before* `write_all` and not after it: `write_all` can fail having
    /// already moved bytes, so "the write failed" is not "nothing was emitted". Marking
    /// afterwards would leave block 0's failure looking like a stale transaction and
    /// re-read the chip into a sink that is already broken — the C's bug reproduced by a
    /// different route.
    #[test]
    fn op_read_a_sink_failure_on_block_zero_is_not_a_stale_transaction() -> TestResult {
        let device = gadget(1024 * 1024);
        let clock = RecordingClock::new();
        let mut said = Vec::new();
        let mut sink = FailingSink::new(1);

        let cause = io_failure(block_on(read(
            &device,
            &clock,
            &AltSel::Default,
            None,
            &mut sink,
            &mut record(&mut said),
        )))?;

        assert!(cause.to_string().contains("offset 0x0"), "{cause}");
        assert_eq!(
            device.class_requests(),
            vec![(request::GETSTATUS, 0), (request::UPLOAD, 0)],
            "block 0 was retried after the sink had already been handed bytes"
        );
        assert_eq!(device.resets(), 0);
        Ok(())
    }

    // -----------------------------------------------------------------
    // Once bytes are out, a failure is final.
    // -----------------------------------------------------------------

    /// **A stall mid-read is final**, however recoverable its kind.
    ///
    /// A [`Stall`](tdfu_usb::UsbErrorKind::Stall) is in the recoverable set, so
    /// an ungated `reset_and_retry_once` would bus-reset the gadget and run the whole
    /// read again — into a sink holding 12 KiB it cannot take back. The C can do that
    /// because it owns the file and `rewind`s it (`dfu.c:826`); a `Write` cannot be
    /// rewound, so the retry stops at the first byte handed over.
    #[test]
    fn op_read_a_mid_read_stall_is_final() -> TestResult {
        let device = gadget(1024 * 1024);
        device.preload(0, pattern(1024 * 1024));
        device.inject(When::ClassBlock(request::UPLOAD, 3), Fault::Stall);
        let clock = RecordingClock::new();
        let mut out = BoundedSink::new();
        let mut said = Vec::new();

        let error = block_on(read(
            &device,
            &clock,
            &AltSel::Default,
            None,
            &mut out,
            &mut record(&mut said),
        ))
        .err()
        .ok_or("a stalled upload read cleanly")?;

        assert!(error.to_string().contains("stall"), "{error}");
        assert_eq!(out.bytes.len(), 4096 * 3, "the blocks that arrived were kept");
        assert_eq!(out.bytes, pattern(1024 * 1024)[..4096 * 3]);
        assert_eq!(uploads(&device), vec![0, 1, 2, 3], "the read was re-run from the start");
        assert_eq!(device.resets(), 0, "a bus reset that could not help anything");
        assert!(clock.slept().is_empty(), "the post-reset settle was waited out");
        assert!(notes(&said).is_empty());
        assert!(device.events().contains(&Event::ReleaseInterface(0)));
        Ok(())
    }

    /// A sink that arms a fault on the device once it has taken `arm_at` bytes.
    ///
    /// The only way to make a failure land on a *wrapped* block 0: the block number is
    /// on the wire, so the fault has to be armed 65 536 blocks into the run.
    struct ArmingSink<'a> {
        gadget: &'a FakeGadget,
        arm_at: u64,
        total: u64,
        armed: bool,
    }

    impl Write for ArmingSink<'_> {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.total += u64::try_from(buf.len()).unwrap_or(0);
            if !self.armed && self.total >= self.arm_at {
                self.gadget.inject(When::ClassBlock(request::UPLOAD, 0), Fault::Stall);
                self.armed = true;
            }
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// **The 65 536-block wrap, end to end.**
    ///
    /// `block` is a `uint16_t` in the C (`dfu.c:819`) and its stale-transaction test is
    /// `r == TDFU_SUCCESS || block != 0` (`dfu.c:855`). At 65 536 blocks the counter is
    /// back at 0 — 256 MiB at `wTransferSize` 4096, which is exactly a T40XP whole-chip
    /// read — so a transfer error there reads as "stale block 0" and the C re-reads the
    /// entire chip. The same test is in its write and verify loops (`:602`, `:955`).
    ///
    /// Nothing here can make that mistake, because nothing here looks at the block
    /// number: the retry gate is an explicit flag set when the first block reached the
    /// sink. This drives the real wrap anyway, at `wTransferSize` 64 so that it costs
    /// 4 MiB instead of 256 MiB, and fails the transfer at the wrapped block 0.
    #[test]
    fn op_read_a_wrapped_block_zero_is_not_a_stale_transaction() -> TestResult {
        const BLOCK: u64 = 64;
        /// Where `block` returns to 0.
        const WRAP: u64 = 65_536 * BLOCK;

        let device = FakeGadget::new(
            GadgetConfig::new(vec![
                AltConfig::flash("flash", WRAP + BLOCK),
                AltConfig::erase(),
                AltConfig::reboot(),
            ])
            .with_transfer_size(64),
        );
        let clock = RecordingClock::new();
        let mut said = Vec::new();
        let mut sink = ArmingSink {
            gadget: &device,
            arm_at: WRAP,
            total: 0,
            armed: false,
        };

        let error = block_on(read(
            &device,
            &clock,
            &AltSel::Default,
            None,
            &mut sink,
            &mut record(&mut said),
        ))
        .err()
        .ok_or("the wrapped block 0 was not the one that failed")?;
        assert!(error.to_string().contains("stall"), "{error}");

        // Exactly one pass over the medium, stopping where the fault was armed.
        assert_eq!(sink.total, WRAP);
        let block_zeros = uploads(&device).into_iter().filter(|value| *value == 0).count();
        assert_eq!(block_zeros, 2, "block 0 was asked for a third time: the read restarted");
        assert_eq!(device.resets(), 0);
        // The device never refused a block, so the failure really was the injected one.
        assert_eq!(device.wrong_sequence_refusals(), 0);
        Ok(())
    }

    // -----------------------------------------------------------------
    // The stale transaction, which is bounded the same way.
    // -----------------------------------------------------------------

    /// Leave the gadget's read entity mid-transaction, as a killed run does.
    ///
    /// One bare `UPLOAD` initiates the entity and advances its sequence counter to 1.
    /// Nothing after it cleans up, which is the state a browser reload or a `^C` leaves
    /// behind.
    fn wedge_the_entity(device: &FakeGadget) -> crate::error::Result<()> {
        block_on(host::upload(device, 0, 0, 64))?;
        device.forget_events();
        Ok(())
    }

    /// **The block 0 retry on a legacy loader.** A stale entity refuses block 0, `make_idle`
    /// clears it, and the retry reads the whole alt.
    ///
    /// A loader without u-boot `3d4848fe0dc` keeps the entity's block
    /// sequence across `ABORT`, `CLRSTATUS` and the alt switch a claim performs, so the
    /// host's first `UPLOAD` asks for block 0 while the entity expects block 1 and the
    /// device answers `Wrong sequence number!` with a STALL (`dfu.c:508-517`). The
    /// refusal itself cleans the entity, so the retry succeeds — and the medium offset
    /// restarts at 0, which an earlier emulator got wrong.
    ///
    /// The retry is **announced**: a retry the user cannot see is a retry they cannot
    /// report.
    #[test]
    fn op_read_retries_a_stale_block_zero() -> TestResult {
        let device = FakeGadget::new(
            GadgetConfig::new(vec![
                AltConfig::flash("flash", 5_000),
                AltConfig::erase(),
                AltConfig::reboot(),
            ])
            .with_loader(Loader::Legacy),
        );
        device.preload(0, pattern(5_000));
        wedge_the_entity(&device)?;

        let clock = RecordingClock::new();
        let mut out = BoundedSink::new();
        let mut said = Vec::new();
        let total = block_on(read(
            &device,
            &clock,
            &AltSel::Default,
            None,
            &mut out,
            &mut record(&mut said),
        ))?;

        assert_eq!(total, 5_000);
        assert_eq!(out.bytes, pattern(5_000), "the retry read from the wrong offset");
        assert_eq!(device.wrong_sequence_refusals(), 1, "the stale entity never refused");
        assert_eq!(device.resets(), 0, "the block retry was escalated to a reset");

        let said_notes = notes(&said);
        assert_eq!(said_notes.len(), 2, "{said_notes:?}");
        assert!(said_notes[0].contains("stale DFU transaction"), "{said_notes:?}");
        assert_eq!(said_notes[1], &complete_note(5_000));
        Ok(())
    }

    /// A **fixed** loader cleans the same entity itself, so nothing is retried.
    ///
    /// The contrast is the point: the alt switch inside the claim reaches
    /// `f_dfu_abort_transaction` on this generation, so the same stale
    /// entity is gone before the first `UPLOAD` and the run is indistinguishable from a
    /// clean one. Without this, a `retry_stale_block0` that fired on every read would
    /// still pass the test above.
    #[test]
    fn op_read_a_fixed_loader_clears_the_stale_entity_itself() -> TestResult {
        let device = gadget(5_000);
        device.preload(0, pattern(5_000));
        wedge_the_entity(&device)?;

        let clock = RecordingClock::new();
        let mut out = BoundedSink::new();
        let mut said = Vec::new();
        let total = block_on(read(
            &device,
            &clock,
            &AltSel::Default,
            None,
            &mut out,
            &mut record(&mut said),
        ))?;

        assert_eq!(total, 5_000);
        assert_eq!(device.wrong_sequence_refusals(), 0);
        assert_eq!(notes(&said), vec![&complete_note(5_000)]);
        Ok(())
    }

    // -----------------------------------------------------------------
    // The recovery reset, while nothing has been emitted.
    // -----------------------------------------------------------------

    /// **An EP0-quiet window before the first byte is recovered.**
    ///
    /// A gadget left wedged by an interrupted transfer answers no control transfer at
    /// all until a bus reset re-inits its endpoints (`dfu.c:368-373`). Here it swallows
    /// the very first descriptor read; nothing has reached the sink, so a bus
    /// reset and one more attempt are exactly the right answer, and the retry produces
    /// the alt once.
    #[test]
    fn op_read_resets_a_gadget_that_went_quiet_before_the_first_block() -> TestResult {
        let device = gadget(5_000);
        device.preload(0, pattern(5_000));
        device.silence_ep0(1);

        let clock = RecordingClock::new();
        let mut out = BoundedSink::new();
        let mut said = Vec::new();
        let total = block_on(read(
            &device,
            &clock,
            &AltSel::Default,
            None,
            &mut out,
            &mut record(&mut said),
        ))?;

        assert_eq!(total, 5_000);
        assert_eq!(
            out.bytes,
            pattern(5_000),
            "the retry duplicated what the first attempt read"
        );
        assert_eq!(device.resets(), 1);
        assert_eq!(clock.slept(), vec![POST_RESET_SETTLE]);

        let said_notes = notes(&said);
        assert_eq!(said_notes.len(), 2, "{said_notes:?}");
        assert!(said_notes[0].contains("USB-reset"), "{said_notes:?}");
        assert_eq!(said_notes[1], &complete_note(5_000));
        Ok(())
    }

    /// The same recovery when the quiet window lands on `make_idle` instead.
    ///
    /// `make_idle` bails on the first unreadable `GETSTATUS` rather than spending 5 s
    /// timeouts on aborts that also hang (`dfu.c:118-122`), which puts the failure in
    /// the bus reset's hands — still before any byte has been emitted.
    #[test]
    fn op_read_resets_a_gadget_that_will_not_go_idle() -> TestResult {
        let device = gadget(5_000);
        device.preload(0, pattern(5_000));
        device.inject(When::Class(request::GETSTATUS), Fault::Timeout);

        let clock = RecordingClock::new();
        let mut out = BoundedSink::new();
        let mut said = Vec::new();
        let total = block_on(read(
            &device,
            &clock,
            &AltSel::Default,
            None,
            &mut out,
            &mut record(&mut said),
        ))?;

        assert_eq!(total, 5_000);
        assert_eq!(out.bytes, pattern(5_000));
        assert_eq!(device.resets(), 1);
        assert!(notes(&said)[0].contains("USB-reset"));
        Ok(())
    }

    // -----------------------------------------------------------------
    // Which alt, and what it costs to get it wrong.
    // -----------------------------------------------------------------

    /// The default is the alt **named** `flash`, not alt 0 and not the first alt.
    #[test]
    fn op_read_default_alt_prefers_the_one_named_flash() -> TestResult {
        let device = FakeGadget::new(GadgetConfig::new(vec![
            AltConfig::reboot(),
            AltConfig::erase(),
            AltConfig::flash("flash", 1_000),
        ]));
        device.preload(2, pattern(1_000));
        let clock = RecordingClock::new();
        let mut out = BoundedSink::new();
        let mut said = Vec::new();

        let total = block_on(read(
            &device,
            &clock,
            &AltSel::Default,
            None,
            &mut out,
            &mut record(&mut said),
        ))?;

        assert_eq!(total, 1_000);
        assert_eq!(out.bytes, pattern(1_000));
        assert!(
            device.events().contains(&Event::SetAltSetting { interface: 0, alt: 2 }),
            "the read did not select the flash alt"
        );
        Ok(())
    }

    /// A name and a number each select their alt.
    #[test]
    fn op_read_selects_an_alt_by_name_and_by_number() -> TestResult {
        for selection in [
            AltSel::Name("flash".to_owned()),
            AltSel::Index(0),
            AltSel::Name("0".to_owned()),
        ] {
            let device = gadget(1_000);
            device.preload(0, pattern(1_000));
            let clock = RecordingClock::new();
            let mut out = BoundedSink::new();
            let mut said = Vec::new();

            let total = block_on(read(
                &device,
                &clock,
                &selection,
                None,
                &mut out,
                &mut record(&mut said),
            ))?;
            assert_eq!(total, 1_000, "{selection:?}");
            assert_eq!(out.bytes, pattern(1_000), "{selection:?}");
        }
        Ok(())
    }

    /// An alt the device does not have is refused **before the claim**, and the refusal
    /// names what the device does offer.
    #[test]
    fn op_read_refuses_an_alt_the_device_does_not_have() -> TestResult {
        let device = gadget(1_000);
        let clock = RecordingClock::new();
        let mut out = BoundedSink::new();
        let mut said = Vec::new();

        let error = block_on(read(
            &device,
            &clock,
            &AltSel::Name("rootfs".to_owned()),
            None,
            &mut out,
            &mut record(&mut said),
        ))
        .err()
        .ok_or("an alt that is not there read fine")?;

        let message = error.to_string();
        assert!(message.contains("rootfs"), "{message}");
        assert!(message.contains("0 (flash)"), "{message}");
        assert!(message.contains("2 (reboot)"), "{message}");
        assert!(!error.is_recoverable(), "a typo was answered with a bus reset");
        assert_eq!(device.resets(), 0);
        assert!(
            !device
                .events()
                .iter()
                .any(|event| matches!(event, Event::ClaimInterface(_))),
            "the interface was claimed for an alt that does not exist"
        );
        Ok(())
    }

    /// A number selects by `bAlternateSetting`, and a number the device does not have is
    /// refused rather than rounded to the boot flash.
    ///
    /// The refusal is the half that needs pinning: an unknown number quietly resolving to
    /// alt 0 would read the boot flash and report success for a question nobody asked —
    /// and on the write side the same slip is what the C's `(uint8_t)` index wrap does
    /// with `-i 256`.
    #[test]
    fn op_read_a_number_selects_its_own_alt_or_nothing() -> TestResult {
        let alts = || {
            GadgetConfig::new(vec![
                AltConfig::flash("first", 1_000),
                AltConfig::flash("second", 2_000),
            ])
        };
        let device = FakeGadget::new(alts());
        device.preload(1, pattern(2_000));

        let clock = RecordingClock::new();
        let mut out = BoundedSink::new();
        let mut said = Vec::new();
        let total = block_on(read(
            &device,
            &clock,
            &AltSel::Index(1),
            None,
            &mut out,
            &mut record(&mut said),
        ))?;
        assert_eq!(total, 2_000, "alt 1 was not the alt that was read");
        assert_eq!(out.bytes, pattern(2_000));

        let missing = FakeGadget::new(alts());
        let mut nothing = BoundedSink::new();
        let error = block_on(read(
            &missing,
            &clock,
            &AltSel::Index(9),
            None,
            &mut nothing,
            &mut record(&mut said),
        ))
        .err()
        .ok_or("alt 9 read something on a device offering 0 and 1")?;
        // The wording is the shared resolver's (dfu::alt), which says "alt 9".
        assert!(error.to_string().contains("alt 9"), "{error}");
        assert!(nothing.bytes.is_empty());
        assert!(uploads(&missing).is_empty(), "an alt that is not there was read anyway");
        Ok(())
    }

    /// No `flash` alt and more than one to choose from: refuse, and say which alt name
    /// was looked for.
    #[test]
    fn op_read_refuses_when_there_is_no_default_alt() -> TestResult {
        let device = FakeGadget::new(GadgetConfig::new(vec![
            AltConfig::flash("nor", 1_000),
            AltConfig::flash("nand", 1_000),
        ]));
        let clock = RecordingClock::new();
        let mut out = BoundedSink::new();
        let mut said = Vec::new();

        let error = block_on(read(
            &device,
            &clock,
            &AltSel::Default,
            None,
            &mut out,
            &mut record(&mut said),
        ))
        .err()
        .ok_or("an ambiguous default picked an alt anyway")?;

        assert!(matches!(error, Error::MissingAlt("flash")), "{error:?}");
        assert_eq!(device.resets(), 0);
        Ok(())
    }

    /// **The narration pin.** A read tells the debug channel what the device answered
    /// with, which alt it took and why, that the upload started, and how it ended.
    ///
    /// Those are the C's `dfu.c:794`, `:799`, `:808`, `:848` and `core.c:159`, `:162`,
    /// `:177`. The Rust core had none of them, so `-d` on a 32 MiB read added one line to
    /// the log (observed 2026-09-03). Revert check: delete any of the four `Progress::Debug`
    /// calls in `one_attempt` or `upload_loop` and one of these assertions fails.
    #[test]
    fn a_read_narrates_the_descriptors_the_claim_and_the_short_block() -> TestResult {
        let device = gadget(10_000);
        device.preload(0, pattern(10_000));
        let clock = RecordingClock::new();
        let mut out = BoundedSink::new();
        let mut said = Vec::new();

        let total = block_on(read(
            &device,
            &clock,
            &AltSel::Default,
            None,
            &mut out,
            &mut record(&mut said),
        ))?;
        assert_eq!(total, 10_000);

        let lines = debug_lines(&said);
        let joined = lines.join("\n");
        // The descriptors, before anything is claimed: the block size every request will
        // use, the DFU revision, the alt count and the interface.
        let descriptors = lines
            .iter()
            .find(|line| line.starts_with("DFU descriptors"))
            .ok_or("the descriptors were never narrated")?;
        assert!(descriptors.contains("transfer size 4096"), "{descriptors}");
        assert!(descriptors.contains("bcdDFU 0x0110"), "{descriptors}");
        assert!(descriptors.contains("3 alt(s)"), "{descriptors}");
        assert!(descriptors.contains("interface 0"), "{descriptors}");

        // One line per alt, by index and name, so an operator can see what they could
        // have asked for.
        for (index, name) in [(0, "flash"), (1, "erase"), (2, "reboot")] {
            assert!(joined.contains(&format!("alt {index}: {name}")), "{joined}");
        }

        // Which alt, and why that one: this run named nothing, so it is the default.
        let claiming = lines
            .iter()
            .find(|line| line.starts_with("claiming alt"))
            .ok_or("the claim was never narrated")?;
        assert!(claiming.contains("claiming alt 0 on interface 0"), "{claiming}");
        assert!(claiming.contains("default"), "{claiming}");
        assert!(joined.contains("starting the upload"), "{joined}");

        // The short block, with the total it settled: a whole-chip read has no knowable
        // total until this moment, so this line is where the length comes
        // from.
        let short = lines
            .iter()
            .find(|line| line.contains("so the upload ends"))
            .ok_or("the short block was never narrated")?;
        assert!(short.contains("block 2"), "{short}");
        assert!(short.contains("1808 of 4096 bytes"), "{short}");
        assert!(short.contains("ends at 10000 bytes"), "{short}");

        // In that order, and never as a `Note`: a narration line a user did not ask for
        // must not reach a frontend that has debug off.
        let order = |needle: &str| joined.find(needle);
        assert!(order("DFU descriptors") < order("alt 0: flash"), "{joined}");
        assert!(order("alt 2: reboot") < order("claiming alt 0"), "{joined}");
        assert!(order("claiming alt 0") < order("starting the upload"), "{joined}");
        assert!(order("starting the upload") < order("so the upload ends"), "{joined}");
        assert_eq!(
            notes(&said),
            vec![&complete_note(10_000)],
            "the narration must not have leaked into the user's lines"
        );
        Ok(())
    }

    /// An alt named on the command line says so, so a read off the wrong part of a chip
    /// can be told from a default this tool chose.
    #[test]
    fn a_named_alt_narrates_that_it_was_asked_for() -> TestResult {
        let device = gadget(64);
        device.preload(0, pattern(64));
        let clock = RecordingClock::new();
        let mut out = BoundedSink::new();
        let mut said = Vec::new();

        block_on(read(
            &device,
            &clock,
            &AltSel::Name("flash".to_owned()),
            None,
            &mut out,
            &mut record(&mut said),
        ))?;

        let joined = debug_lines(&said).join("\n");
        assert!(joined.contains("asked for by name, flash"), "{joined}");
        assert!(!joined.contains("the default"), "{joined}");
        Ok(())
    }

    /// A block that fails names itself and how far the read had got (`dfu.c:834`), which
    /// is what separates a bad cable from a bad chip.
    #[test]
    fn a_failed_upload_block_narrates_where_it_died() -> TestResult {
        let device = gadget(10_000);
        device.preload(0, pattern(10_000));
        // Past the first block, so neither the block 0 retry nor the bus reset
        // re-runs the transfer: the failure is the answer, and the line is about it.
        device.inject(When::ClassBlock(request::UPLOAD, 1), Fault::Stall);
        let clock = RecordingClock::new();
        let mut out = BoundedSink::new();
        let mut said = Vec::new();

        let outcome = block_on(read(
            &device,
            &clock,
            &AltSel::Default,
            None,
            &mut out,
            &mut record(&mut said),
        ));
        assert!(outcome.is_err(), "{outcome:?}");

        let failed = debug_lines(&said)
            .into_iter()
            .find(|line| line.contains("failed after"))
            .ok_or("the failed block was never narrated")?;
        assert!(failed.contains("upload: block 1"), "{failed}");
        assert!(failed.contains("4096 bytes"), "{failed}");
        Ok(())
    }

    /// A single-alt loader needs no name: the only alt is the default (the pre-`a73e4da`
    /// shape, and the one where the claim also skips `SET_INTERFACE`).
    #[test]
    fn op_read_a_single_alt_loader_needs_no_name() -> TestResult {
        let device = FakeGadget::new(GadgetConfig::new(vec![AltConfig::flash("nor", 1_000)]));
        device.preload(0, pattern(1_000));
        let clock = RecordingClock::new();
        let mut out = BoundedSink::new();
        let mut said = Vec::new();

        let total = block_on(read(
            &device,
            &clock,
            &AltSel::Default,
            None,
            &mut out,
            &mut record(&mut said),
        ))?;

        assert_eq!(total, 1_000);
        assert!(
            !device
                .events()
                .iter()
                .any(|event| matches!(event, Event::SetAltSetting { .. })),
            "alt 0 of a single-alt interface is not selected explicitly"
        );
        Ok(())
    }

    // -----------------------------------------------------------------
    // What the caller is told.
    // -----------------------------------------------------------------

    /// The whole progress stream of a three-block read, asserted exactly.
    ///
    /// `total` is `None` because a DFU upload ends on a short block and there is no
    /// length anywhere to know in advance; the phase marker leads so a frontend can
    /// reset its bar; and there is **exactly one** completion note. That count is the
    /// point: core owns the line, and a frontend that prints its own would make it
    /// two.
    #[test]
    fn op_read_progress_reports_bytes_and_one_completion_line() -> TestResult {
        let device = gadget(10_000);
        let clock = RecordingClock::new();
        let mut out = BoundedSink::new();
        let mut said = Vec::new();

        block_on(read(
            &device,
            &clock,
            &AltSel::Default,
            None,
            &mut out,
            &mut record(&mut said),
        ))?;

        let bytes = |done| Progress::Bytes {
            phase: Phase::Upload,
            done,
            total: None,
        };
        assert_eq!(
            shown(&said),
            vec![
                Progress::Phase(Phase::Upload),
                bytes(4096),
                bytes(8192),
                bytes(10_000),
                Progress::Note("DFU upload complete: 10000 bytes".to_owned()),
            ]
        );
        Ok(())
    }

    /// With a cap, the cap **is** the total a frontend can draw a bar against.
    #[test]
    fn op_read_progress_totals_come_from_the_cap() -> TestResult {
        let device = gadget(1024 * 1024);
        let clock = RecordingClock::new();
        let mut out = BoundedSink::new();
        let mut said = Vec::new();

        block_on(read(
            &device,
            &clock,
            &AltSel::Default,
            Some(5_000),
            &mut out,
            &mut record(&mut said),
        ))?;

        let totals: Vec<Option<u64>> = said
            .iter()
            .filter_map(|step| match step {
                Progress::Bytes { total, .. } => Some(*total),
                _ => None,
            })
            .collect();
        assert_eq!(totals, vec![Some(5_000), Some(5_000)]);
        assert_eq!(notes(&said), vec![&complete_note(5_000)]);
        Ok(())
    }

    // -----------------------------------------------------------------
    // The deadline on the wire, which only a scripted transport can see.
    // -----------------------------------------------------------------

    /// `GET_DESCRIPTOR`, the only standard request a read makes.
    const GET_DESCRIPTOR: u8 = 0x06;
    /// `bDescriptorType` CONFIGURATION, in the high byte of `wValue`.
    const CONFIGURATION_VALUE: u16 = 0x0200;
    /// `bDescriptorType` STRING, likewise.
    const STRING_VALUE: u16 = 0x0300;
    /// US English, as the C asks for (`dfu.c:210`).
    const LANGID_EN_US: u16 = 0x0409;

    fn get_descriptor(value: u16, langid: u16, len: u16) -> Call {
        Call::control_in(ControlIn {
            control_type: ControlType::Standard,
            recipient: Recipient::Device,
            request: GET_DESCRIPTOR,
            value,
            index: langid,
            len,
        })
    }

    fn class_in(request: u8, value: u16, len: u16) -> Call {
        Call::control_in(ControlIn {
            control_type: ControlType::Class,
            recipient: Recipient::Interface,
            request,
            value,
            index: 0,
            len,
        })
    }

    /// One UTF-16LE string descriptor, as a device answers it.
    fn string_descriptor(text: &str) -> Vec<u8> {
        let mut bytes = vec![0_u8, 0x03];
        for unit in text.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        let len = u8::try_from(bytes.len()).unwrap_or(u8::MAX);
        bytes[0] = len;
        bytes
    }

    /// **Every `UPLOAD` carries the 5 s control deadline, not the download's
    /// 30 s.**
    ///
    /// The C's `dfu_upload_block` calls the plain `usb_device_control_transfer`
    /// (`dfu.c:104-107`), which substitutes 5000 ms (`usb/device.c:394-398`); only
    /// `DNLOAD` gets the 30 s wrapper (`dfu.c:97-102`). The difference is load-bearing
    /// in the wrong direction as well as the right one: a read that used the download
    /// deadline would sit for half a minute on a gadget that has already gone.
    ///
    /// `FakeGadget` records no deadlines, so this is the one pin that needs the scripted
    /// transport — the same reason `Recorded.timeout` exists at all.
    #[test]
    fn op_read_uploads_carry_the_control_timeout() -> TestResult {
        let descriptors = DeviceDescriptors::new(vid::INGENIC, pid::BOOTROM)
            .with_product_string("USB download gadget")
            .with_config_descriptor(T32LQ_CONFIG);
        let total = u16::try_from(T32LQ_CONFIG.len())?;
        let mut mock = MockTransport::new(descriptors)
            .configured(1)
            .expecting(
                get_descriptor(CONFIGURATION_VALUE, 0, 9),
                Reply::Data(T32LQ_CONFIG[..9].to_vec()),
            )
            .expecting(
                get_descriptor(CONFIGURATION_VALUE, 0, total),
                Reply::Data(T32LQ_CONFIG.to_vec()),
            );
        for (index, name) in [(5_u8, "flash"), (6, "erase"), (7, "reboot")] {
            mock = mock.expecting(
                get_descriptor(STRING_VALUE | u16::from(index), LANGID_EN_US, 256),
                Reply::Data(string_descriptor(name)),
            );
        }
        let mock = mock
            .expecting(Call::ClaimInterface(InterfaceSpec::control_only(0)), Reply::Done)
            .expecting(Call::SetAltSetting { interface: 0, alt: 0 }, Reply::Done)
            // `make_idle`'s poll: bStatus OK, no poll timeout, state dfuIDLE.
            .expecting(class_in(host::request::GETSTATUS, 0, 6), Reply::Data(vec![0, 0, 0, 0, 2, 0]))
            // One short block, which ends the upload.
            .expecting(class_in(host::request::UPLOAD, 0, 4096), Reply::Data(vec![0xAB; 100]))
            .expecting(Call::ReleaseInterface(0), Reply::Done);

        let clock = RecordingClock::new();
        let mut out = BoundedSink::new();
        let mut said = Vec::new();
        let read_total = block_on(read(
            &mock,
            &clock,
            &AltSel::Default,
            None,
            &mut out,
            &mut record(&mut said),
        ))?;
        assert_eq!(read_total, 100);

        let upload_deadlines: Vec<Option<core::time::Duration>> = mock
            .calls()
            .iter()
            .filter(|Recorded { call, .. }| {
                matches!(call, Call::ControlIn { control_type: ControlType::Class, request, .. }
                    if *request == host::request::UPLOAD)
            })
            .map(|recorded| recorded.timeout)
            .collect();
        assert_eq!(upload_deadlines, vec![Some(CONTROL_TIMEOUT)]);
        assert_ne!(CONTROL_TIMEOUT, DNLOAD_TIMEOUT, "the two deadlines became one");
        mock.verify()?;
        Ok(())
    }

    /// A cap that ends the read on a full block closes the transaction it left open,
    /// and a read the device ended itself sends nothing extra.
    ///
    /// The two halves are one rule: a short block is `dfu_read`'s own end of
    /// transaction, a full one is not, and only the second needs an `ABORT`. Without the
    /// close-out the loader's entity is left inited with its sequence counter part way
    /// along, which on a loader without `3d4848fe0dc` costs the next operation a
    /// stale-block-0 retry and a `Wrong sequence number!` line on its console.
    #[test]
    fn op_read_a_cap_closes_the_transaction_it_leaves_open() -> TestResult {
        let device = gadget(1024 * 1024);
        let clock = RecordingClock::new();
        let mut out = BoundedSink::new();
        let mut said = Vec::new();

        let total = block_on(read(
            &device,
            &clock,
            &AltSel::Default,
            Some(8192),
            &mut out,
            &mut record(&mut said),
        ))?;

        assert_eq!(total, 8192);
        assert_eq!(uploads(&device), vec![0, 1], "the cap ended it, not the device");
        assert_eq!(device.entity_inited(0), Some(false), "the transaction was closed");
        assert_eq!(device.entity_sequence(0), Some(0), "and its counter is back at 0");

        // The other half: a read the short block ended needs no close-out at all.
        let device = gadget(1_000);
        device.preload(0, pattern(1_000));
        let mut out = BoundedSink::new();
        let mut said = Vec::new();
        block_on(read(
            &device,
            &clock,
            &AltSel::Default,
            None,
            &mut out,
            &mut record(&mut said),
        ))?;
        assert!(
            !device
                .class_requests()
                .iter()
                .any(|(request, _)| *request == request::ABORT),
            "a short block is the device's own ending"
        );
        Ok(())
    }

    /// The claiming line names the rule [`resolve`](crate::dfu::alt::resolve) applied,
    /// not the position of the alt it picked.
    ///
    /// This loader lists `flash` third, so "the first alt" would be a false sentence
    /// about the one thing this line exists to say: whether the tool or the operator
    /// chose the alt a read came back from.
    #[test]
    fn op_read_the_claiming_line_says_which_rule_chose_the_alt() -> TestResult {
        let device = FakeGadget::new(GadgetConfig::new(vec![
            AltConfig::reboot(),
            AltConfig::erase(),
            AltConfig::flash("flash", 1_000),
        ]));
        device.preload(2, pattern(1_000));
        let clock = RecordingClock::new();
        let mut out = BoundedSink::new();
        let mut said = Vec::new();

        block_on(read(
            &device,
            &clock,
            &AltSel::Default,
            None,
            &mut out,
            &mut record(&mut said),
        ))?;

        let claiming: Vec<&String> = said
            .iter()
            .filter_map(|step| match step {
                Progress::Debug(line) if line.starts_with("claiming alt") => Some(line),
                _ => None,
            })
            .collect();
        assert_eq!(
            claiming,
            ["claiming alt 2 on interface 0 (the default: the alt named flash)"]
        );
        Ok(())
    }
}
