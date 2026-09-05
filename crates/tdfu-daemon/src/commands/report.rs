//! Turning a core [`Progress`] into wire frames.
//!
//! # The frames are sent, and that is the whole point of this file
//!
//! No C daemon has ever sent a `RESP_PROGRESS` frame, **although both C clients parse
//! one** (`cli/remote.c:186`, `:237`, `:300`; `web/src/remote.js:25`, `:148`). An earlier
//! implementation inherited the omission, so remote flashing showed progress only as log
//! prose: an omission, the kind of defect with nothing to grep for.
//! **This daemon sends one per byte count**, and this is where.
//!
//! # The problem this file exists to solve
//!
//! [`ProgressSink`] is `&mut dyn FnMut(Progress)`, **synchronous** by design: a closure
//! is enough and no frontend has to declare a type. Sending a frame
//! is `async`. A sink therefore cannot send, and a daemon that buffers everything until
//! the operation ends has not sent progress at all: a 16 MiB write takes about a minute
//! and a half on real hardware.
//!
//! [`pump`] resolves it without a channel, a task or an executor dependency. The sink
//! pushes into a [`Queue`]; `pump` polls the operation's future and flushes the queue
//! between polls, returning `Pending` only when the future is pending **and** the queue
//! is empty — so the future's own waker still drives the loop and nothing spins. The
//! frames go out interleaved, in order, exactly as they were emitted.

use core::future::{Future, poll_fn};
use core::pin::pin;
use core::task::Poll;
use std::cell::RefCell;
use std::collections::VecDeque;

use tdfu_core::progress::Progress;
use tdfu_proto::{Command, ProgressBody};

use super::Wire;
use crate::errors::DaemonError;

/// Where a synchronous [`ProgressSink`](tdfu_core::progress::ProgressSink) leaves work
/// for [`pump`] to send.
///
/// `RefCell` rather than a channel: the daemon serves one client at a time on a
/// current-thread runtime (decision D1), so there is no thread to cross and
/// a channel would be a dependency bought for nothing. Every borrow is scoped to one
/// statement, so the sink and the pump never hold one at the same time.
#[derive(Debug, Default)]
pub struct Queue {
    events: RefCell<VecDeque<Progress>>,
}

impl Queue {
    /// An empty queue.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A sink to hand an operation.
    ///
    /// ```ignore
    /// let queue = Queue::new();
    /// let mut sink = queue.sink();
    /// let done = pump(conn, cmd, &queue, ops::write(&dev, clock, alt, image, &mut sink)).await?;
    /// ```
    pub fn sink(&self) -> impl FnMut(Progress) + '_ {
        move |progress| self.events.borrow_mut().push_back(progress)
    }

    fn pop(&self) -> Option<Progress> {
        self.events.borrow_mut().pop_front()
    }

    fn is_empty(&self) -> bool {
        self.events.borrow().is_empty()
    }
}

/// Drive `future` to completion, flushing every [`Progress`] it emits as it emits it.
///
/// `cmd` decides whether frames go out at all: the attach rule gives log — and therefore
/// progress — output only to `BOOTSTRAP`, `WRITE` (including its erase and verify forms)
/// and `READ` on raw TCP and WebSocket, and to *every* command over HTTP. That rule is
/// [`Wire::logs_enabled_for`], which is the transport's to answer.
///
/// # Errors
/// [`DaemonError`] if a frame cannot be written — which is what a client that vanished
/// mid-operation looks like from here. The operation's future is dropped at that point,
/// mid-`await`, and every guard it holds unwinds: the claim it took, the staging file it
/// created, and the [`Busy`](super::state::Busy) the caller is holding.
pub async fn pump<W: Wire, T>(
    conn: &mut W,
    cmd: Command,
    queue: &Queue,
    future: impl Future<Output = T>,
) -> Result<T, DaemonError> {
    let mut future = pin!(future);
    let attached = conn.logs_enabled_for(cmd);
    loop {
        // One step: either the future finished, or there is progress to flush. It
        // answers `Pending` only when the future is pending AND the queue is empty, so
        // the future's own waker is what schedules the next poll — this does not spin.
        let finished = poll_fn(|cx| {
            if !queue.is_empty() {
                return Poll::Ready(None);
            }
            match future.as_mut().poll(cx) {
                Poll::Ready(value) => Poll::Ready(Some(value)),
                // The poll above may have pushed progress before returning `Pending`;
                // flushing it now is what makes a long transfer's bar move.
                Poll::Pending if !queue.is_empty() => Poll::Ready(None),
                Poll::Pending => Poll::Pending,
            }
        })
        .await;

        // Drain before returning, so the completion note a successful operation emits
        // last (`DFU download complete`, `Verify OK: N bytes match`) is sent before the
        // final OK frame rather than lost with the queue.
        let mut drained = 0_usize;
        while let Some(progress) = queue.pop() {
            drained += 1;
            if attached {
                send(conn, &progress).await?;
            }
        }

        if let Some(value) = finished {
            return Ok(value);
        }

        // The loop's one invariant, stated where it can catch a mistake: a step that
        // did not finish the operation only happens because the queue had something in
        // it, so the drain must have taken at least one event. If it did not, the next
        // iteration will make the same decision on the same state and this loop will
        // spin for ever.
        //
        // `cargo mutants` found four separate mutations of the queue predicates that
        // **hang** rather than fail, exactly as an audit found for three
        // descriptor-walk mutants. A hang is a worse failure than a
        // panic: it burns a CI slot and reports nothing. `debug_assert` costs nothing in
        // release and turns all four into an immediate, named test failure.
        //
        // **The release build does not depend on this line.** It terminates
        // because `drained > 0` is an invariant of the loop and not because anything
        // checks it: reaching here means `finished` was `None`, which the step above only
        // answers when the queue was non-empty, and nothing but this drain pops the queue.
        // The assertion exists to make a future edit that breaks the invariant fail fast,
        // and it does that only where debug assertions are on, so `cargo test --release`
        // would let those four mutants spin again.
        debug_assert!(drained > 0, "pump stepped with nothing to flush; this loop would spin");
    }
}

/// One [`Progress`] as one frame.
///
/// * [`Progress::Phase`] and [`Progress::Bytes`] are `RESP_PROGRESS`. The
///   `stage` byte is `Phase`'s own discriminant: the wire's stage
///   table lives *in* the enum precisely so this file does not carry a second copy, and
///   so "which stage am I in" is not state this file has to keep.
/// * [`Progress::Note`] is `RESP_LOG`: whole lines, the same text the local
///   CLI writes to stderr.
/// * [`Progress::Debug`] is **no frame at all**. It is core's protocol narration, which
///   every frontend puts behind its own debug switch; the daemon's switch is `-d`, and
///   `-d` is `tracing`. See the arm below.
///
/// **Byte counts are not log lines.** The C had no progress sender, so it pushed
/// `\r  N/M bytes (P%)` down the log stream; this daemon sends progress
/// frames instead and leaves terminating a live bar to the client.
async fn send<W: Wire>(conn: &mut W, progress: &Progress) -> Result<(), DaemonError> {
    match progress {
        // A phase that has just started has moved no bytes, so its percent is 0 — which
        // is also what the frame's own rule yields for it.
        Progress::Phase(phase) => {
            conn.progress(&ProgressBody {
                percent: 0,
                stage: phase.wire_byte(),
                message: phase.to_string(),
            })
            .await
        }
        // The message is [`tdfu_core::progress::bytes_line`] and not a `format!` of its
        // own: the CLI's local bar draws the same producer's output, so the counter a
        // `--host` run shows is spelled the way the local run it stands in for spells it.
        // Two copies of this string is exactly how they came to differ.
        Progress::Bytes { phase, done, total } => {
            conn.progress(&ProgressBody {
                percent: ProgressBody::percent_of(*done, *total),
                stage: phase.wire_byte(),
                message: tdfu_core::progress::bytes_line(*done, *total),
            })
            .await
        }
        Progress::Note(line) => conn.log(line).await,
        // **Core's protocol narration is not a wire frame.** The two frame kinds are the
        // client's contract, and every shipped client renders a `RESP_LOG` as a line the
        // user reads: sending narration there would put the daemon's debug detail in a
        // browser log nobody asked for, and a 16 MiB write's forgiven polls with it. It
        // goes to `tracing` instead, which is the daemon's own `-d` channel, so an
        // operator debugging the daemon sees core's steps interleaved with the daemon's.
        // A client that wants this detail runs the CLI with `-d` locally.
        Progress::Debug(line) => {
            tracing::debug!("{line}");
            Ok(())
        }
        // `Progress` is `#[non_exhaustive]` and lives in another crate. A kind added
        // later must not vanish: it goes out as a log line, which is the shape that
        // cannot be wrong.
        //
        // **Unreachable from this crate, and therefore unpinned** (an audit
        // found this claiming "the pin below says so"). `Progress` being
        // `#[non_exhaustive]` in `tdfu-core` (`progress.rs:71`) is exactly what makes the
        // arm necessary and what makes a test for it impossible from here: there is no
        // value this crate can construct that lands on it. A pin would need a
        // `#[doc(hidden)]` test-only constructor in `tdfu-core`, which is a bigger change
        // than the arm is worth. The behaviour is right; only the claim was not.
        other => conn.log(&format!("{other:?}")).await,
    }
}

#[cfg(test)]
mod tests {
    use super::{Queue, pump};
    use crate::commands::fake::{LoopbackConn, Sent};
    use tdfu_core::progress::{Phase, Progress};
    use tdfu_proto::{Command, ProgressBody};
    use tdfu_usb::mock::block_on;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// The headline: byte counts become progress frames, and they leave the
    /// daemon. No C daemon has ever sent one.
    #[test]
    fn rpc_progress_frames_are_actually_sent() -> TestResult {
        let mut conn = LoopbackConn::raw().during(Command::Write);
        let queue = Queue::new();
        let mut sink = queue.sink();
        let outcome = block_on(pump(&mut conn, Command::Write, &queue, async {
            sink(Progress::Phase(Phase::Download));
            sink(Progress::Bytes {
                phase: Phase::Download,
                done: 2048,
                total: Some(4096),
            });
            sink(Progress::Note("DFU download complete".to_owned()));
            42_u8
        }))?;
        assert_eq!(outcome, 42);

        assert_eq!(
            conn.sent(),
            vec![
                Sent::Progress(ProgressBody {
                    percent: 0,
                    stage: 3,
                    message: "download".to_owned(),
                }),
                Sent::Progress(ProgressBody {
                    percent: 50,
                    stage: 3,
                    message: "2048/4096 bytes".to_owned(),
                }),
                Sent::Log("DFU download complete\n".to_owned()),
            ]
        );
        Ok(())
    }

    /// **The narration pin.** Core's [`Progress::Debug`] produces **no frame**: not a
    /// `RESP_LOG`, not a `RESP_PROGRESS`.
    ///
    /// The two frame kinds are the client's contract, and every shipped client renders a
    /// `RESP_LOG` as a line the user reads. The daemon's own `-d` is `tracing`, which is
    /// where these go. Revert check: route `Debug` to `conn.log` and the frame list here
    /// grows the narration line.
    #[test]
    fn a_debug_line_is_never_a_frame() -> TestResult {
        let mut conn = LoopbackConn::raw().during(Command::Write);
        let queue = Queue::new();
        let mut sink = queue.sink();
        block_on(pump(&mut conn, Command::Write, &queue, async {
            sink(Progress::Debug("claiming alt 0 on interface 0".to_owned()));
            sink(Progress::Note("DFU download complete".to_owned()));
        }))?;

        assert_eq!(
            conn.sent(),
            vec![Sent::Log("DFU download complete\n".to_owned())],
            "the narration must not reach the client"
        );
        // Not merely dropped by the attach gate either: this command *is* attached, which
        // is what the note above it proves.
        assert!(conn.suppressed().is_empty());
        Ok(())
    }

    /// The `stage` byte is `Phase`'s discriminant, so there is no
    /// second table here to drift. The whole list, checked through the frames rather
    /// than by reading the enum.
    #[test]
    fn rpc_progress_stage_bytes() -> TestResult {
        for (phase, stage, name) in [
            (Phase::Unknown, 0_u8, "working"),
            (Phase::Stage1, 1, "stage1"),
            (Phase::UBoot, 2, "u-boot"),
            (Phase::Download, 3, "download"),
            (Phase::Manifest, 4, "manifest"),
            (Phase::Upload, 5, "upload"),
            (Phase::Verify, 6, "verify"),
            (Phase::Erase, 7, "erase"),
        ] {
            let mut conn = LoopbackConn::raw().during(Command::Write);
            let queue = Queue::new();
            let mut sink = queue.sink();
            block_on(pump(&mut conn, Command::Write, &queue, async {
                sink(Progress::Phase(phase));
            }))?;
            assert_eq!(
                conn.sent(),
                vec![Sent::Progress(ProgressBody {
                    percent: 0,
                    stage,
                    message: name.to_owned(),
                })],
                "{phase:?}"
            );
        }
        Ok(())
    }

    /// A read has no knowable total until the short block ends it, so
    /// the percent is 0 and the message carries the count instead of a ratio.
    #[test]
    fn an_unknown_total_reports_the_count_and_no_percent() -> TestResult {
        let mut conn = LoopbackConn::raw().during(Command::Read);
        let queue = Queue::new();
        let mut sink = queue.sink();
        block_on(pump(&mut conn, Command::Read, &queue, async {
            sink(Progress::Bytes {
                phase: Phase::Upload,
                done: 4096,
                total: None,
            });
        }))?;
        assert_eq!(
            conn.sent(),
            vec![Sent::Progress(ProgressBody {
                percent: 0,
                stage: 5,
                message: "4096 bytes".to_owned(),
            })]
        );
        Ok(())
    }

    /// The attach rule: nothing is emitted for a command with no log client.
    /// The operation still runs and still returns its value.
    ///
    /// The connection has the same gate, so "nothing on the wire" no
    /// longer tells the two apart. `suppressed()` does: it is what the connection refused,
    /// so an empty list means **this** file's gate stopped the frames before they were
    /// offered. That is the assertion that fails if `pump` stops consulting
    /// [`Wire::logs_enabled_for`](super::Wire::logs_enabled_for).
    #[test]
    fn rpc_log_frames_when_not_attached() -> TestResult {
        let mut conn = LoopbackConn::raw().during(Command::Discover);
        let queue = Queue::new();
        let mut sink = queue.sink();
        let value = block_on(pump(&mut conn, Command::Discover, &queue, async {
            sink(Progress::Note("this one has no log client".to_owned()));
            sink(Progress::Bytes {
                phase: Phase::Download,
                done: 1,
                total: Some(1),
            });
            7_u8
        }))?;
        assert_eq!(value, 7);
        assert_eq!(conn.sent(), Vec::new(), "DISCOVER on raw TCP attaches no logs");
        assert!(
            conn.suppressed().is_empty(),
            "and this file's gate stopped them, not the connection's: {:?}",
            conn.suppressed()
        );
        Ok(())
    }

    /// ... and over HTTP every command attaches, which is the transport's
    /// answer, not this file's.
    #[test]
    fn http_attaches_every_command() -> TestResult {
        let mut conn = LoopbackConn::http().during(Command::Discover);
        let queue = Queue::new();
        let mut sink = queue.sink();
        block_on(pump(&mut conn, Command::Discover, &queue, async {
            sink(Progress::Note("visible over HTTP".to_owned()));
        }))?;
        assert_eq!(conn.sent(), vec![Sent::Log("visible over HTTP\n".to_owned())]);
        Ok(())
    }

    /// The frames interleave with the work rather than arriving in a heap at the end —
    /// which is the difference between a progress bar and a receipt.
    ///
    /// The future yields between events and reads the transcript through the `Rc` the
    /// connection shares, so each check happens *while* `pump` holds the connection
    /// mutably. A `pump` that buffered would leave every reading at 0.
    #[test]
    fn progress_is_flushed_between_polls_not_at_the_end() -> TestResult {
        let mut conn = LoopbackConn::raw().during(Command::Write);
        let transcript = conn.transcript();
        let queue = Queue::new();
        let mut sink = queue.sink();
        let seen = std::cell::RefCell::new(Vec::new());
        block_on(pump(&mut conn, Command::Write, &queue, async {
            for done in 1..=3_u64 {
                sink(Progress::Bytes {
                    phase: Phase::Download,
                    done,
                    total: Some(3),
                });
                yield_once().await;
                seen.borrow_mut().push(transcript.borrow().len());
            }
        }))?;
        assert_eq!(
            seen.into_inner(),
            vec![1, 2, 3],
            "each byte count was on the wire before the next one was produced"
        );
        let sent = conn.sent();
        assert_eq!(sent.len(), 3, "one frame per byte count");
        for (index, frame) in sent.iter().enumerate() {
            let Sent::Progress(body) = frame else {
                return Err(format!("expected a progress frame, got {frame:?}").into());
            };
            let done = index + 1;
            assert_eq!(body.message, format!("{done}/3 bytes"));
        }
        Ok(())
    }

    /// A client that goes away mid-operation surfaces as an error from the frame write,
    /// and the operation's future is dropped there and then. The `Busy` guard's unwind
    /// is pinned in `state.rs`; this pins that the failure is reported at all rather
    /// than swallowed.
    #[test]
    fn a_dropped_client_stops_the_pump() {
        let mut conn = LoopbackConn::raw().during(Command::Write).failing_after(1);
        let queue = Queue::new();
        let mut sink = queue.sink();
        let reached_the_end = std::cell::Cell::new(false);
        let outcome = block_on(pump(&mut conn, Command::Write, &queue, async {
            sink(Progress::Note("first".to_owned()));
            sink(Progress::Note("second".to_owned()));
            yield_once().await;
            reached_the_end.set(true);
        }));
        assert!(outcome.is_err(), "the write failure must propagate");
        assert!(
            !reached_the_end.get(),
            "the operation must not run on after the client has gone"
        );
    }

    /// The completion note an operation emits last is sent *before* the final response,
    /// not dropped with the queue. An earlier implementation's local CLI printed nothing
    /// on a successful write while its daemon printed two lines; core owns those notes
    /// now, and this is the daemon end of that.
    #[test]
    fn the_last_note_is_sent_before_the_pump_returns() -> TestResult {
        let mut conn = LoopbackConn::raw().during(Command::Write);
        let queue = Queue::new();
        let mut sink = queue.sink();
        block_on(pump(&mut conn, Command::Write, &queue, async {
            yield_once().await;
            sink(Progress::Note("Verify OK: 16777216 bytes match".to_owned()));
        }))?;
        assert_eq!(
            conn.sent(),
            vec![Sent::Log("Verify OK: 16777216 bytes match\n".to_owned())]
        );
        Ok(())
    }

    /// **Progress emitted just before the operation blocks is sent before the pump
    /// parks** — which is the whole reason for the `Pending if !queue.is_empty()` arm.
    ///
    /// `mock::block_on` cannot show this: it spins with a no-op waker, so a pump that
    /// returned `Pending` with a full queue would be re-polled microseconds later and
    /// flush anyway. Under a real runtime the park lasts until the *device* wakes the
    /// task, which on a manifest poll is up to 500 ms and on an erase can be seconds —
    /// so the frames would sit unsent for exactly as long as the user most wants them.
    /// Deleting the arm therefore survived every test here, and it was survivable only
    /// because the executor could not express a real park (contracts, "Amendments to the
    /// seam": check the fixture can produce the separating input before calling a mutant
    /// equivalent).
    ///
    /// This polls the pump **by hand, exactly once**, which is what a parking executor
    /// does, and then looks at what went out.
    #[test]
    fn progress_is_sent_before_the_pump_parks() -> TestResult {
        use core::pin::pin;
        use core::task::{Context, Poll, Waker};

        let mut conn = LoopbackConn::raw().during(Command::Write);
        let transcript = conn.transcript();
        let queue = Queue::new();
        let mut sink = queue.sink();
        let gate = std::cell::Cell::new(false);

        let operation = async {
            sink(Progress::Note("about to wait on the device".to_owned()));
            // Pends without waking: a device that has not answered yet.
            core::future::poll_fn(|_cx| if gate.get() { Poll::Ready(()) } else { Poll::Pending }).await;
            7_u8
        };
        let mut pumping = pin!(pump(&mut conn, Command::Write, &queue, operation));
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);

        assert!(
            pumping.as_mut().poll(&mut cx).is_pending(),
            "the operation has not finished"
        );
        assert_eq!(
            transcript.borrow().len(),
            1,
            "the note must be on the wire before the pump parks, not after the device answers"
        );

        gate.set(true);
        let value = match pumping.as_mut().poll(&mut cx) {
            Poll::Ready(value) => value?,
            Poll::Pending => return Err("the gate is open; the pump must finish".into()),
        };
        assert_eq!(value, 7);
        Ok(())
    }

    /// A yield point, so the pump has to run more than one loop iteration.
    async fn yield_once() {
        let mut yielded = false;
        core::future::poll_fn(move |cx| {
            if yielded {
                core::task::Poll::Ready(())
            } else {
                yielded = true;
                cx.waker().wake_by_ref();
                core::task::Poll::Pending
            }
        })
        .await;
    }
}
