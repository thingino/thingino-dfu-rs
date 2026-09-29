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
//!
//! # A payload or a reply too large to hold
//!
//! [`pump_with`] is the same loop for an operation that also reads a streamed request
//! payload ([`Intake`]) or writes a streamed reply ([`Outbox`]). The operation cannot use
//! the connection itself, because the pump holds it to send the progress; so it leaves
//! what it wants with the pump, and the pump, the connection's one user, does the reading
//! and the writing between polls.

use core::cell::Cell;
use core::future::{Future, poll_fn};
use core::pin::pin;
use core::task::Poll;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::io;

use tdfu_core::progress::Progress;
use tdfu_core::stream::{AsyncSink, AsyncSource};
use tdfu_proto::{Command, HEADER_LEN, ProgressBody};

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

/// The most an operation is handed from a streamed payload in one step, whatever it asks
/// for at once: a bootrom chunk is 64 KiB, and a daemon on a microcontroller should hold
/// that chunk once, not twice.
const INTAKE_STEP: usize = 4 * 1024;

/// How much of a streamed reply an operation may leave before it waits for the pump.
const OUTBOX_CAPACITY: usize = 4 * 1024;

/// A streamed request payload, read by [`pump_with`] on an operation's behalf.
///
/// The operation's [`IntakeSource`] says how many bytes it wants and waits; the pump,
/// seeing that, reads them from the connection and polls the operation again.
#[derive(Debug, Default)]
pub struct Intake {
    /// Bytes the operation is waiting for; zero while it is not.
    wanted: Cell<usize>,
    /// The bytes read for it.
    ready: RefCell<Vec<u8>>,
}

impl Intake {
    /// Nothing asked for yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The source to hand the operation.
    #[must_use]
    pub const fn source(&self) -> IntakeSource<'_> {
        IntakeSource { intake: self }
    }

    /// Read what the operation is waiting for.
    async fn serve<W: Wire>(&self, conn: &mut W) -> Result<(), DaemonError> {
        let wanted = self.wanted.get();
        if wanted == 0 {
            return Ok(());
        }
        let mut ready = core::mem::take(&mut *self.ready.borrow_mut());
        ready.resize(wanted, 0);
        conn.payload(&mut ready).await?;
        *self.ready.borrow_mut() = ready;
        self.wanted.set(0);
        Ok(())
    }
}

/// An [`Intake`] as the operation reads it.
#[derive(Debug)]
pub struct IntakeSource<'a> {
    intake: &'a Intake,
}

impl AsyncSource for IntakeSource<'_> {
    async fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
        for piece in buf.chunks_mut(INTAKE_STEP) {
            self.intake.wanted.set(piece.len());
            // No waker is kept: the pump is the only thing that can answer, and it polls
            // the operation again as soon as it has.
            poll_fn(|_| {
                if self.intake.wanted.get() == 0 {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            })
            .await;
            let ready = self.intake.ready.borrow();
            let Some(bytes) = ready.get(..piece.len()) else {
                return Err(io::Error::other("the request payload came back short"));
            };
            piece.copy_from_slice(bytes);
        }
        Ok(())
    }
}

/// A streamed reply, written by [`pump_with`] on an operation's behalf: [`Intake`] in the
/// other direction. The operation's [`OutboxSink`] fills it and waits while it is full;
/// the pump empties it onto the connection ([`Wire::reply_body`]).
#[derive(Debug, Default)]
pub struct Outbox {
    held: RefCell<Vec<u8>>,
}

impl Outbox {
    /// Empty.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The sink to hand the operation.
    #[must_use]
    pub const fn sink(&self) -> OutboxSink<'_> {
        OutboxSink { outbox: self }
    }

    fn is_empty(&self) -> bool {
        self.held.borrow().is_empty()
    }

    /// Write out what the operation left.
    async fn serve<W: Wire>(&self, conn: &mut W) -> Result<(), DaemonError> {
        let mut held = core::mem::take(&mut *self.held.borrow_mut());
        if !held.is_empty() {
            conn.reply_body(&held).await?;
        }
        held.clear();
        *self.held.borrow_mut() = held;
        Ok(())
    }
}

/// An [`Outbox`] as the operation writes it.
#[derive(Debug)]
pub struct OutboxSink<'a> {
    outbox: &'a Outbox,
}

impl AsyncSink for OutboxSink<'_> {
    async fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
        let mut rest = data;
        while !rest.is_empty() {
            // As for the intake: the pump empties it and polls again.
            poll_fn(|_| {
                if self.outbox.held.borrow().len() < OUTBOX_CAPACITY {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            })
            .await;
            let mut held = self.outbox.held.borrow_mut();
            let room = OUTBOX_CAPACITY.saturating_sub(held.len()).min(rest.len());
            let (now, later) = rest.split_at(room);
            held.extend_from_slice(now);
            rest = later;
        }
        Ok(())
    }
}

/// The streams an operation reads and writes through [`pump_with`].
#[derive(Debug, Clone, Copy, Default)]
pub struct Io<'a> {
    /// The request payload it reads.
    pub intake: Option<&'a Intake>,
    /// The reply it writes.
    pub outbox: Option<&'a Outbox>,
}

impl Io<'_> {
    /// Neither.
    pub const NONE: Self = Self {
        intake: None,
        outbox: None,
    };

    /// Is the operation waiting on the pump?
    fn has_work(&self) -> bool {
        self.intake.is_some_and(|intake| intake.wanted.get() > 0)
            || self.outbox.is_some_and(|outbox| !outbox.is_empty())
    }

    async fn serve<W: Wire>(&self, conn: &mut W) -> Result<(), DaemonError> {
        if let Some(intake) = self.intake {
            intake.serve(conn).await?;
        }
        if let Some(outbox) = self.outbox {
            outbox.serve(conn).await?;
        }
        Ok(())
    }
}

/// Everything sent while a streamed request is still arriving stays under this.
const INTAKE_FRAME_BUDGET: usize = 16 * 1024;

/// While a request is still arriving, one byte-count frame per this much of the total.
const INTAKE_BYTES_STEPS: u64 = 100;

/// ... and never more often than this many bytes apart.
const INTAKE_BYTES_FLOOR: u64 = 64 * 1024;

/// What goes out while a streamed request is still arriving: little.
///
/// A client may read nothing until it has sent its whole request; a browser's `fetch`
/// does not look at the response before the body is up. Every frame sent meanwhile waits
/// in the client's receive buffer, and once that is full the daemon's writes block, so
/// it stops reading the payload, so the client's writes block too, and neither side
/// moves again. So while the payload is still coming, byte counts are thinned to about
/// [`INTAKE_BYTES_STEPS`] per phase and everything together stays under
/// [`INTAKE_FRAME_BUDGET`], far below any receive window. Narration past the budget is
/// counted rather than sent, and the count goes out once the payload is in.
#[derive(Debug, Default)]
struct Thinning {
    /// Frame bytes sent while the payload was arriving.
    spent: usize,
    /// The stage and byte count of the last byte-count frame sent meanwhile.
    last: Option<(u8, u64)>,
    /// Narration lines held back.
    held_back: usize,
}

impl Thinning {
    async fn offer<W: Wire>(&mut self, conn: &mut W, progress: &Progress) -> Result<(), DaemonError> {
        if conn.payload_left() == 0 {
            self.settle(conn).await?;
            return send(conn, progress).await;
        }
        if let Progress::Bytes { phase, done, total } = progress {
            let step = total.map_or(INTAKE_BYTES_FLOOR, |total| {
                (total / INTAKE_BYTES_STEPS).max(INTAKE_BYTES_FLOOR)
            });
            let since = self
                .last
                .filter(|(stage, _)| *stage == phase.wire_byte())
                .map(|(_, last)| done.saturating_sub(last));
            if since.is_some_and(|since| since < step) && Some(*done) != *total {
                return Ok(());
            }
        }
        let size = frame_size(progress);
        if self.spent.saturating_add(size) > INTAKE_FRAME_BUDGET {
            if let Progress::Debug(line) = progress {
                tracing::debug!("{line}");
                self.held_back += 1;
            }
            return Ok(());
        }
        self.spent += size;
        if let Progress::Bytes { phase, done, .. } = progress {
            self.last = Some((phase.wire_byte(), *done));
        }
        send(conn, progress).await
    }

    /// Own up to the narration held back, once the payload is in.
    async fn settle<W: Wire>(&mut self, conn: &mut W) -> Result<(), DaemonError> {
        if self.held_back > 0 && conn.payload_left() == 0 {
            let count = core::mem::take(&mut self.held_back);
            conn.debug(&format!(
                "{count} narration lines were not sent while the request was still arriving"
            ))
            .await?;
        }
        Ok(())
    }
}

/// About how many bytes `progress` takes on the wire: its frame, an HTTP chunk's framing
/// around it, and its payload.
fn frame_size(progress: &Progress) -> usize {
    const FRAMING: usize = HEADER_LEN + 16;
    FRAMING
        + match progress {
            Progress::Note(line) | Progress::Debug(line) => line.len() + 1,
            // A progress body is four bytes and a short message.
            _ => 64,
        }
}

/// Drive `future` to completion, flushing every [`Progress`] it emits as it emits it.
///
/// `cmd` decides whether log and progress frames go out at all: the attach rule gives
/// them only to `BOOTSTRAP`, `WRITE` (including its erase and verify forms) and `READ`
/// on raw TCP and WebSocket, and to *every* command over HTTP. That rule is
/// [`Wire::logs_enabled_for`], which is the transport's to answer. The narration is not
/// under it: a connection that asked for it ([`Wire::narrates`]) reads `RESP_DEBUG`
/// frames on every command, because asking is what says the client can, and a local
/// `-d` narrates every operation too. The attach rule protects clients that asked for
/// nothing beyond the final frame.
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
    pump_with(conn, cmd, queue, Io::NONE, future).await
}

/// One step of [`pump_with`]'s loop.
enum Step<T> {
    /// The operation finished.
    Done(T),
    /// There is progress to send.
    Flush,
    /// The operation is waiting on its [`Io`].
    Io,
}

/// [`pump`], for an operation that also reads a streamed payload or writes a streamed
/// reply through `io`. The pump reads and writes for it between polls, and while the
/// payload is still arriving it sends little ([`Thinning`]).
///
/// # Errors
/// As [`pump`], and a failure to read the payload or write the reply ends it the same
/// way: the operation's future is dropped where it stands.
pub async fn pump_with<W: Wire, T>(
    conn: &mut W,
    cmd: Command,
    queue: &Queue,
    io: Io<'_>,
    future: impl Future<Output = T>,
) -> Result<T, DaemonError> {
    let mut future = pin!(future);
    // The narration is offered to the connection whatever the command; the connection
    // itself keeps the attach rule for the log and progress frames (`Conn::log`,
    // `Conn::progress`).
    let attached = conn.logs_enabled_for(cmd) || conn.narrates();
    let mut thinning = Thinning::default();
    loop {
        // One step: the future finished, or there is progress to flush, or the future
        // waits on its streams. It answers `Pending` only when the future is pending
        // with nothing to flush and nothing to serve, so the future's own waker is what
        // schedules the next poll — this does not spin.
        let step = poll_fn(|cx| {
            if !queue.is_empty() {
                return Poll::Ready(Step::Flush);
            }
            if io.has_work() {
                return Poll::Ready(Step::Io);
            }
            match future.as_mut().poll(cx) {
                Poll::Ready(value) => Poll::Ready(Step::Done(value)),
                // The poll above may have pushed progress before returning `Pending`;
                // flushing it now is what makes a long transfer's bar move.
                Poll::Pending if !queue.is_empty() => Poll::Ready(Step::Flush),
                Poll::Pending if io.has_work() => Poll::Ready(Step::Io),
                Poll::Pending => Poll::Pending,
            }
        })
        .await;

        // Drain before returning, so the completion note a successful operation emits
        // last (`Write complete`, `Verify OK: N bytes match`) is sent before the
        // final OK frame rather than lost with the queue.
        let mut drained = 0_usize;
        while let Some(progress) = queue.pop() {
            drained += 1;
            if attached {
                thinning.offer(conn, &progress).await?;
            }
        }

        match step {
            Step::Done(value) => {
                // The last of a streamed reply, if the operation wrote one.
                io.serve(conn).await?;
                if attached {
                    thinning.settle(conn).await?;
                }
                return Ok(value);
            }
            Step::Io => {
                io.serve(conn).await?;
                // Serving answers the wait, or the next step makes the same decision on
                // the same state and this loop spins for ever.
                debug_assert!(!io.has_work(), "pump served the streams and left them waiting");
            }
            Step::Flush => {
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
                // checks it: reaching here means the step was `Flush`, which the step above only
                // answers when the queue was non-empty, and nothing but this drain pops the queue.
                // The assertion exists to make a future edit that breaks the invariant fail fast,
                // and it does that only where debug assertions are on, so `cargo test --release`
                // would let those four mutants spin again.
                debug_assert!(drained > 0, "pump stepped with nothing to flush; this loop would spin");
            }
        }
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
        // A client that wants this detail asks for it, and then it is a frame as well.
        Progress::Debug(line) => {
            tracing::debug!("{line}");
            // ... and, for a connection that asked (`CMD_DEBUG` or `X-Debug: 1`), a
            // `RESP_DEBUG` frame too, so a remote `-d` reads like a local one.
            conn.debug(line).await
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
    use super::{INTAKE_BYTES_STEPS, INTAKE_FRAME_BUDGET, Intake, Io, Outbox, Queue, pump, pump_with};
    use crate::commands::Wire;
    use crate::commands::fake::{LoopbackConn, Sent};
    use tdfu_core::progress::{Phase, Progress};
    use tdfu_core::stream::{AsyncSink as _, AsyncSource as _};
    use tdfu_proto::{Command, HEADER_LEN, ProgressBody, Status};
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
            sink(Progress::Note("Write complete".to_owned()));
            42_u8
        }))?;
        assert_eq!(outcome, 42);

        assert_eq!(
            conn.sent(),
            vec![
                Sent::Progress(ProgressBody {
                    percent: 0,
                    stage: 3,
                    message: "writing".to_owned(),
                }),
                Sent::Progress(ProgressBody {
                    percent: 50,
                    stage: 3,
                    message: "2048/4096 bytes".to_owned(),
                }),
                Sent::Log("Write complete\n".to_owned()),
            ]
        );
        Ok(())
    }

    /// **The narration pin.** Core's [`Progress::Debug`] is **never a `RESP_LOG`** and
    /// never a `RESP_PROGRESS`: every shipped client renders a `RESP_LOG` as a line the
    /// user reads, and the narration is not that. A connection that did not ask gets no
    /// frame at all; the daemon's own `-d` is `tracing`, which is where these always go.
    /// Revert check: route `Debug` to `conn.log` and the frame list here grows the
    /// narration line.
    #[test]
    fn a_debug_line_is_not_a_frame_unless_asked() -> TestResult {
        let mut conn = LoopbackConn::raw().during(Command::Write);
        let queue = Queue::new();
        let mut sink = queue.sink();
        block_on(pump(&mut conn, Command::Write, &queue, async {
            sink(Progress::Debug("claiming alt 0 on interface 0".to_owned()));
            sink(Progress::Note("Write complete".to_owned()));
        }))?;

        assert_eq!(
            conn.sent(),
            vec![Sent::Log("Write complete\n".to_owned())],
            "the narration must not reach a client that did not ask"
        );
        // This command *is* attached (the note above proves it), so the narration was
        // held back by the ask, not by the attach gate.
        assert_eq!(
            conn.suppressed(),
            vec![Sent::Debug("claiming alt 0 on interface 0\n".to_owned())]
        );
        Ok(())
    }

    /// `CMD_DEBUG` (or `X-Debug: 1`) turns the narration into `RESP_DEBUG` frames, in
    /// order with the logs, so a remote `-d` reads as a local one does.
    #[test]
    fn a_debug_line_is_a_frame_for_a_connection_that_asked() -> TestResult {
        let mut conn = LoopbackConn::raw().narrating().during(Command::Write);
        let queue = Queue::new();
        let mut sink = queue.sink();
        block_on(pump(&mut conn, Command::Write, &queue, async {
            sink(Progress::Debug("claiming alt 0 on interface 0".to_owned()));
            sink(Progress::Note("Write complete".to_owned()));
        }))?;

        assert_eq!(
            conn.sent(),
            vec![
                Sent::Debug("claiming alt 0 on interface 0\n".to_owned()),
                Sent::Log("Write complete\n".to_owned()),
            ]
        );
        assert!(conn.suppressed().is_empty());
        Ok(())
    }

    /// The narration is not under the attach rule: a connection that asked reads it on
    /// a command whose responses carry no logs, while the log line beside it is still
    /// held back. A local `-d --reboot` narrates the reboot's `make idle` poll, and a
    /// remote one has to read the same.
    #[test]
    fn narration_reaches_every_command_on_a_connection_that_asked() -> TestResult {
        let mut conn = LoopbackConn::raw().narrating().during(Command::Reboot);
        let queue = Queue::new();
        let mut sink = queue.sink();
        block_on(pump(&mut conn, Command::Reboot, &queue, async {
            sink(Progress::Debug(
                "make idle: poll 0 found dfuIDLE, status OK (0x00)".to_owned(),
            ));
            sink(Progress::Note("Reboot triggered".to_owned()));
        }))?;

        assert_eq!(
            conn.sent(),
            vec![Sent::Debug(
                "make idle: poll 0 found dfuIDLE, status OK (0x00)\n".to_owned()
            )]
        );
        assert_eq!(
            conn.suppressed(),
            vec![Sent::Log("Reboot triggered\n".to_owned())],
            "the attach rule still holds for the log line"
        );
        Ok(())
    }

    /// And a connection that did not ask reads nothing from that same command: the
    /// pump offers it nothing, exactly as before the narration existed.
    #[test]
    fn a_command_that_carries_no_logs_stays_silent_for_a_connection_that_did_not_ask() -> TestResult {
        let mut conn = LoopbackConn::raw().during(Command::Reboot);
        let queue = Queue::new();
        let mut sink = queue.sink();
        block_on(pump(&mut conn, Command::Reboot, &queue, async {
            sink(Progress::Debug(
                "make idle: poll 0 found dfuIDLE, status OK (0x00)".to_owned(),
            ));
            sink(Progress::Note("Reboot triggered".to_owned()));
        }))?;

        assert!(conn.sent().is_empty());
        assert!(conn.suppressed().is_empty(), "nothing was even offered");
        Ok(())
    }

    /// A narration line needs a command in flight to ride on: the connection refuses
    /// one with nothing to answer, asked or not.
    #[test]
    fn narration_needs_a_command_in_flight() -> TestResult {
        let mut conn = LoopbackConn::raw().narrating();
        block_on(Wire::debug(&mut conn, "claiming alt 0 on interface 0"))?;
        assert!(conn.sent().is_empty());
        assert_eq!(
            conn.suppressed(),
            vec![Sent::Debug("claiming alt 0 on interface 0\n".to_owned())]
        );
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
            (Phase::Download, 3, "writing"),
            (Phase::Manifest, 4, "finishing"),
            (Phase::Upload, 5, "reading"),
            (Phase::Verify, 6, "verifying"),
            (Phase::Erase, 7, "erasing"),
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

    // ------------------------------------------------------------ streams

    /// What a recorded frame took on the wire, header and all.
    fn wire_size(frame: &Sent) -> usize {
        HEADER_LEN
            + match frame {
                Sent::Log(line) | Sent::Debug(line) => line.len(),
                Sent::Progress(body) => body.encode().map_or(0, |bytes| bytes.len()),
                Sent::Response(_, payload) => payload.len(),
            }
    }

    /// **Little goes out while a streamed payload is still arriving**, because a client
    /// may read nothing until it has sent it all, and what waits unread in its receive
    /// buffer must never fill it. Byte counts are thinned, the rest stays under a budget,
    /// the narration past the budget is counted and owned up to once the payload is in,
    /// and from then on everything flows as it always does.
    #[test]
    fn little_goes_out_while_a_payload_is_arriving() -> TestResult {
        const LEN: usize = 1 << 20;
        const BLOCK: usize = 4096;
        let payload: Vec<u8> = (0..=250_u8).cycle().take(LEN).collect();
        let mut conn = LoopbackConn::raw().narrating().during(Command::Write);
        conn.feed(&payload);
        let queue = Queue::new();
        let intake = Intake::new();
        let got = std::cell::RefCell::new(Vec::new());
        let io = Io {
            intake: Some(&intake),
            outbox: None,
        };
        let mut sink = queue.sink();
        block_on(pump_with(&mut conn, Command::Write, &queue, io, async {
            let mut source = intake.source();
            let mut block = vec![0_u8; BLOCK];
            sink(Progress::Phase(Phase::Download));
            for done in (BLOCK..=LEN).step_by(BLOCK) {
                source.read_exact(&mut block).await?;
                got.borrow_mut().extend_from_slice(&block);
                sink(Progress::Debug(format!(
                    "download: block at {done:>8} went out, {}",
                    "-".repeat(80)
                )));
                sink(Progress::Bytes {
                    phase: Phase::Download,
                    done: done as u64,
                    total: Some(LEN as u64),
                });
            }
            sink(Progress::Note("Write complete".to_owned()));
            Ok::<(), std::io::Error>(())
        }))??;
        assert_eq!(got.into_inner(), payload, "the operation read the payload, in order");

        let sent = conn.sent();
        let left = conn.payload_left_at_each_frame();
        let during: Vec<&Sent> = sent
            .iter()
            .zip(&left)
            .filter(|(_, left)| **left > 0)
            .map(|(frame, _)| frame)
            .collect();
        let bytes: usize = during.iter().map(|frame| wire_size(frame)).sum();
        assert!(
            bytes <= INTAKE_FRAME_BUDGET,
            "{bytes} bytes went out while the payload arrived"
        );
        let counts = during.iter().filter(|frame| matches!(frame, Sent::Progress(_))).count();
        assert!(
            counts <= usize::try_from(INTAKE_BYTES_STEPS)? + 2,
            "{counts} progress frames while the payload arrived"
        );
        assert!(counts > 2, "the bar still moves: {counts}");
        let held = sent
            .iter()
            .find_map(|frame| match frame {
                Sent::Debug(line) if line.contains("narration lines were not sent") => Some(line.clone()),
                _ => None,
            })
            .ok_or("the held-back narration is owned up to")?;
        let count: usize = held.split(' ').next().unwrap_or("0").parse()?;
        let narrated = sent.iter().filter(|frame| matches!(frame, Sent::Debug(_))).count();
        assert_eq!(
            count + narrated - 1,
            LEN / BLOCK,
            "every line is either sent or counted: {held}"
        );
        assert!(
            sent.contains(&Sent::Progress(ProgressBody {
                percent: 100,
                stage: Phase::Download.wire_byte(),
                message: format!("{LEN}/{LEN} bytes"),
            })),
            "the last count goes out"
        );
        assert_eq!(sent.last(), Some(&Sent::Log("Write complete\n".to_owned())));
        Ok(())
    }

    /// A request read whole is never thinned: nothing is arriving.
    #[test]
    fn a_whole_request_is_not_thinned() -> TestResult {
        let mut conn = LoopbackConn::raw().during(Command::Write);
        let queue = Queue::new();
        let mut sink = queue.sink();
        block_on(pump_with(&mut conn, Command::Write, &queue, Io::NONE, async {
            for done in 1..=500_u64 {
                sink(Progress::Bytes {
                    phase: Phase::Download,
                    done,
                    total: Some(500),
                });
            }
        }))?;
        assert_eq!(conn.progress_frames().len(), 500);
        Ok(())
    }

    /// **A reply can be written by the operation itself**, through the pump, in order,
    /// whatever sizes it writes in; the last of it goes out before the pump returns.
    #[test]
    fn an_operation_writes_its_reply_through_the_outbox() -> TestResult {
        let body: Vec<u8> = (0..50_000_u32).map(|at| (at % 253) as u8).collect();
        let mut conn = LoopbackConn::raw().during(Command::Read);
        block_on(conn.begin_reply(Status::Ok, body.len() as u64))?;
        let outbox = Outbox::new();
        let io = Io {
            intake: None,
            outbox: Some(&outbox),
        };
        block_on(pump_with(&mut conn, Command::Read, &Queue::new(), io, async {
            let mut out = outbox.sink();
            for piece in body.chunks(3001) {
                out.write_all(piece).await?;
                yield_once().await;
            }
            Ok::<(), std::io::Error>(())
        }))??;
        block_on(conn.end_reply())?;
        assert_eq!(conn.response(), Some((Status::Ok, body)));
        Ok(())
    }
}
