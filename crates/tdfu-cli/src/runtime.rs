//! Driving one device's future to completion, on this thread.
//!
//! The core's operations are `async` and `?Send` by design (AGENTS.md D1): one device is
//! driven from one current-thread executor, so `RefCell`-backed transport handles and
//! `!Send` browser futures share one set of signatures. On native there is exactly one
//! device per run, so this is twenty lines rather than a runtime.
//!
//! # Why not the mock's `block_on`
//!
//! [`tdfu_usb::mock::block_on`] is a spin loop with a no-op waker, and says so: it is
//! enough for a scripted double that never returns `Pending`. The native backend does
//! return `Pending` — its bulk and control transfers `.await` real `nusb` futures woken
//! from `nusb`'s own event loop — so a spinning executor would burn a core for the whole
//! of a 30 s DNLOAD. This one parks and is woken.
//!
//! # Why not `tokio`
//!
//! Nothing here needs a reactor. `nusb` owns its own I/O thread and wakes the waker it
//! was given; the backend's control-plane calls are deliberately blocking `.wait()`s
//! (see `tdfu_usb::native::transport`'s module docs). A runtime would add a dependency
//! and a thread pool to schedule a single future, and the backend's own docs warn that
//! an outer `tokio::time::timeout` around one of its calls cannot fire anyway.

use core::future::Future;
use core::pin::pin;
use core::task::{Context, Poll};
use std::sync::Arc;
use std::task::Wake;
use std::thread::{self, Thread};

/// Wakes the thread that is parked inside [`block_on`].
struct Unpark(Thread);

impl Wake for Unpark {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.unpark();
    }
}

/// Run `future` to completion, parking between polls.
///
/// Safe against a wake that arrives between the poll and the park: `thread::park`
/// consumes a token left by an earlier `unpark` and returns immediately, so the wake
/// cannot be lost. A spurious wake costs one extra poll, which every future here
/// tolerates.
///
/// No `unsafe`: the waker is built from `Arc<W: Wake>`, which is the safe constructor.
pub fn block_on<F: Future>(future: F) -> F::Output {
    let waker = Arc::new(Unpark(thread::current())).into();
    let mut context = Context::from_waker(&waker);
    let mut future = pin!(future);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => return value,
            Poll::Pending => thread::park(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::block_on;
    use core::future::Future;
    use core::pin::Pin;
    use core::task::{Context, Poll};

    /// A future that pends exactly once, waking itself first — the shape a real
    /// transfer has, and the one the mock's spinning `block_on` would busy-loop on.
    struct PendsOnce {
        polled: bool,
    }

    impl Future for PendsOnce {
        type Output = u8;

        fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<u8> {
            if self.polled {
                return Poll::Ready(7);
            }
            self.polled = true;
            context.waker().wake_by_ref();
            Poll::Pending
        }
    }

    #[test]
    fn a_ready_future_returns_without_parking() {
        assert_eq!(block_on(core::future::ready(3_u8)), 3);
    }

    #[test]
    fn a_pending_future_is_woken_and_completed() {
        assert_eq!(block_on(PendsOnce { polled: false }), 7);
    }

    /// A future that pends once and wakes through an **owned** `Waker`.
    ///
    /// `Waker::wake` consumes the waker and reaches `Wake::wake`, where `wake_by_ref`
    /// reaches `Wake::wake_by_ref`. They are separate methods and a future may use
    /// either; mutation testing found `wake` unexercised.
    struct PendsOnceOwned {
        polled: bool,
    }

    impl Future for PendsOnceOwned {
        type Output = u8;

        #[expect(
            clippy::waker_clone_wake,
            reason = "the owned Waker::wake path is exactly what this test exists to reach; \
                      wake_by_ref, which the lint suggests, is the other test"
        )]
        fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<u8> {
            if self.polled {
                return Poll::Ready(9);
            }
            self.polled = true;
            context.waker().clone().wake();
            Poll::Pending
        }
    }

    #[test]
    fn an_owned_waker_wakes_the_parked_thread() {
        assert_eq!(block_on(PendsOnceOwned { polled: false }), 9);
    }

    /// A wake that lands before the park must not be lost, or the run deadlocks.
    #[test]
    fn a_wake_before_the_park_is_not_lost() {
        // `PendsOnce` wakes *during* its own poll, i.e. strictly before `park` is
        // reached, which is exactly the race. It completing at all is the assertion.
        assert_eq!(block_on(async { PendsOnce { polled: false }.await + 1 }), 8);
    }
}
