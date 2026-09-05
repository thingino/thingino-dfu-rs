//! Driving one operation's future to completion on the calling thread.
//!
//! A native method is invoked from one of the app's background worker threads (never the
//! UI thread - `DfuActivity` dispatches on `Dispatchers.IO`), so blocking that thread for
//! the length of the operation is exactly what is wanted. The
//! operations are `async` and `?Send` by design, with no `Send` bound; on Android their only
//! suspension points are `nusb` control transfers, woken from `nusb`'s own event loop,
//! and [`BlockingClock`](tdfu_core::clock::BlockingClock)'s `std::thread::sleep`.
//!
//! This is `tdfu-cli`'s `runtime::block_on` (which explains at length why not a spin
//! loop and why not `tokio`); the two are the same twenty lines because the reasoning is
//! the same and neither crate should depend on the other for it.

use core::future::Future;
use core::pin::pin;
use core::task::{Context, Poll};
use std::sync::Arc;
use std::task::Wake;
use std::thread::{self, Thread};

/// Unparks the thread parked inside [`block_on`].
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
/// A wake that arrives between the poll and the park is not lost: `thread::park` consumes
/// a token an earlier `unpark` left and returns at once. A spurious wake costs one extra
/// poll. No `unsafe`: the waker is built from `Arc<W: Wake>`, the safe constructor.
pub(crate) fn block_on<F: Future>(future: F) -> F::Output {
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

    /// A future that pends once, waking itself first - the shape a real transfer has, and
    /// the one a spinning executor would busy-loop on.
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
        // And the wake that lands during the poll, strictly before the park, is not lost.
        assert_eq!(block_on(async { PendsOnce { polled: false }.await + 1 }), 8);
    }

    /// A future that pends once and wakes through an **owned** `Waker`.
    ///
    /// `Waker::wake` consumes the waker and reaches `Wake::wake`; `wake_by_ref` reaches
    /// `Wake::wake_by_ref`. They are separate methods a future may use either of, so both
    /// need a test - the by-ref path above, the owned path here.
    struct PendsOnceOwned {
        polled: bool,
    }

    impl Future for PendsOnceOwned {
        type Output = u8;

        #[expect(
            clippy::waker_clone_wake,
            reason = "the owned Waker::wake path is exactly what this test reaches; wake_by_ref is the other test"
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
}
