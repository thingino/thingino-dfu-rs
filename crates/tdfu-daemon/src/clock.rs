//! The daemon's clock: [`Sleeper`] on tokio's timer.
//!
//! `tdfu_core::clock::BlockingClock` parks the thread, which is right for the CLI and
//! wrong here: the accept loop races every wait against a shutdown signal, and a
//! parked thread notices SIGTERM only when the wait ends. The re-enumeration
//! window is 120 of those waits, 250 ms apart.

use std::time::Duration;

use tdfu_core::clock::Sleeper;

/// [`Sleeper`] that yields to the runtime.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TokioClock;

impl Sleeper for TokioClock {
    async fn sleep(&self, duration: Duration) {
        tokio::time::sleep(duration).await;
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use tdfu_core::clock::Sleeper;

    use super::TokioClock;

    #[tokio::test]
    async fn sleeps_for_at_least_the_duration_asked() {
        let started = Instant::now();
        TokioClock.sleep(Duration::from_millis(20)).await;
        assert!(started.elapsed() >= Duration::from_millis(20));
    }

    /// The point of the type: another future runs *during* the wait, not after it.
    /// `join!` polls the sleeper first, so a clock that parked the thread would hand
    /// the other future its turn only once the 50 ms were spent.
    #[tokio::test]
    async fn yields_to_the_runtime_while_waiting() {
        let started = Instant::now();
        let sleeper = TokioClock.sleep(Duration::from_millis(50));
        let other = async { started.elapsed() };
        let ((), when) = tokio::join!(sleeper, other);
        assert!(
            when < Duration::from_millis(50),
            "the other future ran only after the wait: {when:?}"
        );
    }
}
