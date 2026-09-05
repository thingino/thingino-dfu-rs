//! Raw TDFU frames, back to back. The CLI and Android speak this.

use tdfu_proto::Command;

use super::error::DaemonError;
use super::wire::{Deadlines, Filled, Wire};

/// A plain TCP connection carrying TDFU frames.
#[derive(Debug)]
pub struct RawConn {
    wire: Wire,
    /// Which command is being served, or `None` between them.
    ///
    /// **There is no other per-connection state anywhere in this crate**, and that is
    /// deliberate. An earlier implementation's daemon sat at `writing` for
    /// the life of the process after a client hung up mid-write, because the state was a
    /// process-global flag some path forgot to clear, the C's shape, where
    /// `g_log_client_fd` is a global (`dfu-remote/main.c:68`) assigned at twelve sites:
    /// five sets (`:422`, `:515`, `:570`, `:658`, `:977`) and **seven clears by hand**
    /// (`:427`, `:520`, `:526`, `:582`, `:663`, `:895`, `:980`). This lives inside the
    /// connection, so dropping the connection drops it.
    pub(super) current: Option<Command>,
}

impl RawConn {
    /// Wrap an established stream.
    pub(super) const fn new(wire: Wire) -> Self {
        Self { wire, current: None }
    }

    /// Who is on the other end.
    pub(super) fn peer(&self) -> Option<core::net::SocketAddr> {
        self.wire.peer()
    }

    /// The deadlines in force.
    pub(super) const fn timeouts(&self) -> super::Timeouts {
        self.wire.timeouts()
    }

    /// Fill `buf`, or say where the peer stopped.
    pub(super) async fn read_exact(
        &mut self,
        buf: &mut [u8],
        deadlines: Deadlines,
        doing: &'static str,
    ) -> Result<Filled, DaemonError> {
        self.wire.read_exact(buf, deadlines, doing).await
    }

    /// Write `parts` end to end.
    pub(super) async fn send_message(&mut self, parts: &[&[u8]]) -> Result<(), DaemonError> {
        for part in parts {
            if !part.is_empty() {
                self.wire.write_all(part).await?;
            }
        }
        Ok(())
    }
}
