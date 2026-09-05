//! `dfu-remote`, the daemon.
//!
//! One TCP port carrying three transports, sniffed by the first byte: `'G'` a WebSocket
//! upgrade, `'P'` an HTTP POST, `'O'` a CORS preflight, anything else a raw TDFU stream
//! on one port. The browser flasher uses the HTTP path.
//!
//! Four things an earlier implementation of this daemon got wrong, listed here because
//! they are properties of the *design* and not of any one function:
//!
//! * **No read or idle timeout anywhere**, with a listen backlog of 1 and one client at
//!   a time on `INADDR_ANY`: one connection that sends nothing wedged every other
//!   client. That is a C defect, and it is fixed here.
//! * **A dropped connection mid-operation left the state stuck at `writing`** for the
//!   life of the process.
//! * **The `READ` staging file was created 0664** where the C's `mkstemp` creates 0600.
//!   It holds a whole flash image, Wi-Fi credentials and keys included, in a shared
//!   directory. A place the C was safer than us.
//! * **Auth failures were logged nowhere**, not even under `--debug`, so token
//!   brute-forcing over the browser transport left no trace.
//!
//! And one about argument parsing: `-p abc` became port 0 and the daemon bound an
//! ephemeral port while printing `listening on port 0`; `-p 70000` silently became
//! 4464; unknown arguments were ignored in silence, and a test pinned all of it as
//! correct.

//! The map: `transport/` and `auth` are the wire (framing, the three transports, the
//! token handshake); `commands/` and `errors` are the eight commands and the
//! `Error` → `ERROR_STRINGS` mapper; `serve` is the accept loop that joins the two;
//! `listen`, `clock` and `logging` are what the binary needs and the library can test.

pub mod auth;
pub mod clock;
pub mod commands;
pub mod errors;
pub mod listen;
pub mod logging;
pub mod serve;
pub mod transport;

pub use clock::TokioClock;

pub use tdfu_core::{Error, ops};
pub use tdfu_proto::{Command, DEFAULT_PORT, ERROR_STRINGS, Request, Status};
