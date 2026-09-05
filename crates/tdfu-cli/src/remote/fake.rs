//! A daemon that speaks `tdfu-proto` on loopback, for the tests in this module.
//!
//! Without a live daemon or hardware, every remote path is driven
//! against a scripted server on a `TcpListener` bound to `127.0.0.1:0`. It is a **test
//! double for a wire protocol**, not for a device: it plays back frames a test wrote out
//! and records the bytes the client sent, so a test can assert on both halves of the
//! conversation.
//!
//! A defect in a test double is worse than a defect
//! in code, so this one deliberately does **not** know the protocol: it never builds a
//! reply from a request. Every reply is bytes the test named, which is what makes the
//! wrong-version, lost-sync and mid-transfer-drop cases writable at all.

use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use tdfu_proto::{HEADER_LEN, ProgressBody, Status};

/// One thing the fake daemon does when it is that step's turn.
#[derive(Debug, Clone)]
pub enum Step {
    /// A `RESP_LOG` frame carrying this text.
    Log(String),
    /// A `RESP_PROGRESS` frame.
    Progress {
        /// 0-100.
        percent: u8,
        /// `Phase::wire_byte`.
        stage: u8,
        /// What is happening, in words.
        message: String,
    },
    /// A final `RESP_OK` with this payload.
    Ok(Vec<u8>),
    /// A final `RESP_ERROR` with this message.
    Fail(String),
    /// A header with an arbitrary status byte and announced length, and no payload —
    /// the way an oversize or a streamed answer is started.
    Header {
        /// The status byte, unvalidated.
        status: u8,
        /// What the header announces, which need not be what follows.
        len: u32,
    },
    /// Exactly these bytes, with no framing of any kind.
    Raw(Vec<u8>),
    /// Say nothing at all for this long, then carry on with the next step.
    ///
    /// **The one thing this double could not express**: a daemon that is slow, as
    /// opposed to one that is wrong or dead. Without it the client's 30 s first-answer
    /// deadline was reachable by no test, and deleting the whole `set_read_timeout` call
    /// left the suite green.
    ///
    /// It costs real wall-clock time in the test that uses it, so it is used with
    /// milliseconds and an injected deadline, never with the shipped one.
    Pause(Duration),
    /// Close the connection here, mid-whatever.
    Close,
}

/// What the client actually sent.
#[derive(Debug, Default)]
pub struct Transcript {
    /// The token from the handshake, if one was expected.
    pub token: Option<Vec<u8>>,
    /// Every request: the command byte and its payload, in order.
    pub requests: Vec<(u8, Vec<u8>)>,
    /// Anything the server could not do. Empty is the happy path.
    pub trouble: Vec<String>,
}

/// A scripted daemon on loopback.
#[derive(Debug)]
pub struct FakeDaemon {
    port: u16,
    handle: Option<JoinHandle<Transcript>>,
}

impl FakeDaemon {
    /// Start a daemon that answers each request with one `Vec<Step>`, in order.
    ///
    /// With `expect_token`, the first script entry answers the token handshake and
    /// the rest answer commands.
    ///
    /// # Errors
    /// Whatever binding loopback raises.
    pub fn start(expect_token: bool, script: Vec<Vec<Step>>) -> std::io::Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        let port = listener.local_addr()?.port();
        let handle = std::thread::spawn(move || serve(&listener, expect_token, script));
        Ok(Self {
            port,
            handle: Some(handle),
        })
    }

    /// The port it is listening on.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// Wait for the script to finish and hand back what the client sent, **failing if the
    /// fake itself gave up**.
    ///
    /// [`Transcript::trouble`] exists so that a double which could not do its job is not
    /// mistaken for a client that behaved; it was read by two of forty-four call sites,
    /// so `no client connected within 2s`, `request magic was …` and `writing a reply: …`
    /// were invisible to the rest: a defect in a double silently
    /// removes coverage, one layer up. Checking it here means every caller checks it.
    ///
    /// [`transcript_raw`](FakeDaemon::transcript_raw) is for the tests that want to
    /// inspect trouble rather than be stopped by it.
    ///
    /// # Errors
    /// If the server thread panicked, which is a bug in the fake rather than in the code
    /// under test, or if it recorded any trouble.
    pub fn transcript(self) -> Result<Transcript, Box<dyn std::error::Error>> {
        let transcript = self.transcript_raw()?;
        if !transcript.trouble.is_empty() {
            return Err(format!("the fake daemon could not play its script: {:?}", transcript.trouble).into());
        }
        Ok(transcript)
    }

    /// The transcript with its [`trouble`](Transcript::trouble) unchecked.
    ///
    /// For a test whose *subject* is what the fake could not do, and for one whose client
    /// deliberately walks away mid-reply. Everything else wants
    /// [`transcript`](FakeDaemon::transcript).
    ///
    /// # Errors
    /// If the server thread panicked.
    pub fn transcript_raw(mut self) -> Result<Transcript, Box<dyn std::error::Error>> {
        let handle = self.handle.take().ok_or("the fake daemon was already joined")?;
        handle.join().map_err(|_| "the fake daemon panicked".into())
    }
}

/// A port with nothing behind it: bound to learn the number, then released.
///
/// Inherently a small race — another process may take the port between the drop and the
/// connect — but it is the only way to get a port that is certainly free *and* certainly
/// unserved, and a stolen port would make the test fail loudly rather than silently pass.
///
/// # Errors
/// Whatever binding loopback raises.
pub fn closed_port() -> std::io::Result<u16> {
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    let port = listener.local_addr()?.port();
    drop(listener);
    Ok(port)
}

/// How long the fake waits for a client that may never come.
///
/// **This deadline is the difference between a failed test and a hung one**, and it was
/// found by mutation testing: with a blocking `accept`, seven mutants that stop the client
/// connecting or sending — `run -> Ok(())`, `send -> Ok(())`, `Address::port -> 0` —
/// left the server thread parked for ever and were reported as *timeouts* rather than as
/// the caught mutants they are. A double that hangs where it should fail is the same
/// class of defect: it silently removes coverage.
///
/// Two seconds is three orders of magnitude more than a loopback connect or a first
/// request needs, and short enough that a whole suite of tests all waiting it out still
/// finishes inside `cargo mutants`' 20 s timeout — which is what makes a mutation like
/// `Session::send -> Ok(())` a *caught* mutant rather than a timed-out one.
const PATIENCE: Duration = Duration::from_secs(2);

/// Accept one client and play the script at it.
fn serve(listener: &TcpListener, expect_token: bool, script: Vec<Vec<Step>>) -> Transcript {
    let mut transcript = Transcript::default();
    let mut stream = match accept_one(listener) {
        Ok(stream) => stream,
        Err(trouble) => {
            transcript.trouble.push(trouble);
            return transcript;
        }
    };
    // A client that goes quiet must not wedge the test suite: every read here is bounded,
    // and the thread ends with a note in `trouble` rather than hanging.
    let _ignored = stream.set_read_timeout(Some(PATIENCE));

    let mut steps = script.into_iter();
    if expect_token {
        match read_handshake(&mut stream) {
            Ok(token) => transcript.token = Some(token),
            Err(trouble) => {
                transcript.trouble.push(trouble);
                return transcript;
            }
        }
        let Some(reply) = steps.next() else {
            transcript.trouble.push("no script entry for the handshake".to_owned());
            return transcript;
        };
        if !play(&mut stream, &reply, &mut transcript) {
            return transcript;
        }
    }

    for reply in steps {
        match read_request(&mut stream) {
            Ok(Some(request)) => transcript.requests.push(request),
            Ok(None) => return transcript,
            Err(trouble) => {
                transcript.trouble.push(trouble);
                return transcript;
            }
        }
        if !play(&mut stream, &reply, &mut transcript) {
            return transcript;
        }
    }
    transcript
}

/// Wait [`PATIENCE`] for one client, then give up and say so.
fn accept_one(listener: &TcpListener) -> Result<TcpStream, String> {
    if let Err(source) = listener.set_nonblocking(true) {
        return Err(format!("cannot poll the listener: {source}"));
    }
    let deadline = Instant::now() + PATIENCE;
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                if let Err(source) = stream.set_nonblocking(false) {
                    return Err(format!("cannot go back to blocking reads: {source}"));
                }
                return Ok(stream);
            }
            Err(source) if source.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(format!("no client connected within {PATIENCE:?}"));
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(source) => return Err(format!("accept failed: {source}")),
        }
    }
}

/// `[4 magic][1 version][1 len][token]`: the token handshake.
fn read_handshake(stream: &mut TcpStream) -> Result<Vec<u8>, String> {
    let mut head = [0_u8; 6];
    fill(stream, &mut head)?;
    if head[..4] != tdfu_proto::MAGIC.to_be_bytes() {
        return Err(format!("handshake magic was {:02X?}", &head[..4]));
    }
    if head[4] != tdfu_proto::VERSION {
        return Err(format!("handshake version was {}", head[4]));
    }
    let mut token = vec![0_u8; usize::from(head[5])];
    fill(stream, &mut token)?;
    Ok(token)
}

/// One request header and its payload; `None` when the client closed cleanly.
fn read_request(stream: &mut TcpStream) -> Result<Option<(u8, Vec<u8>)>, String> {
    let mut header = [0_u8; HEADER_LEN];
    match stream.read(&mut header) {
        Ok(0) => return Ok(None),
        Ok(got) if got < HEADER_LEN => fill(stream, &mut header[got..])?,
        Ok(_) => {}
        Err(source) => return Err(format!("reading a request header: {source}")),
    }
    if header[..4] != tdfu_proto::MAGIC.to_be_bytes() {
        return Err(format!("request magic was {:02X?}", &header[..4]));
    }
    let mut len = [0_u8; 4];
    len.copy_from_slice(&header[6..10]);
    let mut payload = vec![0_u8; u32::from_be_bytes(len) as usize];
    fill(stream, &mut payload)?;
    Ok(Some((header[5], payload)))
}

/// Play one reply. `false` means the connection is finished.
fn play(stream: &mut TcpStream, steps: &[Step], transcript: &mut Transcript) -> bool {
    for step in steps {
        let bytes = match step {
            Step::Log(text) => frame(Status::Log.wire_byte(), text.as_bytes()),
            Step::Progress {
                percent,
                stage,
                message,
            } => {
                let body = ProgressBody {
                    percent: *percent,
                    stage: *stage,
                    message: message.clone(),
                };
                match body.encode() {
                    Ok(encoded) => frame(Status::Progress.wire_byte(), &encoded),
                    Err(source) => {
                        transcript.trouble.push(format!("encoding a progress body: {source}"));
                        return false;
                    }
                }
            }
            Step::Ok(payload) => frame(Status::Ok.wire_byte(), payload),
            Step::Fail(message) => frame(Status::Error.wire_byte(), message.as_bytes()),
            Step::Header { status, len } => header_bytes(*status, *len).to_vec(),
            Step::Raw(bytes) => bytes.clone(),
            Step::Pause(how_long) => {
                std::thread::sleep(*how_long);
                continue;
            }
            Step::Close => return false,
        };
        if let Err(source) = stream.write_all(&bytes) {
            transcript.trouble.push(format!("writing a reply: {source}"));
            return false;
        }
    }
    let _ignored = stream.flush();
    true
}

/// A response header plus its payload.
fn frame(status: u8, payload: &[u8]) -> Vec<u8> {
    // A test double never sends more than a few hundred kilobytes, and a saturating
    // conversion keeps the fake free of the `unwrap` the workspace denies.
    let len = u32::try_from(payload.len()).unwrap_or(u32::MAX);
    let mut out = header_bytes(status, len).to_vec();
    out.extend_from_slice(payload);
    out
}

/// `[magic][version][status][len]`, built by hand so a test can spoil any field.
fn header_bytes(status: u8, len: u32) -> [u8; HEADER_LEN] {
    let mut out = [0_u8; HEADER_LEN];
    out[0..4].copy_from_slice(&tdfu_proto::MAGIC.to_be_bytes());
    out[4] = tdfu_proto::VERSION;
    out[5] = status;
    out[6..10].copy_from_slice(&len.to_be_bytes());
    out
}

/// Read exactly `buffer.len()` bytes or say why not.
fn fill(stream: &mut TcpStream, buffer: &mut [u8]) -> Result<(), String> {
    let mut got = 0;
    while got < buffer.len() {
        match stream.read(&mut buffer[got..]) {
            Ok(0) => return Err(format!("the client closed after {got} of {} bytes", buffer.len())),
            Ok(read) => got += read,
            Err(source) => return Err(format!("reading from the client: {source}")),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{FakeDaemon, Step};
    use std::io::Write as _;
    use std::net::TcpStream;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// **The double's own pin.** A fake that could not play its script says so
    /// through [`FakeDaemon::transcript`], and only `transcript_raw` lets it past.
    ///
    /// A defect in a double silently removes coverage. `trouble` was
    /// read by two of forty-four call sites, so a fake that never saw a client, or read a
    /// request that was not one, looked exactly like a client that behaved. This is the
    /// test that would have failed then and passes now.
    #[test]
    fn a_fake_that_could_not_play_its_script_fails_the_transcript() -> TestResult {
        // Ten bytes that are not a request header: the fake reports the magic it saw.
        let daemon = FakeDaemon::start(false, vec![vec![Step::Ok(b"OK".to_vec())]])?;
        let mut client = TcpStream::connect(("127.0.0.1", daemon.port()))?;
        client.write_all(b"NOT-A-HDR!")?;
        client.flush()?;
        drop(client);

        let refusal = daemon.transcript().err().ok_or("junk on the wire is trouble")?;
        let message = refusal.to_string();
        assert!(message.contains("could not play its script"), "{message}");
        assert!(message.contains("request magic was"), "{message}");

        // And the raw form hands the same note back instead of refusing.
        let daemon = FakeDaemon::start(false, vec![vec![Step::Ok(b"OK".to_vec())]])?;
        let mut client = TcpStream::connect(("127.0.0.1", daemon.port()))?;
        client.write_all(b"NOT-A-HDR!")?;
        client.flush()?;
        drop(client);
        let transcript = daemon.transcript_raw()?;
        assert_eq!(transcript.trouble.len(), 1, "{:?}", transcript.trouble);
        assert!(transcript.requests.is_empty(), "{:?}", transcript.requests);
        Ok(())
    }
}
