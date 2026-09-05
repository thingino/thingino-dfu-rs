//! The transport layer against real sockets on loopback.
//!
//! Everything here runs over an in-process `TcpListener` on `127.0.0.1:0`. No hardware,
//! no external network, no fixed port.
//!
//! The server loop in [`serve`] is deliberately the shape `dfu-remote`'s `main.rs` wants:
//! accept, `Conn::accept_with`, then `next_request` until it says `Ok(None)`, honouring
//! `one_shot`. Testing through that loop is what makes the two properties provable, that
//! a silent peer cannot hold the listener and that a peer dropping mid-request leaves
//! nothing stuck behind it, because both are properties of the loop and not of one
//! function.

use core::net::SocketAddr;
use core::time::Duration;

use tdfu_daemon::auth::Auth;
use tdfu_daemon::transport::{Conn, Origins, Timeouts};
use tdfu_proto::{Command, HEADER_LEN, MAGIC, MAX_PAYLOAD, ProgressBody, Status, VERSION};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

type TestResult = Result<(), Box<dyn core::error::Error>>;

/// The shipped origin allow list, as a borrow that outlives the futures it is passed to.
/// `Origins` owns a `Vec`, so `&Origins::SHIPPED` is a temporary rather than a promoted
/// constant and every call site would otherwise need a local of its own.
fn shipped() -> &'static Origins {
    static SHIPPED: std::sync::OnceLock<Origins> = std::sync::OnceLock::new();
    SHIPPED.get_or_init(|| Origins::SHIPPED)
}

/// Short enough that a wedge shows up as a test that finishes, not one that hangs.
fn brisk() -> Timeouts {
    Timeouts {
        handshake: Some(Duration::from_millis(300)),
        read: Some(Duration::from_millis(300)),
        idle: Some(Duration::from_millis(300)),
    }
}

/// What the server saw. The assertions are on this, so a test can tell "refused" from
/// "hung up" from "served".
#[derive(Debug, Clone, PartialEq, Eq)]
enum Event {
    /// `Conn::accept` produced a connection on this transport.
    Accepted(String),
    /// `Conn::accept` said there was nothing to serve (a preflight, or a peer that closed).
    Nothing,
    /// A dispatchable request.
    Request(Command, Vec<u8>),
    /// `next_request` said the client closed cleanly.
    Closed,
    /// Anything that ended the connection, by its `Display`.
    Failed(String),
}

impl Event {
    fn failure(&self) -> Option<&str> {
        match self {
            Self::Failed(text) => Some(text),
            _ => None,
        }
    }
}

/// How the fake dispatcher answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reply {
    /// One OK frame.
    Plain,
    /// A log line and a progress frame first — the attach rule decides whether
    /// they actually go out.
    Chatty,
}

/// Bind, then serve exactly `connections` clients and return everything that happened.
fn serve(auth: Auth, timeouts: Timeouts, connections: usize, reply: Reply) -> (SocketAddr, JoinHandle<Vec<Event>>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").and_then(|listener| {
        listener.set_nonblocking(true)?;
        Ok(listener)
    });
    let listener = match listener {
        Ok(listener) => listener,
        Err(error) => {
            let handle = tokio::spawn(async move { vec![Event::Failed(error.to_string())] });
            return (
                "127.0.0.1:0".parse().unwrap_or(SocketAddr::from(([127, 0, 0, 1], 0))),
                handle,
            );
        }
    };
    let address = listener
        .local_addr()
        .unwrap_or_else(|_| SocketAddr::from(([127, 0, 0, 1], 0)));

    let handle = tokio::spawn(async move {
        let mut events = Vec::new();
        let listener = match TcpListener::from_std(listener) {
            Ok(listener) => listener,
            Err(error) => return vec![Event::Failed(error.to_string())],
        };
        for _ in 0..connections {
            let stream = match listener.accept().await {
                Ok((stream, _)) => stream,
                Err(error) => {
                    events.push(Event::Failed(error.to_string()));
                    break;
                }
            };
            match Conn::accept_with(stream, &auth, timeouts, shipped()).await {
                Err(error) => events.push(Event::Failed(error.to_string())),
                Ok(None) => events.push(Event::Nothing),
                Ok(Some(mut conn)) => {
                    events.push(Event::Accepted(conn.transport().to_string()));
                    loop {
                        match conn.next_request().await {
                            Ok(None) => {
                                events.push(Event::Closed);
                                break;
                            }
                            Ok(Some((command, payload))) => {
                                events.push(Event::Request(command, payload));
                                if reply == Reply::Chatty {
                                    let _log = conn.log("staging the loader").await;
                                    let _bar = conn
                                        .progress(&ProgressBody {
                                            percent: 50,
                                            stage: 3,
                                            message: "download".to_owned(),
                                        })
                                        .await;
                                }
                                if let Err(error) = conn.respond(Status::Ok, b"OK").await {
                                    events.push(Event::Failed(error.to_string()));
                                    break;
                                }
                            }
                            Err(error) => {
                                events.push(Event::Failed(error.to_string()));
                                break;
                            }
                        }
                        if conn.one_shot() {
                            break;
                        }
                    }
                }
            }
        }
        events
    });
    (address, handle)
}

/// A request frame, with the command byte and length under the caller's control so a test
/// can build one the codec would refuse.
fn frame(command: u8, payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(HEADER_LEN + payload.len());
    bytes.extend_from_slice(&MAGIC.to_be_bytes());
    bytes.push(VERSION);
    bytes.push(command);
    bytes.extend_from_slice(&u32::try_from(payload.len()).unwrap_or(u32::MAX).to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

/// A header that announces a length it will not send.
fn header_claiming(command: u8, payload_len: u32) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(HEADER_LEN);
    bytes.extend_from_slice(&MAGIC.to_be_bytes());
    bytes.push(VERSION);
    bytes.push(command);
    bytes.extend_from_slice(&payload_len.to_be_bytes());
    bytes
}

/// How long any client-side read here may block.
///
/// Every read the test client makes carries this. It is not about the daemon's deadlines:
/// it is so a mutation that stops the daemon answering makes a test **fail** instead of
/// hang. An audit found three descriptor-walk mutants that hung for want of exactly this,
/// and two more did here.
const CLIENT_DEADLINE: Duration = Duration::from_secs(10);

/// Read one response frame from a raw stream.
async fn response(stream: &mut TcpStream) -> Result<(u8, Vec<u8>), Box<dyn core::error::Error>> {
    let mut header = [0_u8; HEADER_LEN];
    tokio::time::timeout(CLIENT_DEADLINE, stream.read_exact(&mut header)).await??;
    let magic = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
    assert_eq!(magic, MAGIC, "the response is not a TDFU frame");
    assert_eq!(header[4], VERSION);
    let len = u32::from_be_bytes([header[6], header[7], header[8], header[9]]) as usize;
    let mut payload = vec![0_u8; len];
    tokio::time::timeout(CLIENT_DEADLINE, stream.read_exact(&mut payload)).await??;
    Ok((header[5], payload))
}

/// The bytes still to come, until the peer closes.
async fn drain(stream: &mut TcpStream) -> Result<Vec<u8>, Box<dyn core::error::Error>> {
    let mut rest = Vec::new();
    tokio::time::timeout(CLIENT_DEADLINE, stream.read_to_end(&mut rest)).await??;
    Ok(rest)
}

// ---------------------------------------------------------------------------
// The four first-byte paths
// ---------------------------------------------------------------------------

/// `dfu-remote/main.c:1136-1154`. All four branches, each reaching the
/// transport it names.
#[tokio::test]
async fn rpc_transport_sniff() -> TestResult {
    // 'T' (the magic's first byte) and anything else: raw.
    let (address, server) = serve(Auth::open(), brisk(), 1, Reply::Plain);
    let mut client = TcpStream::connect(address).await?;
    client.write_all(&frame(Command::Discover.wire_byte(), b"")).await?;
    let (status, payload) = response(&mut client).await?;
    assert_eq!((status, payload.as_slice()), (Status::Ok.wire_byte(), &b"OK"[..]));
    drop(client);
    let events = server.await?;
    assert_eq!(events.first(), Some(&Event::Accepted("raw".to_owned())));

    // 'G': the WebSocket upgrade.
    let (address, server) = serve(Auth::open(), brisk(), 1, Reply::Plain);
    let mut client = TcpStream::connect(address).await?;
    let mut ws = WsClient::upgrade(&mut client).await?;
    ws.send(&mut client, 0x2, &frame(Command::Status.wire_byte(), b""))
        .await?;
    let (status, payload) = ws.response(&mut client).await?;
    assert_eq!((status, payload.as_slice()), (Status::Ok.wire_byte(), &b"OK"[..]));
    drop(client);
    let events = server.await?;
    assert_eq!(events.first(), Some(&Event::Accepted("websocket".to_owned())));

    // 'P': the HTTP POST.
    let (address, server) = serve(Auth::open(), brisk(), 1, Reply::Plain);
    let mut client = TcpStream::connect(address).await?;
    post(&mut client, &frame(Command::Diag.wire_byte(), &[0]), None).await?;
    let reply = String::from_utf8_lossy(&drain(&mut client).await?).into_owned();
    assert!(reply.starts_with("HTTP/1.1 200 OK\r\n"), "{reply}");
    let events = server.await?;
    assert_eq!(events.first(), Some(&Event::Accepted("http".to_owned())));

    // 'O': the preflight, which produces no connection to dispatch on. From the origin
    // the flasher is served from, because a preflight from anywhere else is refused.
    let (address, server) = serve(Auth::open(), brisk(), 1, Reply::Plain);
    let mut client = TcpStream::connect(address).await?;
    client
        .write_all(b"OPTIONS / HTTP/1.1\r\nHost: h\r\nOrigin: https://webflash.thingino.com\r\n\r\n")
        .await?;
    let reply = String::from_utf8_lossy(&drain(&mut client).await?).into_owned();
    assert!(reply.starts_with("HTTP/1.1 200 OK\r\n"), "{reply}");
    assert_eq!(server.await?, vec![Event::Nothing]);
    Ok(())
}

/// **The seam's own entry point.** `Conn::accept(stream, auth)` is frozen,
/// and the commands compile against exactly that signature, but every other test here reaches
/// for `accept_with` to get a short deadline, so without this one nothing runs the
/// two-argument form at all. `cargo mutants` found that hole: replacing the whole body
/// with `Ok(None)` survived the suite.
#[tokio::test]
async fn conn_accept_serves_a_client_on_the_default_deadlines() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let auth = Auth::open();

    let mut client = TcpStream::connect(address).await?;
    let (stream, _) = listener.accept().await?;
    let accepted = Conn::accept(stream, &auth);
    let sent = async {
        client.write_all(&frame(Command::Discover.wire_byte(), b"")).await?;
        Ok::<(), std::io::Error>(())
    };
    let (accepted, sent) = tokio::join!(accepted, sent);
    sent?;

    let mut conn = accepted?.ok_or("Conn::accept produced nothing to serve")?;
    assert_eq!(
        conn.timeouts(),
        Timeouts::DEFAULT,
        "the two-argument form is the default-deadline form"
    );
    assert!(!conn.one_shot(), "a raw connection carries many commands");
    assert_eq!(conn.current(), None, "no command is in flight before the first read");

    let (command, payload) = conn.next_request().await?.ok_or("no request arrived")?;
    assert_eq!((command, payload.as_slice()), (Command::Discover, &b""[..]));
    assert_eq!(conn.current(), Some(Command::Discover));

    conn.respond(Status::Ok, b"OK").await?;
    assert_eq!(conn.current(), None, "responding clears the command in flight");

    let (status, payload) = response(&mut client).await?;
    assert_eq!((status, payload.as_slice()), (Status::Ok.wire_byte(), &b"OK"[..]));
    Ok(())
}

/// The accessors on the seam, on a real connection of each kind.
///
/// `transport()`, `one_shot()`, `peer()` and `logs_enabled_for()` are what a dispatcher
/// steers by, and every one of them was reachable only indirectly until `cargo mutants`
/// pointed out that `one_shot -> false` and `peer -> None` both survived the suite.
#[tokio::test]
async fn the_seam_accessors_answer_for_a_real_connection() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let auth = Auth::open();

    // Raw. The first byte has to be there for the sniff, so the frame goes
    // out before the accept — it sits in the socket buffer until it is read.
    let mut client = TcpStream::connect(address).await?;
    let client_address = client.local_addr()?;
    client.write_all(&frame(Command::Status.wire_byte(), b"")).await?;
    let (stream, _) = listener.accept().await?;
    let conn = Conn::accept_with(stream, &auth, brisk(), shipped())
        .await?
        .ok_or("no raw connection")?;
    assert_eq!(conn.transport().to_string(), "raw");
    assert!(!conn.one_shot(), "raw carries many commands");
    assert_eq!(
        conn.peer(),
        Some(client_address),
        "the peer is the client's own address"
    );
    for command in [Command::Bootstrap, Command::Write, Command::Read] {
        assert!(conn.logs_enabled_for(command), "raw {command:?}");
    }
    for command in [
        Command::Discover,
        Command::Status,
        Command::Cancel,
        Command::Diag,
        Command::Reboot,
    ] {
        assert!(!conn.logs_enabled_for(command), "raw {command:?}");
    }
    drop(conn);
    drop(client);

    // HTTP.
    let mut client = TcpStream::connect(address).await?;
    let client_address = client.local_addr()?;
    let (stream, _) = listener.accept().await?;
    let accepted = Conn::accept_with(stream, &auth, brisk(), shipped());
    let body = frame(Command::Status.wire_byte(), b"");
    let posted = post(&mut client, &body, None);
    let (accepted, posted) = tokio::join!(accepted, posted);
    posted?;
    let conn = accepted?.ok_or("no http connection")?;
    assert_eq!(conn.transport().to_string(), "http");
    assert!(conn.one_shot(), "exactly one command per POST");
    assert_eq!(conn.peer(), Some(client_address));
    for command in Command::ALL {
        assert!(
            conn.logs_enabled_for(command),
            "HTTP attaches for every command, including {command:?}"
        );
    }

    // WebSocket.
    let mut client = TcpStream::connect(address).await?;
    let client_address = client.local_addr()?;
    let (stream, _) = listener.accept().await?;
    let accepted = Conn::accept_with(stream, &auth, brisk(), shipped());
    let upgraded = WsClient::upgrade(&mut client);
    let (accepted, upgraded) = tokio::join!(accepted, upgraded);
    let _ws = upgraded?;
    let conn = accepted?.ok_or("no websocket connection")?;
    assert_eq!(conn.transport().to_string(), "websocket");
    assert!(!conn.one_shot());
    assert_eq!(conn.peer(), Some(client_address));
    assert!(conn.logs_enabled_for(Command::Write));
    assert!(!conn.logs_enabled_for(Command::Diag));
    Ok(())
}

/// **The encode-side cap, and the one command exempt from it.**
///
/// An audit asked for `exceeds_payload_cap` on the encode side too. The cap exempts
/// `CMD_READ`, whose OK payload is a whole flash, 256 MiB on the T40XP. Both halves are
/// checked, because a cap that also refuses `READ` breaks the largest operation the tool
/// has, and a cap that exempts everything is not a cap.
#[tokio::test]
async fn a_response_over_the_cap_is_refused_unless_it_is_a_read() -> TestResult {
    let oversize = vec![0_u8; MAX_PAYLOAD as usize + 1];

    // A non-READ command: refused, and nothing is written.
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let auth = Auth::open();

    let mut client = TcpStream::connect(address).await?;
    let (stream, _) = listener.accept().await?;
    let accepted = Conn::accept_with(stream, &auth, brisk(), shipped());
    let sent = async {
        client.write_all(&frame(Command::Status.wire_byte(), b"")).await?;
        Ok::<(), std::io::Error>(())
    };
    let (accepted, sent) = tokio::join!(accepted, sent);
    sent?;
    let mut conn = accepted?.ok_or("no connection")?;
    let _request = conn.next_request().await?.ok_or("no request")?;
    assert_eq!(conn.current(), Some(Command::Status));

    let refused = conn.respond(Status::Ok, &oversize).await;
    let message = match refused {
        Err(error) => error.to_string(),
        Ok(()) => "expected a refusal".to_owned(),
    };
    assert!(message.contains("over the 64 MiB cap"), "{message}");
    assert!(
        message.contains("Status"),
        "the command in flight is part of the fact: {message}"
    );
    assert!(message.contains("67108865"), "the length that did not fit: {message}");

    // Exactly the cap is fine for any command (`>` on both sides). Checked
    // without moving 64 MiB: the refusal happens before a byte is written, so a payload
    // that is *not* refused proves the predicate let it through.
    let at_cap = vec![0_u8; MAX_PAYLOAD as usize];
    let write = conn.respond(Status::Ok, &at_cap);
    // Under a deadline: a mutant that refuses this payload must FAIL the test, not hang
    // it. An audit recorded three mutants that hung for want of exactly this.
    let read = async {
        let mut sink = vec![0_u8; HEADER_LEN + MAX_PAYLOAD as usize];
        tokio::time::timeout(Duration::from_secs(20), client.read_exact(&mut sink)).await??;
        Ok::<usize, Box<dyn core::error::Error>>(sink.len())
    };
    let (written, read) = tokio::join!(write, read);
    written?;
    assert_eq!(read?, HEADER_LEN + MAX_PAYLOAD as usize, "exactly the cap went out");
    drop(client);
    Ok(())
}

/// The exemption's other half: with `CMD_READ` in flight the same oversize payload is
/// **not** refused. Kept apart from the test above so the 64 MiB that actually crosses the
/// socket is paid once.
///
/// **The read deadline here is deliberately far shorter than the transfer takes.**
/// `Timeouts::read` is a *no-progress* bound, not a bound on the whole write, and a
/// `CMD_READ` answer is a whole flash — 256 MiB on a T40XP. A single deadline over the
/// entire write would abort exactly the operation the cap exempts. It was
/// written that way first, and it failed only when the machine was busy.
#[tokio::test]
async fn a_read_may_answer_past_the_cap() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let auth = Auth::open();
    let impatient = Timeouts {
        handshake: Some(Duration::from_millis(500)),
        read: Some(Duration::from_millis(50)),
        idle: Some(Duration::from_millis(500)),
    };

    let mut client = TcpStream::connect(address).await?;
    let (stream, _) = listener.accept().await?;
    let accepted = Conn::accept_with(stream, &auth, impatient, shipped());
    let sent = async {
        client.write_all(&frame(Command::Read.wire_byte(), b"")).await?;
        Ok::<(), std::io::Error>(())
    };
    let (accepted, sent) = tokio::join!(accepted, sent);
    sent?;
    let mut conn = accepted?.ok_or("no connection")?;
    let _request = conn.next_request().await?.ok_or("no request")?;
    assert_eq!(conn.current(), Some(Command::Read));

    // One byte past the cap: a NAND alt 0 is 256 MiB, four times this.
    let oversize = MAX_PAYLOAD as usize + 1;
    let payload = vec![0_u8; oversize];
    let write = conn.respond(Status::Ok, &payload);
    let read = async {
        let mut sink = vec![0_u8; HEADER_LEN + oversize];
        tokio::time::timeout(Duration::from_secs(20), client.read_exact(&mut sink)).await??;
        Ok::<Vec<u8>, Box<dyn core::error::Error>>(sink)
    };
    let (written, read) = tokio::join!(write, read);
    written?;
    let sink = read?;
    let announced = u32::from_be_bytes([sink[6], sink[7], sink[8], sink[9]]);
    assert_eq!(
        announced as usize, oversize,
        "the header announces the whole thing, past the cap"
    );
    Ok(())
}

/// A listener whose accepted sockets carry a tiny send buffer, so a modest payload cannot
/// all sit in the pipe and the daemon's write blocks on the peer draining it.
fn tiny_send_listener() -> Result<TcpListener, Box<dyn core::error::Error + Send + Sync>> {
    let socket = tokio::net::TcpSocket::new_v4()?;
    socket.set_send_buffer_size(2 * 1024)?;
    socket.bind("127.0.0.1:0".parse()?)?;
    Ok(socket.listen(16)?)
}

/// A client with a tiny receive buffer, the other half of forcing the write to block: with
/// both small, only a few kilobytes are ever in flight.
async fn tiny_recv_client(address: SocketAddr) -> Result<TcpStream, Box<dyn core::error::Error + Send + Sync>> {
    let socket = tokio::net::TcpSocket::new_v4()?;
    socket.set_recv_buffer_size(2 * 1024)?;
    Ok(socket.connect(address).await?)
}

/// **A slow-drain peer cannot hold the DFU interface open for ever.** A client that drains
/// its response a few kilobytes at a time, each read just before the no-progress deadline,
/// keeps that per-write deadline from ever firing, so without a bound on the whole write
/// it holds the daemon, the claimed interface and the part-written device for as long as
/// it likes. The whole-call budget is what ends it.
///
/// The socket buffers are shrunk to a few kilobytes so the write blocks on the peer, and
/// the peer drains at about 4 KiB/s: fast enough (a read every half second against a
/// 1.5 s deadline) that the per-write deadline never fires, and far too slow to finish the
/// 128 KiB before the whole-call budget (3.5 s) does. On the *base* the daemon has no
/// whole-call budget and writes for the full drain (about half a minute), which the
/// test-side bound turns into a failure rather than a hang; on the fix it gives up at the
/// budget.
#[tokio::test]
async fn a_slow_drain_cannot_hold_the_response_open_for_ever() -> Result<(), Box<dyn core::error::Error + Send + Sync>>
{
    let floor = Duration::from_millis(1500);
    let timeouts = Timeouts {
        handshake: Some(floor),
        read: Some(floor),
        idle: Some(floor),
    };
    let payload_len = 128 * 1024;
    // floor + ceil(128 KiB / 64 KiB) s.
    let budget = floor + Duration::from_secs(2);
    // Longer than the fix takes (the budget) and far shorter than the whole drain, so the
    // base (which writes for the whole drain) trips it and fails rather than hangs.
    let test_bound = Duration::from_secs(8);

    let listener = tiny_send_listener()?;
    let address = listener.local_addr()?;
    let auth = Auth::open();

    // The drain client: ask for a READ, then read whatever is in the pipe every half
    // second, enough to reopen the receive window (so the write keeps making progress and
    // the per-write deadline never fires), but only a few kilobytes a second.
    let drip = tokio::spawn(async move {
        let mut client = tiny_recv_client(address).await?;
        client.write_all(&frame(Command::Read.wire_byte(), b"")).await?;
        let mut chunk = vec![0_u8; 16 * 1024];
        loop {
            match client.read(&mut chunk).await {
                Ok(0) | Err(_) => break, // the daemon closed the connection
                Ok(_) => {}
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        Ok::<(), Box<dyn core::error::Error + Send + Sync>>(())
    });

    let (stream, _) = listener.accept().await?;
    let mut conn = Conn::accept_with(stream, &auth, timeouts, shipped())
        .await?
        .ok_or("no connection")?;
    let _request = conn.next_request().await?.ok_or("no request")?;
    assert_eq!(conn.current(), Some(Command::Read));

    let payload = vec![0_u8; payload_len];
    let started = std::time::Instant::now();
    let outcome = tokio::time::timeout(test_bound, conn.respond(Status::Ok, &payload)).await;
    let elapsed = started.elapsed();
    drip.abort();
    let _ = drip.await;

    match outcome {
        Err(deadline) => {
            return Err(format!(
                "the daemon never gave up on a slow-drain peer within {test_bound:?} ({deadline}): the whole-call write budget is missing"
            )
            .into());
        }
        Ok(Ok(())) => {
            return Err(format!(
                "the whole {payload_len}-byte payload drained in {elapsed:?}; the buffers were too large or the drain too fast to test a stall"
            )
            .into());
        }
        Ok(Err(error)) => {
            let message = error.to_string();
            assert!(message.contains("response"), "{message}");
            // It lasted past the per-write no-progress deadline (the drain keeps that one
            // alive), so only the whole-call budget could have ended the write, and it did
            // so at about the budget rather than long after.
            assert!(
                elapsed > floor && elapsed < budget + Duration::from_secs(3),
                "gave up, but not at the whole-call budget ({budget:?}): {elapsed:?}"
            );
        }
    }
    Ok(())
}

/// A client that drains at full speed is unaffected: the same small buffers and the same
/// payload go through whole, so the budget bounds only the peer that will not keep up.
#[tokio::test]
async fn a_normally_draining_client_is_not_cut_off() -> Result<(), Box<dyn core::error::Error + Send + Sync>> {
    let timeouts = Timeouts {
        handshake: Some(Duration::from_millis(500)),
        read: Some(Duration::from_millis(500)),
        idle: Some(Duration::from_millis(500)),
    };
    let payload_len = 128 * 1024;

    let listener = tiny_send_listener()?;
    let address = listener.local_addr()?;
    let auth = Auth::open();

    let reader = tokio::spawn(async move {
        let mut client = tiny_recv_client(address).await?;
        client.write_all(&frame(Command::Read.wire_byte(), b"")).await?;
        let mut sink = vec![0_u8; HEADER_LEN + payload_len];
        tokio::time::timeout(CLIENT_DEADLINE, client.read_exact(&mut sink)).await??;
        Ok::<Vec<u8>, Box<dyn core::error::Error + Send + Sync>>(sink)
    });

    let (stream, _) = listener.accept().await?;
    let mut conn = Conn::accept_with(stream, &auth, timeouts, shipped())
        .await?
        .ok_or("no connection")?;
    let _request = conn.next_request().await?.ok_or("no request")?;
    let payload = vec![0xC7_u8; payload_len];
    conn.respond(Status::Ok, &payload).await?;
    drop(conn);

    let sink = reader.await??;
    let announced = u32::from_be_bytes([sink[6], sink[7], sink[8], sink[9]]) as usize;
    assert_eq!(announced, payload_len, "the whole payload was announced");
    assert_eq!(&sink[HEADER_LEN..], &payload[..], "and every byte arrived");
    Ok(())
}

/// The preflight, `dfu-remote/ws.c:232-239`: every header, on the wire.
#[tokio::test]
async fn rpc_preflight_headers() -> TestResult {
    let (address, server) = serve(Auth::open(), brisk(), 1, Reply::Plain);
    let mut client = TcpStream::connect(address).await?;
    client.write_all(b"OPTIONS / HTTP/1.1\r\nHost: h\r\n\r\n").await?;
    let reply = String::from_utf8_lossy(&drain(&mut client).await?).into_owned();
    for header in [
        "Access-Control-Allow-Origin: *",
        "Access-Control-Allow-Methods: GET, POST, OPTIONS",
        "Access-Control-Allow-Headers: Content-Type, X-Auth-Token",
        "Access-Control-Allow-Private-Network: true",
        "Access-Control-Max-Age: 600",
        "Content-Length: 0",
    ] {
        assert!(reply.contains(header), "preflight is missing {header:?}:\n{reply}");
    }
    let _events = server.await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// A silent peer must not hold the listener
// ---------------------------------------------------------------------------

/// A client that connects and sends nothing must hit the deadline, and the
/// listener must go straight on to the next client.
///
/// The C has no timeout anywhere in `dfu-remote/` and pairs that with `listen(fd, 1)`
/// (`main.c:1108`) and one client served to completion (`:1119-1156`), so this test would
/// never return against it.
#[tokio::test]
async fn a_silent_client_times_out_and_does_not_wedge_the_listener() -> TestResult {
    let (address, server) = serve(Auth::open(), brisk(), 2, Reply::Plain);

    // The peer that says nothing. Held open, so the server cannot mistake it for a close.
    let silent = TcpStream::connect(address).await?;

    // The peer behind it in the queue, which must still be served.
    let mut waiting = TcpStream::connect(address).await?;
    waiting.write_all(&frame(Command::Status.wire_byte(), b"")).await?;
    let (status, payload) = response(&mut waiting).await?;
    assert_eq!(
        (status, payload.as_slice()),
        (Status::Ok.wire_byte(), &b"OK"[..]),
        "the second client was served, so the first did not wedge the listener"
    );
    drop(waiting);
    drop(silent);

    let events = server.await?;
    let timeout = events
        .iter()
        .filter_map(Event::failure)
        .find(|text| text.contains("nothing arrived for"))
        .ok_or("the silent client did not time out")?;
    assert!(timeout.contains("first byte"), "{timeout}");
    assert!(
        events.contains(&Event::Request(Command::Status, Vec::new())),
        "the queued client was never served: {events:?}"
    );
    Ok(())
}

/// A peer that starts something and then stalls is bounded by the **handshake** deadline,
/// not by the transfer one.
///
/// The distinction is the whole point of having two: the no-progress deadline a 64 MiB
/// `CMD_WRITE` needs is minutes, and if a half-sent header block inherited it, one byte
/// would buy a peer minutes of the single-client listener. The deadlines here are set far
/// apart so a regression shows up as a slow test rather than a subtle one.
#[tokio::test]
async fn a_peer_that_dribbles_one_byte_is_bounded_by_the_handshake_deadline() -> TestResult {
    let timeouts = Timeouts {
        handshake: Some(Duration::from_millis(150)),
        read: Some(Duration::from_secs(30)),
        idle: Some(Duration::from_secs(30)),
    };

    // The start of a WebSocket upgrade, and then silence: the header block never ends.
    let (address, server) = serve(Auth::open(), timeouts, 1, Reply::Plain);
    let mut client = TcpStream::connect(address).await?;
    client.write_all(b"GET / HTTP/1.1\r\nHost: h\r\n").await?;
    let started = std::time::Instant::now();
    let events = server.await?;
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "the upgrade's header block took the transfer deadline: {:?}",
        started.elapsed()
    );
    assert!(
        events
            .iter()
            .any(|event| event.failure().is_some_and(|text| text.contains("request headers"))),
        "{events:?}"
    );
    drop(client);

    // The start of a token handshake, and then silence.
    let (address, server) = serve(Auth::with_token("s3cr3t"), timeouts, 1, Reply::Plain);
    let mut client = TcpStream::connect(address).await?;
    client.write_all(&MAGIC.to_be_bytes()).await?;
    let started = std::time::Instant::now();
    let events = server.await?;
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "the auth handshake took the transfer deadline: {:?}",
        started.elapsed()
    );
    assert!(
        events
            .iter()
            .any(|event| event.failure().is_some_and(|text| text.contains("auth handshake"))),
        "{events:?}"
    );
    drop(client);
    Ok(())
}

/// The idle deadline covers the gap *between* commands on a live connection, not just the
/// first byte of one.
#[tokio::test]
async fn a_connection_that_goes_quiet_between_commands_is_closed() -> TestResult {
    let (address, server) = serve(Auth::open(), brisk(), 1, Reply::Plain);
    let mut client = TcpStream::connect(address).await?;
    client.write_all(&frame(Command::Status.wire_byte(), b"")).await?;
    let _first = response(&mut client).await?;

    // Now say nothing. The server must give up rather than hold the connection open.
    let rest = drain(&mut client).await?;
    assert!(rest.is_empty(), "no second response was owed");

    let events = server.await?;
    let timeout = events
        .iter()
        .filter_map(Event::failure)
        .find(|text| text.contains("nothing arrived for"))
        .ok_or("an idle connection was held open")?;
    assert!(timeout.contains("request header"), "{timeout}");
    Ok(())
}

// ---------------------------------------------------------------------------
// A drop mid-request leaves nothing stuck
// ---------------------------------------------------------------------------

/// A client that half-closes part-way through a payload it announced must be
/// reported as exactly that, and the daemon must serve the next client normally.
///
/// An earlier implementation's daemon sat at `writing` for the life of the process after this, while its
/// own doc said it could not happen. The structural answer is that there is no state to
/// leave behind: the only per-connection state is `Conn::current`, and it dies with the
/// `Conn`.
#[tokio::test]
async fn a_half_close_mid_request_leaves_nothing_stuck() -> TestResult {
    let (address, server) = serve(Auth::open(), brisk(), 2, Reply::Plain);

    // Announce a 4096-byte WRITE, send 10 bytes of it, then go away.
    let mut dropper = TcpStream::connect(address).await?;
    dropper
        .write_all(&header_claiming(Command::Write.wire_byte(), 4096))
        .await?;
    dropper.write_all(&[0xAB; 10]).await?;
    dropper.shutdown().await?;
    drop(dropper);

    // The very next client gets a clean connection and a correct answer.
    let mut next = TcpStream::connect(address).await?;
    next.write_all(&frame(Command::Discover.wire_byte(), b"")).await?;
    let (status, payload) = response(&mut next).await?;
    assert_eq!((status, payload.as_slice()), (Status::Ok.wire_byte(), &b"OK"[..]));
    drop(next);

    let events = server.await?;
    let truncated = events
        .iter()
        .filter_map(Event::failure)
        .find(|text| text.contains("the peer stopped"))
        .ok_or("the half-close was not reported")?;
    assert!(
        truncated.contains("after 10 of 4096 bytes"),
        "the message lost the numbers it had: {truncated}"
    );
    assert!(truncated.contains("payload"), "{truncated}");
    assert!(
        events.contains(&Event::Request(Command::Discover, Vec::new())),
        "the next client was not served: {events:?}"
    );
    Ok(())
}

/// A peer that closes cleanly between frames is `Ok(None)`, not a failure. Told apart from
/// the case above by where it stopped.
#[tokio::test]
async fn a_clean_close_between_commands_is_not_a_failure() -> TestResult {
    let (address, server) = serve(Auth::open(), brisk(), 1, Reply::Plain);
    let mut client = TcpStream::connect(address).await?;
    client.write_all(&frame(Command::Status.wire_byte(), b"")).await?;
    let _reply = response(&mut client).await?;
    client.shutdown().await?;
    drop(client);

    let events = server.await?;
    assert!(events.contains(&Event::Closed), "{events:?}");
    assert!(
        events.iter().all(|event| event.failure().is_none()),
        "a clean hang-up is not an error: {events:?}"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Refusals, and which of them end the connection
// ---------------------------------------------------------------------------

/// `dfu-remote/main.c:823-827`: over the cap, the peer is told and the
/// connection ends.
#[tokio::test]
async fn rpc_oversize_payload_is_refused_and_the_connection_ends() -> TestResult {
    let (address, server) = serve(Auth::open(), brisk(), 1, Reply::Plain);
    let mut client = TcpStream::connect(address).await?;
    client
        .write_all(&header_claiming(Command::Write.wire_byte(), MAX_PAYLOAD + 1))
        .await?;

    let (status, payload) = response(&mut client).await?;
    assert_eq!(status, Status::Error.wire_byte());
    assert_eq!(payload, b"payload too large");
    assert!(drain(&mut client).await?.is_empty(), "the connection must end");

    let events = server.await?;
    assert!(
        events
            .iter()
            .any(|event| event.failure().is_some_and(|text| text.contains("payload too large"))),
        "{events:?}"
    );
    Ok(())
}

/// Exactly the cap is legal (`>` on both sides). Checked at the header, so
/// the test does not have to move 64 MiB.
#[tokio::test]
async fn rpc_exactly_the_cap_is_not_refused_at_the_header() -> TestResult {
    let (address, server) = serve(Auth::open(), brisk(), 1, Reply::Plain);
    let mut client = TcpStream::connect(address).await?;
    client
        .write_all(&header_claiming(Command::Write.wire_byte(), MAX_PAYLOAD))
        .await?;
    client.shutdown().await?;

    // No refusal frame: the header was accepted and the daemon went on to read a payload
    // the client never sent.
    assert!(drain(&mut client).await?.is_empty());
    let events = server.await?;
    let failure = events
        .iter()
        .find_map(Event::failure)
        .ok_or("expected a truncated payload")?;
    assert!(
        failure.contains("the peer stopped after 0 of 67108864 bytes"),
        "{failure}"
    );
    assert!(!failure.contains("too large"), "the cap is a maximum: {failure}");
    Ok(())
}

/// `dfu-remote/main.c:815-822`: bad magic and a version mismatch each end the
/// connection, with their exact strings.
#[tokio::test]
async fn rpc_header_errors() -> TestResult {
    for (spoil, expected) in [(0_usize, "bad magic"), (4, "version mismatch")] {
        let (address, server) = serve(Auth::open(), brisk(), 1, Reply::Plain);
        let mut client = TcpStream::connect(address).await?;
        let mut bad = frame(Command::Status.wire_byte(), b"");
        if let Some(byte) = bad.get_mut(spoil) {
            *byte = 0x7F;
        }
        client.write_all(&bad).await?;

        let (status, payload) = response(&mut client).await?;
        assert_eq!(status, Status::Error.wire_byte());
        assert_eq!(payload, expected.as_bytes());
        assert!(
            drain(&mut client).await?.is_empty(),
            "{expected} must end the connection"
        );
        let _events = server.await?;
    }
    Ok(())
}

/// The other half, `dfu-remote/main.c:803-804`: an unknown command is refused and
/// **the connection continues**. The announced payload has to be skipped to get there.
#[tokio::test]
async fn rpc_unknown_command_is_refused_and_the_connection_continues() -> TestResult {
    let (address, server) = serve(Auth::open(), brisk(), 1, Reply::Plain);
    let mut client = TcpStream::connect(address).await?;

    // Command 0x09 does not exist, and it claims a payload that must be skipped exactly.
    client.write_all(&frame(0x09, b"payload-to-skip")).await?;
    let (status, payload) = response(&mut client).await?;
    assert_eq!(status, Status::Error.wire_byte());
    assert_eq!(payload, b"unknown command");

    // The connection is still good, and still framed: the skip consumed the payload and
    // stopped.
    client.write_all(&frame(Command::Status.wire_byte(), b"")).await?;
    let (status, payload) = response(&mut client).await?;
    assert_eq!((status, payload.as_slice()), (Status::Ok.wire_byte(), &b"OK"[..]));

    // And again, with a zero-length payload, so the skip of 0 is exercised too.
    client.write_all(&frame(0x00, b"")).await?;
    let (status, payload) = response(&mut client).await?;
    assert_eq!(
        (status, payload.as_slice()),
        (Status::Error.wire_byte(), &b"unknown command"[..])
    );
    client.write_all(&frame(Command::Cancel.wire_byte(), b"")).await?;
    let (status, _) = response(&mut client).await?;
    assert_eq!(status, Status::Ok.wire_byte());
    drop(client);

    let events = server.await?;
    assert!(
        events.contains(&Event::Request(Command::Status, Vec::new())),
        "{events:?}"
    );
    assert!(
        events.contains(&Event::Request(Command::Cancel, Vec::new())),
        "{events:?}"
    );
    Ok(())
}

/// The skip after an unknown command spans more than one read.
///
/// Every other test skips a payload that fits in a single 16 KiB scratch buffer, and for
/// those the loop runs once — so its arithmetic is unobservable. `cargo mutants` found
/// that: `count -= take` mutated to `+=` survived the whole suite, because the very next
/// iteration asks for a slice longer than the buffer and takes the defensive `break`.
/// Past one chunk, the two differ: `+=` reads for ever.
#[tokio::test]
async fn a_skipped_payload_larger_than_one_chunk_is_skipped_exactly() -> TestResult {
    let (address, server) = serve(Auth::open(), brisk(), 1, Reply::Plain);
    let mut client = TcpStream::connect(address).await?;

    // 40 KiB is three passes of the 16 KiB scratch buffer, the last one partial.
    let bulk = vec![0x5A_u8; 40 * 1024];
    client.write_all(&frame(0x09, &bulk)).await?;
    let (status, payload) = response(&mut client).await?;
    assert_eq!(
        (status, payload.as_slice()),
        (Status::Error.wire_byte(), &b"unknown command"[..])
    );

    // The stream is still framed: the skip stopped on the byte it was told to.
    client.write_all(&frame(Command::Status.wire_byte(), b"")).await?;
    let (status, payload) = response(&mut client).await?;
    assert_eq!((status, payload.as_slice()), (Status::Ok.wire_byte(), &b"OK"[..]));
    drop(client);

    let events = server.await?;
    assert!(
        events.contains(&Event::Request(Command::Status, Vec::new())),
        "{events:?}"
    );
    Ok(())
}

/// A skip that is cut short reports **everything it got through**, not
/// just the chunk it was in.
///
/// This is `Conn::discard`'s half of the `left`/`count` fix in `511552f`; only its twin
/// in `Wire::discard` was pinned, and every `header_claiming` call here names a *known*
/// command, so nothing reached the skip path with a payload it would not deliver.
///
/// The truncation is deliberately put in the **second** chunk. Cutting the first one off
/// makes `skipped` zero, so `skipped.saturating_add(got)` and a bare `got` agree and the
/// mutant lives; past 16 KiB they differ by exactly the chunk that was already consumed.
#[tokio::test]
async fn a_truncated_skip_reports_everything_it_skipped() -> TestResult {
    let (address, server) = serve(Auth::open(), brisk(), 1, Reply::Plain);
    let mut client = TcpStream::connect(address).await?;

    // Command 0x09 does not exist, so the announced payload is skipped rather than read.
    client.write_all(&header_claiming(0x09, 40_000)).await?;
    client.write_all(&vec![0x5A_u8; 20_000]).await?;
    client.shutdown().await?;

    assert!(drain(&mut client).await?.is_empty(), "no refusal frame was owed");
    let events = server.await?;
    let failure = events
        .iter()
        .filter_map(Event::failure)
        .find(|text| text.contains("the peer stopped"))
        .ok_or("the truncated skip was not reported")?;
    assert!(
        failure.contains("after 20000 of 40000 bytes"),
        "the count lost the chunk that had already been skipped: {failure}"
    );
    assert!(failure.contains("skipped payload"), "{failure}");
    Ok(())
}

/// A raw client may send many commands on one connection.
#[tokio::test]
async fn rpc_many_commands_on_one_raw_connection() -> TestResult {
    let (address, server) = serve(Auth::open(), brisk(), 1, Reply::Plain);
    let mut client = TcpStream::connect(address).await?;
    for command in [Command::Discover, Command::Status, Command::Diag] {
        client.write_all(&frame(command.wire_byte(), b"")).await?;
        let (status, _) = response(&mut client).await?;
        assert_eq!(status, Status::Ok.wire_byte(), "{command:?}");
    }
    drop(client);
    let events = server.await?;
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, Event::Request(..)))
            .count(),
        3
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, Event::Accepted(_)))
            .count(),
        1,
        "one connection, not three"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// The token handshake
// ---------------------------------------------------------------------------

/// The handshake prefix: `[4:magic][1:version][1:token_len][token]`.
fn handshake(token: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&MAGIC.to_be_bytes());
    bytes.push(VERSION);
    bytes.push(u8::try_from(token.len()).unwrap_or(u8::MAX));
    bytes.extend_from_slice(token);
    bytes
}

/// `dfu-remote/main.c:850-886`. Present and absent, right and wrong.
#[tokio::test]
async fn rpc_auth_both_transports() -> TestResult {
    // No `--token`: no handshake is expected, and a command works straight away.
    let (address, server) = serve(Auth::open(), brisk(), 1, Reply::Plain);
    let mut client = TcpStream::connect(address).await?;
    client.write_all(&frame(Command::Status.wire_byte(), b"")).await?;
    let (status, _) = response(&mut client).await?;
    assert_eq!(status, Status::Ok.wire_byte(), "an open daemon expects no handshake");
    drop(client);
    let _events = server.await?;

    // `--token`, and the right one: OK "OK", then commands.
    let (address, server) = serve(Auth::with_token("s3cr3t"), brisk(), 1, Reply::Plain);
    let mut client = TcpStream::connect(address).await?;
    client.write_all(&handshake(b"s3cr3t")).await?;
    let (status, payload) = response(&mut client).await?;
    assert_eq!((status, payload.as_slice()), (Status::Ok.wire_byte(), &b"OK"[..]));
    client.write_all(&frame(Command::Status.wire_byte(), b"")).await?;
    let (status, _) = response(&mut client).await?;
    assert_eq!(status, Status::Ok.wire_byte());
    drop(client);
    let events = server.await?;
    assert!(
        events.contains(&Event::Request(Command::Status, Vec::new())),
        "{events:?}"
    );

    // The wrong one: refused with the frozen string, and the connection ends.
    let (address, server) = serve(Auth::with_token("s3cr3t"), brisk(), 1, Reply::Plain);
    let mut client = TcpStream::connect(address).await?;
    client.write_all(&handshake(b"s3cr3T")).await?;
    let (status, payload) = response(&mut client).await?;
    assert_eq!(status, Status::Error.wire_byte());
    assert_eq!(payload, b"auth: invalid token");
    assert!(drain(&mut client).await?.is_empty(), "a rejected client is closed");
    let events = server.await?;
    assert!(
        events.iter().any(|event| event
            .failure()
            .is_some_and(|text| text.contains("auth rejected over raw"))),
        "{events:?}"
    );

    // A prefix that is not ours at all: one string for bad magic and bad version alike
    // (`dfu-remote/main.c:860-863`), unlike the command header.
    for spoil in [0_usize, 4] {
        let (address, server) = serve(Auth::with_token("s3cr3t"), brisk(), 1, Reply::Plain);
        let mut client = TcpStream::connect(address).await?;
        let mut prefix = handshake(b"s3cr3t");
        if let Some(byte) = prefix.get_mut(spoil) {
            *byte = 0x7F;
        }
        client.write_all(&prefix).await?;
        let (status, payload) = response(&mut client).await?;
        assert_eq!(status, Status::Error.wire_byte());
        assert_eq!(payload, b"auth: bad handshake", "spoiled byte {spoil}");
        let _events = server.await?;
    }
    Ok(())
}

/// Every rejection is counted by the `Auth` itself, so
/// the record does not depend on a `tracing` subscriber having been installed.
#[tokio::test]
async fn every_auth_rejection_leaves_a_trace() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let auth = Auth::with_token("s3cr3t");

    for guess in [&b"a"[..], b"s3cr3", b"s3cr3t!", b"t3rc3s"] {
        let mut client = TcpStream::connect(address).await?;
        let (stream, _) = listener.accept().await?;
        let served = Conn::accept_with(stream, &auth, brisk(), shipped());
        let refused = async {
            client.write_all(&handshake(guess)).await?;
            response(&mut client).await
        };
        let (outcome, reply) = tokio::join!(served, refused);
        assert!(outcome.is_err(), "guess {guess:?} was accepted");
        let (status, payload) = reply?;
        assert_eq!(status, Status::Error.wire_byte());
        assert_eq!(payload, b"auth: invalid token");
    }

    assert_eq!(auth.rejections(), 4, "four guesses, four records");
    assert_eq!(auth.acceptances(), 0);
    Ok(())
}

/// A peer that half-closes during the handshake is **not** an auth
/// rejection, and is not logged as one.
///
/// Both arms of the old behaviour said something false: `TDFU` then a close was
/// `the handshake magic or version was not ours` when the magic was ours, and a peer that
/// announced twelve token bytes and sent three was `no token was presented` when a token
/// was announced. Either way it inflated `Auth::rejections()`, which is the one number
/// the auth log exists to make trustworthy, and it is the named failure
/// ("a dropped connection was reported as `Auth failed`") reproduced inside the module
/// written against it.
#[tokio::test]
async fn a_half_close_during_the_handshake_is_not_an_auth_rejection() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let auth = Auth::with_token("s3cr3t");

    // (a) The magic, and then nothing: the six-byte prefix never completes.
    let mut client = TcpStream::connect(address).await?;
    let (stream, _) = listener.accept().await?;
    let served = Conn::accept_with(stream, &auth, brisk(), shipped());
    let dropped = async {
        client.write_all(&MAGIC.to_be_bytes()).await?;
        client.shutdown().await?;
        Ok::<(), std::io::Error>(())
    };
    let (outcome, dropped) = tokio::join!(served, dropped);
    dropped?;
    let failure = match outcome {
        Err(error) => error.to_string(),
        Ok(_) => "expected the handshake to fail".to_owned(),
    };
    assert!(failure.contains("after 4 of 6 bytes"), "{failure}");
    assert!(failure.contains("auth handshake"), "{failure}");
    assert!(
        !failure.contains("auth rejected"),
        "a dropped connection is not a refusal: {failure}"
    );

    // (b) A complete prefix announcing twelve token bytes, three of them sent.
    let mut client = TcpStream::connect(address).await?;
    let (stream, _) = listener.accept().await?;
    let served = Conn::accept_with(stream, &auth, brisk(), shipped());
    let dropped = async {
        let mut prefix = MAGIC.to_be_bytes().to_vec();
        prefix.push(VERSION);
        prefix.push(12);
        prefix.extend_from_slice(b"abc");
        client.write_all(&prefix).await?;
        client.shutdown().await?;
        Ok::<(), std::io::Error>(())
    };
    let (outcome, dropped) = tokio::join!(served, dropped);
    dropped?;
    let failure = match outcome {
        Err(error) => error.to_string(),
        Ok(_) => "expected the handshake to fail".to_owned(),
    };
    assert!(failure.contains("after 3 of 12 bytes"), "{failure}");
    assert!(failure.contains("auth token"), "{failure}");

    assert_eq!(auth.rejections(), 0, "neither peer presented anything to refuse");
    assert_eq!(auth.acceptances(), 0);
    assert_eq!(auth.abandons(), 2, "both are counted, as the thing they are");
    Ok(())
}

// ---------------------------------------------------------------------------
// The WebSocket transport
// ---------------------------------------------------------------------------

/// A minimal RFC 6455 client: enough to upgrade, mask, and read the server's frames.
struct WsClient {
    buffered: Vec<u8>,
}

impl WsClient {
    /// The upgrade, checking the accept key against RFC 6455 §1.3's worked example.
    async fn upgrade(stream: &mut TcpStream) -> Result<Self, Box<dyn core::error::Error>> {
        stream
            .write_all(
                b"GET /ws HTTP/1.1\r\n\
                  Host: localhost\r\n\
                  Upgrade: websocket\r\n\
                  Connection: Upgrade\r\n\
                  Sec-WebSocket-Version: 13\r\n\
                  Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
                  \r\n",
            )
            .await?;

        let mut block = Vec::new();
        loop {
            let mut byte = [0_u8; 1];
            let read = tokio::time::timeout(CLIENT_DEADLINE, stream.read_exact(&mut byte)).await;
            if !matches!(read, Ok(Ok(_))) {
                return Err("the upgrade response never arrived".into());
            }
            block.push(byte[0]);
            if block.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let text = String::from_utf8_lossy(&block).into_owned();
        assert!(text.starts_with("HTTP/1.1 101 Switching Protocols\r\n"), "{text}");
        assert!(
            text.contains("Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"),
            "the accept key is not RFC 6455 §1.3's: {text}"
        );
        assert!(
            text.contains("Access-Control-Allow-Private-Network: true\r\n"),
            "{text}"
        );
        Ok(Self { buffered: Vec::new() })
    }

    /// One client frame. `mask` off is the RFC 6455 §5.1 violation the C tolerates.
    async fn frame(
        stream: &mut TcpStream,
        opcode: u8,
        payload: &[u8],
        masked: bool,
    ) -> Result<(), Box<dyn core::error::Error>> {
        let mut bytes = vec![0x80 | opcode];
        let flag: u8 = if masked { 0x80 } else { 0x00 };
        let len = payload.len();
        if len < 126 {
            bytes.push(flag | u8::try_from(len).unwrap_or(0));
        } else if len < 65_536 {
            bytes.push(flag | 0x7E);
            bytes.extend_from_slice(&u16::try_from(len).unwrap_or(u16::MAX).to_be_bytes());
        } else {
            bytes.push(flag | 0x7F);
            bytes.extend_from_slice(&(len as u64).to_be_bytes()); // usize -> u64 widens
        }
        let key = [0x37_u8, 0xFA, 0x21, 0x3D];
        if masked {
            bytes.extend_from_slice(&key);
            for (index, byte) in payload.iter().enumerate() {
                bytes.push(byte ^ key[index & 3]);
            }
        } else {
            bytes.extend_from_slice(payload);
        }
        stream.write_all(&bytes).await?;
        Ok(())
    }

    async fn send(
        &mut self,
        stream: &mut TcpStream,
        opcode: u8,
        payload: &[u8],
    ) -> Result<(), Box<dyn core::error::Error>> {
        Self::frame(stream, opcode, payload, true).await
    }

    /// The next server frame, whole: opcode and payload. Server frames are never masked.
    async fn next_frame(stream: &mut TcpStream) -> Result<(u8, Vec<u8>), Box<dyn core::error::Error>> {
        let mut head = [0_u8; 2];
        tokio::time::timeout(CLIENT_DEADLINE, stream.read_exact(&mut head)).await??;
        assert_eq!(head[1] & 0x80, 0, "a server frame must not be masked (RFC 6455 §5.1)");
        let len = match head[1] & 0x7F {
            126 => {
                let mut extended = [0_u8; 2];
                stream.read_exact(&mut extended).await?;
                u64::from(u16::from_be_bytes(extended))
            }
            127 => {
                let mut extended = [0_u8; 8];
                stream.read_exact(&mut extended).await?;
                u64::from_be_bytes(extended)
            }
            short => u64::from(short),
        };
        let mut payload = vec![0_u8; usize::try_from(len).unwrap_or(0)];
        tokio::time::timeout(CLIENT_DEADLINE, stream.read_exact(&mut payload)).await??;
        Ok((head[0] & 0x0F, payload))
    }

    /// One TDFU response frame, gathered across however many WebSocket frames it took.
    async fn response(&mut self, stream: &mut TcpStream) -> Result<(u8, Vec<u8>), Box<dyn core::error::Error>> {
        let header = self.take(stream, HEADER_LEN).await?;
        let magic = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
        assert_eq!(magic, MAGIC);
        let len = u32::from_be_bytes([header[6], header[7], header[8], header[9]]) as usize;
        let payload = self.take(stream, len).await?;
        Ok((header[5], payload))
    }

    /// `want` bytes of the data-frame byte stream.
    async fn take(&mut self, stream: &mut TcpStream, want: usize) -> Result<Vec<u8>, Box<dyn core::error::Error>> {
        while self.buffered.len() < want {
            let (opcode, payload) = Self::next_frame(stream).await?;
            assert!(opcode < 0x8, "expected a data frame, got opcode 0x{opcode:X}");
            self.buffered.extend_from_slice(&payload);
        }
        Ok(self.buffered.drain(..want).collect())
    }
}

/// TDFU frames are a byte stream across WebSocket frames, so a header may
/// straddle a boundary and must still be read.
#[tokio::test]
async fn rpc_ws_codec() -> TestResult {
    let (address, server) = serve(Auth::open(), brisk(), 1, Reply::Plain);
    let mut client = TcpStream::connect(address).await?;
    let mut ws = WsClient::upgrade(&mut client).await?;

    // A DIAG frame split so the 10-byte header lands across three WebSocket frames.
    let request = frame(Command::Diag.wire_byte(), &[7]);
    ws.send(&mut client, 0x2, &request[..4]).await?;
    ws.send(&mut client, 0x0, &request[4..7]).await?;
    ws.send(&mut client, 0x0, &request[7..]).await?;

    let (status, payload) = ws.response(&mut client).await?;
    assert_eq!((status, payload.as_slice()), (Status::Ok.wire_byte(), &b"OK"[..]));
    drop(client);

    let events = server.await?;
    assert!(events.contains(&Event::Request(Command::Diag, vec![7])), "{events:?}");
    Ok(())
}

/// A `GET` that is not an upgrade gets an answer, not a silent close.
///
/// The C checks only for `Sec-WebSocket-Key` and, failing to find it, closes without
/// writing anything (`dfu-remote/ws.c:198-199`, `main.c:1145-1147`) — so a browser pointed
/// at the daemon's port sees a connection reset.
///
/// **Every case differs from a valid upgrade in exactly the field it names.**
/// Two of them used to omit `Connection: Upgrade` as well, so once that check was
/// added they would have been refused before reaching the version or the key at all, and
/// the branch each is named for would have gone untested while the test went on passing.
#[tokio::test]
async fn a_get_that_is_not_an_upgrade_is_answered() -> TestResult {
    for (request, why, reason) in [
        // A plain browser visit.
        (
            "GET / HTTP/1.1\r\nHost: h\r\n\r\n",
            "no Upgrade header",
            "not an `Upgrade: websocket` request",
        ),
        // An upgrade to something else.
        (
            "GET / HTTP/1.1\r\nHost: h\r\nUpgrade: h2c\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
            "a different protocol",
            "not an `Upgrade: websocket` request",
        ),
        // RFC 6455 §4.2.1's third field, which the C does not look at either.
        (
            "GET / HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: keep-alive\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
            "Connection does not list Upgrade",
            "no `Connection: Upgrade` header",
        ),
        (
            "GET / HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
            "no Connection header at all",
            "no `Connection: Upgrade` header",
        ),
        // The right shape, the wrong version.
        (
            "GET / HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 8\r\n\r\n",
            "an old draft version",
            "only Sec-WebSocket-Version 13 is spoken",
        ),
        // An upgrade with no key at all.
        (
            "GET / HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n\r\n",
            "no key to answer",
            "no Sec-WebSocket-Key header",
        ),
    ] {
        let (address, server) = serve(Auth::open(), brisk(), 1, Reply::Plain);
        let mut client = TcpStream::connect(address).await?;
        client.write_all(request.as_bytes()).await?;
        let reply = String::from_utf8_lossy(&drain(&mut client).await?).into_owned();
        assert!(
            reply.starts_with("HTTP/1.1 400 Bad Request\r\n"),
            "{why}: expected a 400, got {reply:?}"
        );
        assert!(reply.contains("Access-Control-Allow-Origin: *\r\n"), "{why}");
        let events = server.await?;
        let failure = events
            .iter()
            .find_map(Event::failure)
            .ok_or("the upgrade was not refused")?;
        assert!(
            failure.contains(reason),
            "{why}: refused for the wrong reason, so this row pins nothing: {failure}"
        );
    }
    Ok(())
}

/// A ping is answered with a pong carrying the same payload, and the data stream around it
/// is untouched — which is the mask bookkeeping working.
#[tokio::test]
async fn rpc_ws_ping_is_answered_and_the_stream_survives_it() -> TestResult {
    let (address, server) = serve(Auth::open(), brisk(), 1, Reply::Plain);
    let mut client = TcpStream::connect(address).await?;
    let mut ws = WsClient::upgrade(&mut client).await?;

    let request = frame(Command::Status.wire_byte(), b"");
    ws.send(&mut client, 0x2, &request[..5]).await?;
    // A legal 125-byte ping, right in the middle of a TDFU frame.
    let ping = vec![0x5A_u8; 125];
    ws.send(&mut client, 0x9, &ping).await?;
    ws.send(&mut client, 0x0, &request[5..]).await?;

    let (opcode, payload) = WsClient::next_frame(&mut client).await?;
    assert_eq!(opcode, 0xA, "a ping must be answered with a pong");
    assert_eq!(payload, ping, "the pong carries the ping's payload, unmasked");

    let (status, payload) = ws.response(&mut client).await?;
    assert_eq!(
        (status, payload.as_slice()),
        (Status::Ok.wire_byte(), &b"OK"[..]),
        "the request either side of the ping was still read correctly"
    );
    drop(client);
    let _events = server.await?;
    Ok(())
}

/// **RFC 6455 §5.1.** The C zeroes the key and unmasks anyway
/// (`dfu-remote/ws.c:296-301`); an unmasked client frame is refused here.
#[tokio::test]
async fn rpc_ws_unmasked_client_frames_are_refused() -> TestResult {
    let (address, server) = serve(Auth::open(), brisk(), 1, Reply::Plain);
    let mut client = TcpStream::connect(address).await?;
    let _ws = WsClient::upgrade(&mut client).await?;

    WsClient::frame(&mut client, 0x2, &frame(Command::Status.wire_byte(), b""), false).await?;

    let (opcode, payload) = WsClient::next_frame(&mut client).await?;
    assert_eq!(opcode, 0x8, "the connection is failed with a close frame");
    assert_eq!(payload, vec![0x03, 0xEA], "close status 1002, protocol error");

    let events = server.await?;
    let failure = events
        .iter()
        .filter_map(Event::failure)
        .find(|text| text.contains("was not masked"))
        .ok_or("an unmasked frame was accepted")?;
    assert!(failure.contains("RFC 6455 §5.1"), "{failure}");
    Ok(())
}

/// **RFC 6455 §5.5.** A control frame announcing more than 125 bytes: the C reads 125 and
/// leaves the rest, desyncing every following frame (`dfu-remote/ws.c:308-310`). Here the
/// tail is drained and the connection is failed with 1002.
#[tokio::test]
async fn rpc_ws_oversize_control_payload_is_refused() -> TestResult {
    let (address, server) = serve(Auth::open(), brisk(), 1, Reply::Plain);
    let mut client = TcpStream::connect(address).await?;
    let mut ws = WsClient::upgrade(&mut client).await?;

    // 200 bytes on a ping. The last 75 are what the C would parse as the next frame.
    ws.send(&mut client, 0x9, &[0xC3_u8; 200]).await?;

    let (opcode, payload) = WsClient::next_frame(&mut client).await?;
    assert_eq!(opcode, 0x8, "a control frame that long fails the connection");
    assert_eq!(payload, vec![0x03, 0xEA], "close status 1002");

    let events = server.await?;
    let failure = events
        .iter()
        .filter_map(Event::failure)
        .find(|text| text.contains("control payload at 125"))
        .ok_or("an oversize control frame was tolerated")?;
    assert!(failure.contains("announced 200 payload bytes"), "{failure}");
    assert!(failure.contains("0x9"), "the opcode is part of the fact: {failure}");
    Ok(())
}

/// An oversize control frame is failed **without its payload being
/// read**, and the announced length is a 64-bit field an unauthenticated peer chooses.
///
/// The daemon used to drain the announcement before failing, bounded only by
/// `Timeouts::read` *per read* and never in total, so one 14-byte header announcing 2^63
/// bytes plus one byte a minute held the single-client daemon for ever from outside the
/// token handshake: the wedged listener, restored pre-auth.
///
/// The read deadline here is 30 s against a 2 s budget for the whole test: a daemon that
/// drains cannot answer inside the budget, so the drain coming back **fails** this test
/// rather than slowing it.
#[tokio::test]
async fn a_control_frame_announcing_a_64_bit_length_is_failed_without_reading_it() -> TestResult {
    let patient = Timeouts {
        handshake: Some(Duration::from_secs(5)),
        read: Some(Duration::from_secs(30)),
        idle: Some(Duration::from_secs(30)),
    };
    let (address, server) = serve(Auth::with_token("s3cr3t"), patient, 1, Reply::Plain);
    let mut client = TcpStream::connect(address).await?;
    let _ws = WsClient::upgrade(&mut client).await?;

    // A masked ping announcing 2^63 bytes, and not one byte of the payload after it.
    // The peer has not authenticated: this is what an unauthenticated stranger can send.
    let started = std::time::Instant::now();
    client
        .write_all(&[0x89, 0xFF, 0x80, 0, 0, 0, 0, 0, 0, 0, 0x37, 0xFA, 0x21, 0x3D])
        .await?;

    let (opcode, payload) = WsClient::next_frame(&mut client).await?;
    assert_eq!(opcode, 0x8, "the connection is failed at once");
    assert_eq!(payload, vec![0x03, 0xEA], "close status 1002");

    let events = server.await?;
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "the daemon read the announced payload instead of refusing the header: {:?}",
        started.elapsed()
    );
    let failure = events
        .iter()
        .filter_map(Event::failure)
        .find(|text| text.contains("control payload at 125"))
        .ok_or("a 2^63-byte control frame was tolerated")?;
    assert!(
        failure.contains("announced 9223372036854775808 payload bytes"),
        "{failure}"
    );
    assert!(
        !failure.contains("oversize control payload"),
        "the refusal must not come from a drain that timed out: {failure}"
    );
    assert!(
        !events
            .iter()
            .any(|event| event.failure().is_some_and(|text| text.contains("auth rejected"))),
        "the peer never authenticated, so nothing here is an auth event: {events:?}"
    );
    Ok(())
}

/// Three WebSocket rules nothing else here exercised, all found by `cargo mutants`.
///
/// * A **control frame must not be fragmented** (RFC 6455 §5.5). Neutering the `FIN` test
///   survived, because every control frame the suite sent had `FIN` set.
/// * A **data frame may be longer than 125 bytes** — that cap is control-frames-only.
///   Neutering the control-frame classification survived, because every data frame the
///   suite sent was short enough to pass the control-payload check anyway.
/// * A **client pong is dropped**, not fatal (`dfu-remote/ws.c:321-331` discards them).
///   Deleting the pong arm sends the frame to the reserved-opcode arm, which fails the
///   connection — and no test sent a pong.
#[tokio::test]
async fn rpc_ws_control_rules_and_long_data_frames() -> TestResult {
    // (a) A fragmented ping: FIN clear on a control opcode.
    let (address, server) = serve(Auth::open(), brisk(), 1, Reply::Plain);
    let mut client = TcpStream::connect(address).await?;
    let _ws = WsClient::upgrade(&mut client).await?;
    // 0x09 = ping with FIN *clear*; masked, 2-byte payload.
    client.write_all(&[0x09, 0x82, 0, 0, 0, 0, 0x41, 0x42]).await?;
    let (opcode, payload) = WsClient::next_frame(&mut client).await?;
    assert_eq!(opcode, 0x8, "a fragmented control frame fails the connection");
    assert_eq!(payload, vec![0x03, 0xEA], "close status 1002");
    let events = server.await?;
    assert!(
        events.iter().any(|event| event
            .failure()
            .is_some_and(|text| text.contains("must not be fragmented"))),
        "{events:?}"
    );

    // (b) A data frame well past 125 bytes, which is a control-frame limit only.
    let (address, server) = serve(Auth::open(), brisk(), 1, Reply::Plain);
    let mut client = TcpStream::connect(address).await?;
    let mut ws = WsClient::upgrade(&mut client).await?;
    let payload = vec![0xA5_u8; 600];
    ws.send(&mut client, 0x2, &frame(Command::Write.wire_byte(), &payload))
        .await?;
    let (status, body) = ws.response(&mut client).await?;
    assert_eq!((status, body.as_slice()), (Status::Ok.wire_byte(), &b"OK"[..]));
    drop(client);
    let events = server.await?;
    assert!(
        events.contains(&Event::Request(Command::Write, payload.clone())),
        "a 600-byte data frame must be served, not refused as an oversize control payload"
    );

    // (c) An unsolicited client pong is discarded and the connection carries on.
    let (address, server) = serve(Auth::open(), brisk(), 1, Reply::Plain);
    let mut client = TcpStream::connect(address).await?;
    let mut ws = WsClient::upgrade(&mut client).await?;
    ws.send(&mut client, 0xA, b"unsolicited").await?;
    ws.send(&mut client, 0x2, &frame(Command::Status.wire_byte(), b""))
        .await?;
    let (status, body) = ws.response(&mut client).await?;
    assert_eq!(
        (status, body.as_slice()),
        (Status::Ok.wire_byte(), &b"OK"[..]),
        "a pong is dropped, and the command after it is still served"
    );
    drop(client);
    let events = server.await?;
    assert!(
        events.contains(&Event::Request(Command::Status, Vec::new())),
        "{events:?}"
    );
    assert!(
        events.iter().all(|event| event.failure().is_none()),
        "a pong is not a protocol error: {events:?}"
    );
    Ok(())
}

/// The split deadline reaches the WebSocket codec too.
///
/// `WsConn::read_exact` picks `first` for the frame the header starts in and `rest` for
/// every frame after it. Nothing distinguished them, because the fixture set idle and read
/// to the same value — so `cargo mutants` swapped the two and nothing failed. Here they
/// are 25x apart.
#[tokio::test]
async fn the_ws_codec_uses_the_read_deadline_for_the_rest_of_a_frame() -> TestResult {
    let timeouts = Timeouts {
        handshake: Some(Duration::from_millis(500)),
        read: Some(Duration::from_millis(200)),
        idle: Some(Duration::from_secs(5)),
    };
    let (address, server) = serve(Auth::open(), timeouts, 1, Reply::Plain);
    let mut client = TcpStream::connect(address).await?;
    let mut ws = WsClient::upgrade(&mut client).await?;

    // Three bytes of a ten-byte header, in one frame, then silence. The daemon has begun
    // a request, so the rest of it is owed under the *read* deadline.
    let request = frame(Command::Status.wire_byte(), b"");
    ws.send(&mut client, 0x2, &request[..3]).await?;

    let started = std::time::Instant::now();
    let events = server.await?;
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "the rest of the header waited on the idle deadline, not the read one: {:?}",
        started.elapsed()
    );
    assert!(
        events
            .iter()
            .any(|event| event.failure().is_some_and(|text| text.contains("nothing arrived for"))),
        "{events:?}"
    );
    drop(client);
    Ok(())
}

/// Two bytes of a frame header must buy the peer the **read** deadline,
/// not the idle one.
///
/// The test above sends a *complete* frame first, so it exercises only the second frame's
/// header, where `first` has already been reassigned to `Timeouts::read`, which is why
/// it could not see this. Here the peer stops inside the **first** frame's header, where
/// the mask read used to inherit `Timeouts::idle`. The two are 25x apart, so a regression
/// shows up as a test that fails on the clock rather than one that is merely slow.
#[tokio::test]
async fn a_websocket_head_without_its_mask_is_bounded_by_the_read_deadline() -> TestResult {
    let timeouts = Timeouts {
        handshake: Some(Duration::from_millis(500)),
        read: Some(Duration::from_millis(200)),
        idle: Some(Duration::from_secs(5)),
    };
    let (address, server) = serve(Auth::open(), timeouts, 1, Reply::Plain);
    let mut client = TcpStream::connect(address).await?;
    let _ws = WsClient::upgrade(&mut client).await?;

    // FIN + binary, masked, announcing a 10-byte payload, and then nothing. The mask is
    // the next thing owed and it never comes.
    let started = std::time::Instant::now();
    client.write_all(&[0x82, 0x8A]).await?;
    let events = server.await?;
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "the mask waited on the idle deadline instead of the read one: {:?}",
        started.elapsed()
    );
    let failure = events
        .iter()
        .filter_map(Event::failure)
        .find(|text| text.contains("nothing arrived for"))
        .ok_or("a head-only peer was held for ever")?;
    assert!(
        failure.contains("websocket mask"),
        "the deadline that fired must be the mask's: {failure}"
    );
    drop(client);
    Ok(())
}

/// A close frame ends the session cleanly, and is answered with one.
#[tokio::test]
async fn rpc_ws_close_ends_the_session() -> TestResult {
    let (address, server) = serve(Auth::open(), brisk(), 1, Reply::Plain);
    let mut client = TcpStream::connect(address).await?;
    let mut ws = WsClient::upgrade(&mut client).await?;
    ws.send(&mut client, 0x8, &[0x03, 0xE8]).await?;

    let (opcode, _) = WsClient::next_frame(&mut client).await?;
    assert_eq!(opcode, 0x8);

    let events = server.await?;
    assert!(events.contains(&Event::Closed), "a close is a clean end: {events:?}");
    assert!(events.iter().all(|event| event.failure().is_none()), "{events:?}");
    Ok(())
}

/// A reserved bit with no extension negotiated (RFC 6455 §5.2). The C looks at neither the
/// reserved bits nor the FIN bit (`dfu-remote/ws.c:280-282`).
#[tokio::test]
async fn rpc_ws_reserved_bits_are_refused() -> TestResult {
    let (address, server) = serve(Auth::open(), brisk(), 1, Reply::Plain);
    let mut client = TcpStream::connect(address).await?;
    let _ws = WsClient::upgrade(&mut client).await?;

    // FIN + RSV1 + binary, masked and otherwise perfectly formed.
    client.write_all(&[0xC2, 0x80, 0, 0, 0, 0]).await?;

    let (opcode, payload) = WsClient::next_frame(&mut client).await?;
    assert_eq!(opcode, 0x8);
    assert_eq!(payload, vec![0x03, 0xEA]);

    let events = server.await?;
    assert!(
        events.iter().any(|event| event
            .failure()
            .is_some_and(|text| text.contains("reserved bits are set"))),
        "{events:?}"
    );
    Ok(())
}

/// The token handshake runs over the WebSocket byte stream, as it does in the C
/// (`dfu-remote/main.c:1139-1143` sets `g_ws` and then calls `handle_client`).
#[tokio::test]
async fn rpc_auth_over_websocket() -> TestResult {
    let (address, server) = serve(Auth::with_token("s3cr3t"), brisk(), 1, Reply::Plain);
    let mut client = TcpStream::connect(address).await?;
    let mut ws = WsClient::upgrade(&mut client).await?;
    ws.send(&mut client, 0x2, &handshake(b"s3cr3t")).await?;
    let (status, payload) = ws.response(&mut client).await?;
    assert_eq!((status, payload.as_slice()), (Status::Ok.wire_byte(), &b"OK"[..]));

    ws.send(&mut client, 0x2, &frame(Command::Status.wire_byte(), b""))
        .await?;
    let (status, _) = ws.response(&mut client).await?;
    assert_eq!(status, Status::Ok.wire_byte());
    drop(client);
    let events = server.await?;
    assert!(
        events.contains(&Event::Request(Command::Status, Vec::new())),
        "{events:?}"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// The HTTP POST transport
// ---------------------------------------------------------------------------

/// One POST carrying `body`, optionally with a token header.
async fn post(stream: &mut TcpStream, body: &[u8], token: Option<&str>) -> TestResult {
    let mut request = format!(
        "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n",
        body.len()
    );
    if let Some(token) = token {
        use core::fmt::Write as _;
        let _wrote = write!(request, "X-Auth-Token: {token}\r\n");
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await?;
    stream.write_all(body).await?;
    Ok(())
}

/// One POST from a browser page on `origin`, with the body and any token.
async fn post_from(stream: &mut TcpStream, origin: &str, body: &[u8], token: Option<&str>) -> TestResult {
    let mut request = format!(
        "POST / HTTP/1.1\r\nHost: localhost\r\nOrigin: {origin}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n",
        body.len()
    );
    if let Some(token) = token {
        use core::fmt::Write as _;
        let _wrote = write!(request, "X-Auth-Token: {token}\r\n");
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await?;
    stream.write_all(body).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Which page may drive the daemon
// ---------------------------------------------------------------------------

/// **Any page the operator visits could drive this daemon.** The POST path answered every
/// origin with `Access-Control-Allow-Origin: *`, so a page on any site could read a whole
/// flash back out of a daemon on the operator's own network, or write firmware of its own
/// into the camera. With the shipped defaults (every interface, no token) nothing else
/// stood in the way.
#[tokio::test]
async fn a_post_from_an_unknown_origin_is_refused() -> TestResult {
    let (address, server) = serve(Auth::open(), brisk(), 1, Reply::Plain);
    let mut client = TcpStream::connect(address).await?;
    post_from(
        &mut client,
        "https://evil.example",
        &frame(Command::Read.wire_byte(), b""),
        None,
    )
    .await?;

    let reply = String::from_utf8_lossy(&drain(&mut client).await?).into_owned();
    assert!(reply.starts_with("HTTP/1.1 403 Forbidden\r\n"), "{reply}");
    assert!(
        !reply.contains("Access-Control-Allow-Origin: *"),
        "a refused page must not be handed the answer: {reply}"
    );
    assert!(!reply.contains("evil.example"), "nor named as allowed: {reply}");
    assert!(reply.contains("Vary: Origin\r\n"), "{reply}");

    // And nothing was dispatched: no USB work for a page that may not ask for it.
    let events = server.await?;
    assert!(
        !events.iter().any(|event| matches!(event, Event::Request(..))),
        "{events:?}"
    );
    Ok(())
}

/// The flasher's own page still works, and the answer names it rather than every origin.
#[tokio::test]
async fn a_post_from_the_flasher_is_served_and_the_answer_names_it() -> TestResult {
    for origin in ["https://webflash.thingino.com", "http://localhost:5173"] {
        let (address, server) = serve(Auth::open(), brisk(), 1, Reply::Plain);
        let mut client = TcpStream::connect(address).await?;
        post_from(&mut client, origin, &frame(Command::Status.wire_byte(), b""), None).await?;

        let (headers, _) = unchunk(&drain(&mut client).await?)?;
        assert!(headers.starts_with("HTTP/1.1 200 OK\r\n"), "{origin}: {headers}");
        assert!(
            headers.contains(&format!("Access-Control-Allow-Origin: {origin}\r\n")),
            "{origin}: {headers}"
        );
        assert!(!headers.contains("Allow-Origin: *"), "{origin}: {headers}");
        assert!(headers.contains("Vary: Origin\r\n"), "{origin}: {headers}");

        let events = server.await?;
        assert!(
            events.contains(&Event::Request(Command::Status, Vec::new())),
            "{events:?}"
        );
    }
    Ok(())
}

/// A client that sends no `Origin` is every non-browser client there is, and it is
/// served exactly as before.
#[tokio::test]
async fn a_client_with_no_origin_is_unaffected() -> TestResult {
    let (address, server) = serve(Auth::open(), brisk(), 1, Reply::Plain);
    let mut client = TcpStream::connect(address).await?;
    post(&mut client, &frame(Command::Status.wire_byte(), b""), None).await?;
    let (headers, _) = unchunk(&drain(&mut client).await?)?;
    assert!(headers.contains("Access-Control-Allow-Origin: *\r\n"), "{headers}");
    let events = server.await?;
    assert!(
        events.contains(&Event::Request(Command::Status, Vec::new())),
        "{events:?}"
    );
    Ok(())
}

/// **A WebSocket handshake is not a CORS request.** A browser opens one cross-origin
/// without asking and hands the socket to the page whatever comes back, so RFC 6455
/// §10.2 leaves the check to the server; there was none, and a page on any origin could
/// open a TDFU stream and drive a flash down it.
#[tokio::test]
async fn a_websocket_upgrade_from_an_unknown_origin_is_refused() -> TestResult {
    let (address, server) = serve(Auth::open(), brisk(), 1, Reply::Plain);
    let mut client = TcpStream::connect(address).await?;
    client
        .write_all(
            b"GET /ws HTTP/1.1\r\n\
              Host: localhost\r\n\
              Origin: https://evil.example\r\n\
              Upgrade: websocket\r\n\
              Connection: Upgrade\r\n\
              Sec-WebSocket-Version: 13\r\n\
              Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
              \r\n",
        )
        .await?;

    let reply = String::from_utf8_lossy(&drain(&mut client).await?).into_owned();
    assert!(reply.starts_with("HTTP/1.1 403 Forbidden\r\n"), "{reply}");
    assert!(!reply.contains("101 Switching Protocols"), "{reply}");
    assert!(!reply.contains("Sec-WebSocket-Accept"), "no socket for it: {reply}");

    let events = server.await?;
    assert!(
        events
            .iter()
            .any(|event| event.failure().is_some_and(|text| text.contains("Origin"))),
        "{events:?}"
    );
    assert!(
        !events.iter().any(|event| matches!(event, Event::Accepted(_))),
        "{events:?}"
    );
    Ok(())
}

/// The upgrade the flasher would make still completes.
#[tokio::test]
async fn a_websocket_upgrade_from_an_allowed_origin_still_works() -> TestResult {
    let (address, server) = serve(Auth::open(), brisk(), 1, Reply::Plain);
    let mut client = TcpStream::connect(address).await?;
    client
        .write_all(
            b"GET /ws HTTP/1.1\r\n\
              Host: localhost\r\n\
              Origin: https://webflash.thingino.com\r\n\
              Upgrade: websocket\r\n\
              Connection: Upgrade\r\n\
              Sec-WebSocket-Version: 13\r\n\
              Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
              \r\n",
        )
        .await?;
    let mut block = Vec::new();
    loop {
        let mut byte = [0_u8; 1];
        tokio::time::timeout(CLIENT_DEADLINE, client.read_exact(&mut byte)).await??;
        block.push(byte[0]);
        if block.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let text = String::from_utf8_lossy(&block).into_owned();
    assert!(text.starts_with("HTTP/1.1 101 Switching Protocols\r\n"), "{text}");
    drop(client);
    let events = server.await?;
    assert_eq!(events.first(), Some(&Event::Accepted("websocket".to_owned())));
    Ok(())
}

/// The preflight is answered for a page that may talk to the daemon and refused for one
/// that may not, so the browser never sends the POST at all.
#[tokio::test]
async fn the_preflight_answers_the_flasher_and_refuses_the_rest() -> TestResult {
    let (address, server) = serve(Auth::open(), brisk(), 1, Reply::Plain);
    let mut client = TcpStream::connect(address).await?;
    client
        .write_all(b"OPTIONS / HTTP/1.1\r\nHost: h\r\nOrigin: https://webflash.thingino.com\r\n\r\n")
        .await?;
    let reply = String::from_utf8_lossy(&drain(&mut client).await?).into_owned();
    assert!(reply.starts_with("HTTP/1.1 200 OK\r\n"), "{reply}");
    assert!(
        reply.contains("Access-Control-Allow-Origin: https://webflash.thingino.com\r\n"),
        "{reply}"
    );
    assert!(
        reply.contains("Access-Control-Allow-Headers: Content-Type, X-Auth-Token\r\n"),
        "the flasher's own headers are still allowed: {reply}"
    );
    let _events = server.await?;

    let (address, server) = serve(Auth::open(), brisk(), 1, Reply::Plain);
    let mut client = TcpStream::connect(address).await?;
    client
        .write_all(b"OPTIONS / HTTP/1.1\r\nHost: h\r\nOrigin: https://evil.example\r\n\r\n")
        .await?;
    let reply = String::from_utf8_lossy(&drain(&mut client).await?).into_owned();
    assert!(reply.starts_with("HTTP/1.1 403 Forbidden\r\n"), "{reply}");
    assert!(!reply.contains("Allow-Methods"), "{reply}");
    let _events = server.await?;
    Ok(())
}

/// Split an HTTP response into its header block and its decoded chunked body.
fn unchunk(response: &[u8]) -> Result<(String, Vec<u8>), Box<dyn core::error::Error>> {
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or("no header terminator")?;
    let headers = String::from_utf8_lossy(&response[..split + 4]).into_owned();
    let mut rest = &response[split + 4..];
    let mut body = Vec::new();
    loop {
        let line = rest
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or("no chunk size")?;
        let size = usize::from_str_radix(core::str::from_utf8(&rest[..line])?.trim(), 16)?;
        rest = &rest[line + 2..];
        if size == 0 {
            break;
        }
        body.extend_from_slice(rest.get(..size).ok_or("chunk shorter than its size")?);
        rest = &rest[size + 2..];
    }
    Ok((headers, body))
}

/// `dfu-remote/main.c:962-983`: the five headers and a chunked TDFU reply.
#[tokio::test]
async fn rpc_http_post_chunked() -> TestResult {
    let (address, server) = serve(Auth::open(), brisk(), 1, Reply::Plain);
    let mut client = TcpStream::connect(address).await?;
    post(&mut client, &frame(Command::Discover.wire_byte(), b""), None).await?;

    let raw = drain(&mut client).await?;
    let (headers, body) = unchunk(&raw)?;
    assert!(headers.starts_with("HTTP/1.1 200 OK\r\n"), "{headers}");
    for header in [
        "Access-Control-Allow-Origin: *",
        "Access-Control-Allow-Private-Network: true",
        "Content-Type: application/octet-stream",
        "Cache-Control: no-store",
        "Transfer-Encoding: chunked",
    ] {
        assert!(headers.contains(header), "missing {header:?}:\n{headers}");
    }
    assert!(raw.ends_with(b"0\r\n\r\n"), "the terminating chunk is missing");

    assert_eq!(body.len(), HEADER_LEN + 2);
    assert_eq!(body.get(5).copied(), Some(Status::Ok.wire_byte()));
    assert_eq!(body.get(HEADER_LEN..), Some(&b"OK"[..]));

    let events = server.await?;
    assert!(
        events.contains(&Event::Request(Command::Discover, Vec::new())),
        "{events:?}"
    );
    Ok(())
}

/// The body's own bytes reach the dispatcher, not the header's.
///
/// Every other HTTP test here sends an empty payload or never inspects it, so the body
/// cursor could stop advancing and nothing would notice — `cargo mutants` turned
/// `self.at += take` into `*=` (which pins the cursor at zero, since it starts there) and
/// the whole suite still passed. This is the browser flasher's transport, where a
/// `CMD_WRITE` payload is a firmware image.
#[tokio::test]
async fn an_http_body_hands_over_its_own_bytes() -> TestResult {
    let (address, server) = serve(Auth::open(), brisk(), 1, Reply::Plain);
    let mut client = TcpStream::connect(address).await?;
    let payload = b"not-the-header-bytes";
    post(&mut client, &frame(Command::Write.wire_byte(), payload), None).await?;
    let _reply = drain(&mut client).await?;

    let events = server.await?;
    assert!(
        events.contains(&Event::Request(Command::Write, payload.to_vec())),
        "the dispatcher was handed the wrong bytes: {events:?}"
    );
    Ok(())
}

/// Exactly one command per POST, however many frames the body holds.
#[tokio::test]
async fn rpc_http_is_one_shot() -> TestResult {
    let (address, server) = serve(Auth::open(), brisk(), 1, Reply::Plain);
    let mut client = TcpStream::connect(address).await?;
    let mut body = frame(Command::Discover.wire_byte(), b"");
    body.extend_from_slice(&frame(Command::Status.wire_byte(), b""));
    post(&mut client, &body, None).await?;

    let raw = drain(&mut client).await?;
    let (_, decoded) = unchunk(&raw)?;
    assert_eq!(decoded.len(), HEADER_LEN + 2, "exactly one response frame");

    let events = server.await?;
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, Event::Request(..)))
            .count(),
        1,
        "the second frame in the body was not served: {events:?}"
    );
    Ok(())
}

/// An unknown command keeps a connection alive; a POST gets
/// exactly one response. On HTTP the refusal *is* that response, so the reply is complete,
/// terminated, and not followed by an attempt to read the body again.
#[tokio::test]
async fn an_unknown_command_over_http_is_answered_once() -> TestResult {
    let (address, server) = serve(Auth::open(), brisk(), 1, Reply::Plain);
    let mut client = TcpStream::connect(address).await?;
    // An unknown command, and then trailing bytes a second read would trip over.
    let mut body = frame(0x09, b"skip me");
    body.extend_from_slice(&frame(Command::Status.wire_byte(), b""));
    post(&mut client, &body, None).await?;

    let raw = drain(&mut client).await?;
    let (headers, decoded) = unchunk(&raw)?;
    assert!(headers.starts_with("HTTP/1.1 200 OK\r\n"), "{headers}");
    assert!(raw.ends_with(b"0\r\n\r\n"), "the chunked body is terminated");
    assert_eq!(decoded.get(5).copied(), Some(Status::Error.wire_byte()));
    assert_eq!(decoded.get(HEADER_LEN..), Some(&b"unknown command"[..]));
    assert_eq!(
        decoded.len(),
        HEADER_LEN + "unknown command".len(),
        "exactly one frame came back"
    );

    let events = server.await?;
    assert!(
        events.iter().all(|event| event.failure().is_none()),
        "the refusal is not a failure of the connection: {events:?}"
    );
    assert!(
        !events.iter().any(|event| matches!(event, Event::Request(..))),
        "nothing dispatchable was found: {events:?}"
    );
    Ok(())
}

/// **The 413 carries the CORS headers.** The C's does not (`dfu-remote/main.c:934`) while
/// its 403 does (`:954-955`), so a browser that oversteps the cap sees an opaque network
/// failure instead of the refusal.
#[tokio::test]
async fn rpc_http_413_carries_the_cors_headers() -> TestResult {
    let (address, server) = serve(Auth::open(), brisk(), 1, Reply::Plain);
    let mut client = TcpStream::connect(address).await?;
    client
        .write_all(
            format!(
                "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n",
                u64::from(MAX_PAYLOAD) + 1
            )
            .as_bytes(),
        )
        .await?;

    let raw = drain(&mut client).await?;
    let reply = String::from_utf8_lossy(&raw).into_owned();
    assert!(reply.starts_with("HTTP/1.1 413 Payload Too Large\r\n"), "{reply}");
    assert!(
        reply.contains("Access-Control-Allow-Origin: *\r\n"),
        "the 413 must be readable by the browser that provoked it:\n{reply}"
    );
    assert!(
        reply.contains("Access-Control-Allow-Private-Network: true\r\n"),
        "{reply}"
    );
    assert!(reply.contains("Content-Length: 0\r\n"), "{reply}");

    // And nothing was buffered: the refusal came from the header, before the body.
    let events = server.await?;
    assert!(
        events
            .iter()
            .any(|event| event.failure().is_some_and(|text| text.contains("over the cap"))),
        "{events:?}"
    );
    Ok(())
}

/// Exactly the cap is legal on HTTP too, so the refusal is `>` and not `>=`.
/// Checked at the header: the body is never sent, so no 64 MiB moves.
#[tokio::test]
async fn rpc_http_exactly_the_cap_is_accepted_at_the_header() -> TestResult {
    let (address, server) = serve(Auth::open(), brisk(), 1, Reply::Plain);
    let mut client = TcpStream::connect(address).await?;
    client
        .write_all(format!("POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: {MAX_PAYLOAD}\r\n\r\n").as_bytes())
        .await?;
    client.shutdown().await?;

    let reply = String::from_utf8_lossy(&drain(&mut client).await?).into_owned();
    assert!(!reply.contains("413"), "the cap is a maximum: {reply}");

    let events = server.await?;
    let failure = events
        .iter()
        .find_map(Event::failure)
        .ok_or("expected a truncated body")?;
    assert!(failure.contains("while reading the request body"), "{failure}");
    Ok(())
}

/// The handshake's HTTP half, `dfu-remote/main.c:948-960`: a wrong `X-Auth-Token` is a 403
/// with the CORS headers, and it is recorded.
#[tokio::test]
async fn rpc_http_auth_is_a_403_with_cors() -> TestResult {
    let (address, server) = serve(Auth::with_token("s3cr3t"), brisk(), 1, Reply::Plain);
    let mut client = TcpStream::connect(address).await?;
    post(&mut client, &frame(Command::Status.wire_byte(), b""), Some("wrong")).await?;

    let reply = String::from_utf8_lossy(&drain(&mut client).await?).into_owned();
    assert!(reply.starts_with("HTTP/1.1 403 Forbidden\r\n"), "{reply}");
    assert!(reply.contains("Access-Control-Allow-Origin: *\r\n"), "{reply}");
    assert!(
        reply.contains("Access-Control-Allow-Private-Network: true\r\n"),
        "{reply}"
    );

    let events = server.await?;
    assert!(
        events.iter().any(|event| event
            .failure()
            .is_some_and(|text| text.contains("auth rejected over http"))),
        "{events:?}"
    );

    // The right token is served.
    let (address, server) = serve(Auth::with_token("s3cr3t"), brisk(), 1, Reply::Plain);
    let mut client = TcpStream::connect(address).await?;
    post(&mut client, &frame(Command::Status.wire_byte(), b""), Some("s3cr3t")).await?;
    let (headers, _) = unchunk(&drain(&mut client).await?)?;
    assert!(headers.starts_with("HTTP/1.1 200 OK\r\n"), "{headers}");
    let events = server.await?;
    assert!(
        events.contains(&Event::Request(Command::Status, Vec::new())),
        "{events:?}"
    );
    Ok(())
}

/// **The token is checked before the body is read.** The body was read first, and
/// `Timeouts::read` bounds one read rather than the transfer, so an unauthenticated peer
/// could announce 64 MiB, send a byte per deadline and hold the single-client daemon for
/// as long as it liked. The refusal now arrives with the body still unsent, and the
/// client behind it is served.
#[tokio::test]
async fn a_wrong_token_is_refused_before_the_body_and_does_not_hold_the_listener() -> TestResult {
    let (address, server) = serve(Auth::with_token("s3cr3t"), brisk(), 2, Reply::Plain);

    // Headers only: a 4 KiB body is announced and never sent.
    let mut dribbler = TcpStream::connect(address).await?;
    dribbler
        .write_all(b"POST / HTTP/1.1\r\nHost: localhost\r\nX-Auth-Token: wrong\r\nContent-Length: 4096\r\n\r\n")
        .await?;

    let mut head = [0_u8; 14];
    tokio::time::timeout(CLIENT_DEADLINE, dribbler.read_exact(&mut head)).await??;
    assert_eq!(&head, b"HTTP/1.1 403 F", "{:?}", String::from_utf8_lossy(&head));
    drop(dribbler);

    // The next client is served, which is the property the wedge took away.
    let mut client = TcpStream::connect(address).await?;
    post(&mut client, &frame(Command::Status.wire_byte(), b""), Some("s3cr3t")).await?;
    let (headers, _) = unchunk(&drain(&mut client).await?)?;
    assert!(headers.starts_with("HTTP/1.1 200 OK\r\n"), "{headers}");

    let events = server.await?;
    assert!(
        events.iter().any(|event| event
            .failure()
            .is_some_and(|text| text.contains("auth rejected over http"))),
        "{events:?}"
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, Event::Request(..)))
            .count(),
        1,
        "only the authenticated client's command was dispatched: {events:?}"
    );
    Ok(())
}

/// **A body has a finite budget.** The per-read deadline is a no-progress bound by
/// design, so a peer that keeps a transfer barely alive was under no bound at all; the
/// whole body is now under one, generous and sized by what was announced.
#[tokio::test]
async fn a_body_that_never_finishes_hits_the_whole_transfer_deadline() -> TestResult {
    // 200 ms of read deadline plus a second per 64 KiB: a 4 KiB body has about 1.2 s,
    // and a peer that sends a byte every 100 ms would otherwise never reach it.
    let timeouts = Timeouts {
        handshake: Some(Duration::from_millis(300)),
        read: Some(Duration::from_millis(200)),
        idle: Some(Duration::from_millis(300)),
    };
    let (address, server) = serve(Auth::open(), timeouts, 1, Reply::Plain);
    let mut client = TcpStream::connect(address).await?;
    client
        .write_all(b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4096\r\n\r\n")
        .await?;

    let started = std::time::Instant::now();
    let dribble = async {
        for _ in 0..100_u32 {
            if client.write_all(b"x").await.is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    };
    let (_dribbled, events) = tokio::join!(tokio::time::timeout(CLIENT_DEADLINE, dribble), server);
    let events = events?;
    assert!(
        started.elapsed() < Duration::from_secs(9),
        "the daemon never gave up: {:?}",
        started.elapsed()
    );
    assert!(
        events
            .iter()
            .any(|event| event.failure().is_some_and(|text| text.contains("request body"))),
        "{events:?}"
    );
    Ok(())
}

/// **A guess costs time.** Every wrong token was answered at once, so an attacker paid
/// one connection per guess; consecutive refusals from one address are now answered
/// later each time.
#[tokio::test]
async fn repeated_wrong_tokens_from_one_address_are_answered_more_slowly() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let auth = Auth::with_token("s3cr3t");

    let mut elapsed = Vec::new();
    for guess in [&b"a"[..], b"s3cr3", b"s3cr3t!"] {
        let mut client = TcpStream::connect(address).await?;
        let (stream, _) = listener.accept().await?;
        let started = std::time::Instant::now();
        let served = Conn::accept_with(stream, &auth, brisk(), shipped());
        let refused = async {
            client.write_all(&handshake(guess)).await?;
            response(&mut client).await
        };
        let (outcome, reply) = tokio::join!(served, refused);
        assert!(outcome.is_err(), "guess {guess:?} was accepted");
        let (status, payload) = reply?;
        assert_eq!(status, Status::Error.wire_byte());
        assert_eq!(payload, b"auth: invalid token");
        elapsed.push(started.elapsed());
    }

    assert!(
        elapsed
            .first()
            .is_some_and(|first| *first >= Duration::from_millis(150)),
        "the first refusal was free: {elapsed:?}"
    );
    let (Some(first), Some(third)) = (elapsed.first(), elapsed.get(2)) else {
        return Err("three guesses were not timed".into());
    };
    assert!(third > first, "the delay did not grow: {elapsed:?}");
    assert_eq!(auth.rejections(), 3);
    Ok(())
}

/// A missing token header is refused the same way a wrong one is, so a prober learns
/// nothing from the difference.
#[tokio::test]
async fn rpc_http_a_missing_token_is_also_a_403() -> TestResult {
    let (address, server) = serve(Auth::with_token("s3cr3t"), brisk(), 1, Reply::Plain);
    let mut client = TcpStream::connect(address).await?;
    post(&mut client, &frame(Command::Status.wire_byte(), b""), None).await?;
    let reply = String::from_utf8_lossy(&drain(&mut client).await?).into_owned();
    assert!(reply.starts_with("HTTP/1.1 403 Forbidden\r\n"), "{reply}");
    let events = server.await?;
    assert!(
        events.iter().any(|event| event
            .failure()
            .is_some_and(|text| text.contains("no token was presented"))),
        "the log distinguishes what the wire does not: {events:?}"
    );
    Ok(())
}

/// The refusals the C cannot make, each with the CORS headers.
#[tokio::test]
async fn http_refusals_name_what_was_wrong() -> TestResult {
    for (request, status) in [
        ("PUT / HTTP/1.1\r\nContent-Length: 0\r\n\r\n", "405 Method Not Allowed"),
        ("POST / HTTP/1.1\r\nHost: h\r\n\r\n", "411 Length Required"),
        ("POST / HTTP/1.1\r\nContent-Length: abc\r\n\r\n", "400 Bad Request"),
        (
            "POST / HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 9\r\n\r\n",
            "400 Bad Request",
        ),
        // A body that cannot hold a header. The C sends the `200` preamble first and then
        // discovers there is no command, leaving a chunked body it never terminates.
        ("POST / HTTP/1.1\r\nContent-Length: 0\r\n\r\n", "400 Bad Request"),
        (
            "POST / HTTP/1.1\r\nContent-Length: 9\r\n\r\nTDFU\x01\x01\x00\x00\x00",
            "400 Bad Request",
        ),
    ] {
        let (address, server) = serve(Auth::open(), brisk(), 1, Reply::Plain);
        let mut client = TcpStream::connect(address).await?;
        client.write_all(request.as_bytes()).await?;
        let reply = String::from_utf8_lossy(&drain(&mut client).await?).into_owned();
        assert!(
            reply.starts_with(&format!("HTTP/1.1 {status}\r\n")),
            "{request:?} gave {reply}"
        );
        assert!(
            reply.contains("Access-Control-Allow-Origin: *\r\n"),
            "{status}: {reply}"
        );
        assert!(
            reply.contains("Access-Control-Allow-Private-Network: true\r\n"),
            "{status}: {reply}"
        );
        let _events = server.await?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Progress and log frames, and when they attach
// ---------------------------------------------------------------------------

/// Peel the frames out of a raw response stream: `(status, payload)` in order.
async fn frames(stream: &mut TcpStream, count: usize) -> Result<Vec<(u8, Vec<u8>)>, Box<dyn core::error::Error>> {
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(response(stream).await?);
    }
    Ok(out)
}

/// No C daemon ever sent a `RESP_PROGRESS`
/// frame although both C clients parse them. This one does.
#[tokio::test]
async fn rpc_progress_frames_are_sent() -> TestResult {
    let (address, server) = serve(Auth::open(), brisk(), 1, Reply::Chatty);
    let mut client = TcpStream::connect(address).await?;
    client.write_all(&frame(Command::Write.wire_byte(), b"image")).await?;

    let got = frames(&mut client, 3).await?;
    assert_eq!(got[0].0, Status::Log.wire_byte(), "the log line comes first");
    assert_eq!(got[0].1, b"staging the loader\n", "a whole line");

    assert_eq!(got[1].0, Status::Progress.wire_byte());
    let body = ProgressBody::decode(&got[1].1)?;
    assert_eq!(body.percent, 50);
    assert_eq!(body.stage, 3, "stage byte for download");
    assert_eq!(body.message, "download");

    assert_eq!(got[2].0, Status::Ok.wire_byte(), "then the final frame");
    assert_eq!(got[2].1, b"OK");
    drop(client);
    let _events = server.await?;
    Ok(())
}

/// `DaemonError::Encode` is reachable, and it **refuses** the frame
/// rather than truncating it.
///
/// It exists only as the `#[from] ProtoError` conversion, raised solely by
/// `ProgressBody::encode()?` in `Conn::progress`, and no daemon path builds a message
/// past `u16::MAX`, so nothing constructed it and nothing asserted it. That is precisely
/// the shape `ProtoError::FieldTooLong` is a lesson about: an earlier implementation's encoder
/// truncated silently, which is how a write to the wrong partition came to be reported as
/// a success. A refusal that nobody has ever seen fail is a refusal nobody knows is
/// there.
#[tokio::test]
async fn a_progress_message_too_long_for_its_length_prefix_is_refused() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let auth = Auth::open();

    let mut client = TcpStream::connect(address).await?;
    let (stream, _) = listener.accept().await?;
    let accepted = Conn::accept_with(stream, &auth, brisk(), shipped());
    let sent = async {
        client.write_all(&frame(Command::Write.wire_byte(), b"")).await?;
        Ok::<(), std::io::Error>(())
    };
    let (accepted, sent) = tokio::join!(accepted, sent);
    sent?;
    let mut conn = accepted?.ok_or("no connection")?;
    let _request = conn.next_request().await?.ok_or("no request")?;

    // 70 000 bytes: past the `u16` length prefix `ProgressBody` encodes it into.
    let refused = conn
        .progress(&ProgressBody {
            percent: 50,
            stage: 3,
            message: "x".repeat(70_000),
        })
        .await;
    let message = match refused {
        Err(error) => error.to_string(),
        Ok(()) => "expected a refusal".to_owned(),
    };
    assert!(message.contains("could not encode a frame"), "{message}");
    assert!(message.contains("70000"), "the length that did not fit: {message}");

    // Nothing went out, so the stream is still framed: the next frame the client reads is
    // the response, not the head of a truncated progress body.
    conn.respond(Status::Ok, b"OK").await?;
    let (status, payload) = response(&mut client).await?;
    assert_eq!(
        (status, payload.as_slice()),
        (Status::Ok.wire_byte(), &b"OK"[..]),
        "a refused frame must leave no bytes behind"
    );
    Ok(())
}

/// A `RESP_LOG` frame carries a whole line, terminator included, and a
/// line that already has one is not given a second.
///
/// The C's log strings all end in `\n` (`libtdfu/src/dfu/dfu.c:618`, `:742`, `:781`,
/// `:861`, `:961`) and `daemon_log_hook` forwards them verbatim
/// (`dfu-remote/main.c:181-188`), so the shipped C CLI adds nothing
/// (`cli/remote.c:194-196`). Ours did not, and a remote `-w --verify` from v1.5.43
/// printed `DFU download completeVerify OK: 16777216 bytes match` on one line. Checked
/// through a real `Conn` rather than the double, because `Conn::log` is where the frame
/// is built.
#[tokio::test]
async fn rpc_log_frames_are_whole_lines() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let auth = Auth::open();

    let mut client = TcpStream::connect(address).await?;
    let (stream, _) = listener.accept().await?;
    let accepted = Conn::accept_with(stream, &auth, brisk(), shipped());
    let sent = async {
        // WRITE, because logs attach for it on raw.
        client.write_all(&frame(Command::Write.wire_byte(), b"")).await?;
        Ok::<(), std::io::Error>(())
    };
    let (accepted, sent) = tokio::join!(accepted, sent);
    sent?;
    let mut conn = accepted?.ok_or("no connection")?;
    let _request = conn.next_request().await?.ok_or("no request")?;

    conn.log("DFU download complete").await?;
    conn.log("Verify OK: 16777216 bytes match\n").await?;
    conn.log("").await?;
    conn.respond(Status::Ok, b"OK").await?;

    let got = frames(&mut client, 4).await?;
    assert_eq!(got[0].0, Status::Log.wire_byte());
    assert_eq!(got[0].1, b"DFU download complete\n", "the terminator is added");
    assert_eq!(got[1].0, Status::Log.wire_byte());
    assert_eq!(
        got[1].1, b"Verify OK: 16777216 bytes match\n",
        "a line that has one is not given a second"
    );
    // A zero-length note still reaches the wire as a line: `remote.js:97-106` handles an
    // empty `RESP_LOG` payload, and the C CLI would print nothing at all for it.
    assert_eq!(got[2].1, b"\n");
    assert_eq!(got[3].0, Status::Ok.wire_byte());

    // Concatenated, the two notes are two lines. This is the C CLI's `fprintf("%s")`.
    let printed: String = got
        .iter()
        .take(2)
        .map(|(_, payload)| String::from_utf8_lossy(payload).into_owned())
        .collect();
    assert_eq!(printed.lines().count(), 2, "{printed:?}");
    Ok(())
}

/// **The attach rule**, on the wire. `dfu-remote/main.c` sets `g_log_client_fd`
/// only around bootstrap (`:422`), write incl. erase and verify (`:515`, `:570`), read
/// (`:658`) and — for every command — HTTP (`:977`).
#[tokio::test]
async fn rpc_log_frames_when() -> TestResult {
    // Raw, DISCOVER: no log and no progress, just the answer.
    let (address, server) = serve(Auth::open(), brisk(), 1, Reply::Chatty);
    let mut client = TcpStream::connect(address).await?;
    client.write_all(&frame(Command::Discover.wire_byte(), b"")).await?;
    let (status, payload) = response(&mut client).await?;
    assert_eq!(
        (status, payload.as_slice()),
        (Status::Ok.wire_byte(), &b"OK"[..]),
        "DISCOVER on raw attaches nothing, so the first frame is the final one"
    );
    drop(client);
    let _events = server.await?;

    // Raw, the three that do attach.
    for command in [Command::Bootstrap, Command::Write, Command::Read] {
        let (address, server) = serve(Auth::open(), brisk(), 1, Reply::Chatty);
        let mut client = TcpStream::connect(address).await?;
        client.write_all(&frame(command.wire_byte(), b"")).await?;
        let got = frames(&mut client, 3).await?;
        assert_eq!(got[0].0, Status::Log.wire_byte(), "{command:?}");
        assert_eq!(got[1].0, Status::Progress.wire_byte(), "{command:?}");
        assert_eq!(got[2].0, Status::Ok.wire_byte(), "{command:?}");
        drop(client);
        let _events = server.await?;
    }

    // Raw, the five that never do.
    for command in [
        Command::Discover,
        Command::Status,
        Command::Cancel,
        Command::Diag,
        Command::Reboot,
    ] {
        let (address, server) = serve(Auth::open(), brisk(), 1, Reply::Chatty);
        let mut client = TcpStream::connect(address).await?;
        client.write_all(&frame(command.wire_byte(), b"")).await?;
        let (status, _) = response(&mut client).await?;
        assert_eq!(status, Status::Ok.wire_byte(), "{command:?} attaches nothing on raw");
        drop(client);
        let _events = server.await?;
    }

    // HTTP attaches for *every* command, DISCOVER included.
    let (address, server) = serve(Auth::open(), brisk(), 1, Reply::Chatty);
    let mut client = TcpStream::connect(address).await?;
    post(&mut client, &frame(Command::Discover.wire_byte(), b""), None).await?;
    let (_, body) = unchunk(&drain(&mut client).await?)?;
    assert_eq!(
        body.get(5).copied(),
        Some(Status::Log.wire_byte()),
        "HTTP attaches for every command"
    );
    let _events = server.await?;
    Ok(())
}
