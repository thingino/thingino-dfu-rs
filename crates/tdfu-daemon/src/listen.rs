//! The listening socket: its options and its backlog.
//!
//! In the library rather than in `main.rs` because it was a private fn in the binary
//! crate and so reachable by **no test at all**, while carrying `IPV6_V6ONLY`
//! cleared, `SO_REUSEADDR`, backlog 1 and two fallbacks. The binary passes
//! [`Options::socket_addrs`](crate::transport::Options::socket_addrs) straight through.

use core::net::SocketAddr;

use tokio::net::{TcpListener, TcpSocket};

/// The backlog, which is the C's (`dfu-remote/main.c:1108`, `listen(fd, 1)`).
///
/// **Kept, and what it costs is measured.** `ss -ltn` shows `Send-Q 1`; with
/// one connection served and two queued, the third, fourth and fifth `connect()` calls
/// all *time out* rather than being refused, because Linux drops the SYN with no RST and
/// retries to `ETIMEDOUT` with no diagnostic anywhere. Raising it to tokio's 1024 would
/// not change "one client at a time" (the serial accept loop is the limiter), only turn a
/// dropped SYN into a queued wait, so it has real merit; it is a **protocol change** and
/// belongs in a commit of its own, not here. Either way a queued client's
/// wait is bounded by no daemon deadline (a 16 MiB flash is around 90 s), and a browser's
/// speculative pre-connect can occupy the served slot for the whole handshake deadline.
const BACKLOG: u32 = 1;

/// Why there is no listening socket.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BindError {
    /// The socket could not be created.
    #[error("cannot open a socket for {address}: {error}")]
    Socket {
        /// Which address was being tried.
        address: SocketAddr,
        /// What the OS said.
        error: std::io::Error,
    },
    /// A socket option could not be set.
    #[error("cannot set up the socket for {address}: {error}")]
    Option {
        /// Which address was being tried.
        address: SocketAddr,
        /// What the OS said.
        error: std::io::Error,
    },
    /// The address could not be bound.
    #[error("cannot bind {address}: {error}")]
    Bind {
        /// Which address was being tried.
        address: SocketAddr,
        /// What the OS said.
        error: std::io::Error,
    },
    /// The socket could not be put into the listening state.
    #[error("cannot listen on {address}: {error}")]
    Listen {
        /// Which address was being tried.
        address: SocketAddr,
        /// What the OS said.
        error: std::io::Error,
    },
    /// There was nothing to try.
    #[error("no address to listen on")]
    Nothing,
}

/// The listening socket, the C's way (`dfu-remote/main.c:1063-1112`): IPv6 first with
/// `IPV6_V6ONLY` cleared so one socket serves both families, IPv4 only where the host has
/// no IPv6 to offer; `SO_REUSEADDR`; backlog [`BACKLOG`].
///
/// `addresses` is tried in order and the **last** entry gets no fallback: silently
/// listening somewhere nobody chose is the failure this is shaped to avoid, so an
/// explicit `--bind` is a one-entry list and its failure is an error.
///
/// "No IPv6 to offer" is the C's condition, `socket(AF_INET6)` failing (`:1069-1073`),
/// plus one it does not handle: the socket opens but the wildcard is not there to bind
/// (`AddrNotAvailable`, IPv6 present but switched off). The C exits on that (`:1102-1106`);
/// here it is the same fallback, said out loud.
///
/// # Errors
/// [`BindError`], naming the address and what the OS said about it.
pub fn bind(addresses: &[SocketAddr]) -> Result<TcpListener, BindError> {
    for (position, address) in addresses.iter().copied().enumerate() {
        // Whether *this* address has another behind it, not whether the list has more
        // than one entry: with three addresses the last one is still the last one, and
        // falling through it would answer "no address to listen on" for a failure that
        // had a cause worth printing.
        let has_fallback = position.saturating_add(1) < addresses.len();
        let no_v6 = |error: std::io::Error| {
            tracing::warn!("IPv6 is unavailable ({error}); listening on IPv4 only");
        };
        let socket = if address.is_ipv6() {
            TcpSocket::new_v6()
        } else {
            TcpSocket::new_v4()
        };
        let socket = match socket {
            Ok(socket) => socket,
            Err(error) if may_fall_back(address, has_fallback) => {
                no_v6(error);
                continue;
            }
            Err(error) => return Err(BindError::Socket { address, error }),
        };
        prepare(&socket, address)?;
        match socket.bind(address) {
            Ok(()) => {}
            Err(error)
                if may_fall_back(address, has_fallback) && error.kind() == std::io::ErrorKind::AddrNotAvailable =>
            {
                no_v6(error);
                continue;
            }
            Err(error) => return Err(BindError::Bind { address, error }),
        }
        return socket
            .listen(BACKLOG)
            .map_err(|error| BindError::Listen { address, error });
    }
    Err(BindError::Nothing)
}

/// May a failure on `address` fall through to the next entry in the list?
///
/// Only for an **IPv6** address, and only when something follows it. A named predicate
/// rather than the expression written twice inside two match guards, because one of the
/// two arms it guards is unreachable on any machine a test runs on: it fires when
/// `socket(AF_INET6)` itself fails (`dfu-remote/main.c:1069-1073`), which needs a kernel
/// with no IPv6 at all, so `cargo mutants` can replace that whole guard with `true` or
/// `false` and nothing observes it. Pulled out here, the **rule** is checkable without
/// the environment, and the `&&` in particular is: under `||` an IPv4 address with a
/// fallback would be skipped instead of reported.
fn may_fall_back(address: SocketAddr, has_fallback: bool) -> bool {
    address.is_ipv6() && has_fallback
}

/// The two options the C sets before it binds: `IPV6_V6ONLY` cleared on a v6 socket
/// (`dfu-remote/main.c:1084-1085`) and `SO_REUSEADDR` on any (`:1079-1080`).
///
/// A function of its own so it can be **pinned**. On a host with the usual
/// `net.ipv6.bindv6only = 0` a freshly created v6 socket already answers
/// `only_v6 == false`, so asserting that on a bound listener passes whether the call was
/// made or not: the line exists precisely for the hosts where the sysctl is 1, which is
/// not the machine the tests run on. The test starts from the opposite value, so only
/// this call can produce the one it asserts.
fn prepare(socket: &TcpSocket, address: SocketAddr) -> Result<(), BindError> {
    if address.is_ipv6() {
        socket2::SockRef::from(socket)
            .set_only_v6(false)
            .map_err(|error| BindError::Option { address, error })?;
    }
    socket
        .set_reuseaddr(true)
        .map_err(|error| BindError::Option { address, error })
}

#[cfg(test)]
mod tests {
    use super::{BindError, bind, may_fall_back, prepare};
    use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use tokio::net::TcpSocket;

    type TestResult = Result<(), Box<dyn core::error::Error>>;

    fn at(ip: IpAddr, port: u16) -> SocketAddr {
        SocketAddr::new(ip, port)
    }

    /// The socket options, **from the opposite starting value**.
    ///
    /// `net.ipv6.bindv6only` is 0 on the machines this runs on, so a v6 socket answers
    /// `only_v6 == false` before anything is set and the obvious assertion on a bound
    /// listener is satisfied by a `bind` that never made the call. `IPV6_V6ONLY` is
    /// turned **on** here first, so only `prepare` can produce the answer asserted;
    /// `SO_REUSEADDR` starts off, which it does everywhere.
    #[tokio::test]
    async fn rpc_the_v6_socket_serves_both_families_and_reuses_the_address() -> TestResult {
        let socket = TcpSocket::new_v6()?;
        socket2::SockRef::from(&socket).set_only_v6(true)?;
        assert!(!socket.reuseaddr()?, "SO_REUSEADDR is off until it is asked for");

        prepare(&socket, at(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0))?;
        assert!(
            !socket2::SockRef::from(&socket).only_v6()?,
            "IPV6_V6ONLY must be cleared, or an IPv4 client cannot reach the daemon"
        );
        assert!(socket.reuseaddr()?, "SO_REUSEADDR, before bind");

        // An IPv4 socket takes only the second: `IPV6_V6ONLY` on one is `EINVAL`, and
        // `prepare` returning an error here would make every v4 fallback fail to bind.
        let v4 = TcpSocket::new_v4()?;
        prepare(&v4, at(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))?;
        assert!(v4.reuseaddr()?);

        // And the whole of `bind` really does go through it.
        let listener = bind(&[at(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)])?;
        let bound = listener.local_addr()?;
        assert!(bound.is_ipv6(), "{bound}");
        assert_ne!(bound.port(), 0, "the OS handed out a real port");
        assert!(socket2::SockRef::from(&listener).reuse_address()?);
        Ok(())
    }

    /// `dfu-remote/main.c:1069-1073`: IPv4 is the fallback where IPv6 is not there.
    ///
    /// The first address is in the documentation prefix, so no host has it: on a machine
    /// with IPv6 the `bind` fails with `AddrNotAvailable` (the branch the C does not
    /// have), and on one without it `socket(AF_INET6)` fails (the branch it does).
    /// Either way the fallback is what is exercised, and the listener that comes back is
    /// the IPv4 one.
    #[tokio::test]
    async fn an_unbindable_v6_address_falls_back_to_v4() -> TestResult {
        let unreachable: SocketAddr = "[2001:db8::1]:0".parse()?;
        let listener = bind(&[unreachable, at(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)])?;
        let bound = listener.local_addr()?;
        assert!(bound.is_ipv4(), "the fallback was not taken: {bound}");
        assert_eq!(bound.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        Ok(())
    }

    /// The **last** address gets no fallback: an explicit `--bind` that cannot be bound
    /// is an error, because listening somewhere else instead is the bug.
    #[tokio::test]
    async fn the_last_address_has_no_fallback() -> TestResult {
        let unreachable: SocketAddr = "[2001:db8::1]:0".parse()?;
        let error = match bind(&[unreachable]) {
            Err(error) => error.to_string(),
            Ok(listener) => format!("expected a refusal, bound {:?}", listener.local_addr()),
        };
        assert!(
            error.contains("2001:db8::1"),
            "the address is part of the fact: {error}"
        );
        assert!(
            error.contains("cannot bind") || error.contains("cannot open a socket"),
            "{error}"
        );

        // And with two addresses, neither of which can be bound, the failure that comes
        // back is the **last one's**, not `Nothing`. Whether an address has a fallback is
        // a property of its position, not of the list being longer than one.
        let elsewhere: SocketAddr = "[2001:db8::2]:0".parse()?;
        let error = match bind(&[unreachable, elsewhere]) {
            Err(error) => error.to_string(),
            Ok(listener) => format!("expected a refusal, bound {:?}", listener.local_addr()),
        };
        assert!(error.contains("2001:db8::2"), "{error}");
        assert_ne!(error, BindError::Nothing.to_string(), "the cause is the news");
        Ok(())
    }

    /// A port already in use is refused loudly, not worked around.
    #[tokio::test]
    async fn a_port_in_use_is_an_error_naming_it() -> TestResult {
        let held = bind(&[at(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)])?;
        let taken = held.local_addr()?;
        // `SO_REUSEADDR` lets a socket rebind a port in `TIME_WAIT`; it does not let two
        // listeners share a live one, and `SO_REUSEPORT` is deliberately not set.
        let error = match bind(&[taken]) {
            Err(error) => error.to_string(),
            Ok(second) => format!("two listeners on {:?}", second.local_addr()),
        };
        assert!(error.contains(&taken.port().to_string()), "{error}");
        Ok(())
    }

    /// Both halves of the fallback rule, without needing a host that lacks IPv6.
    ///
    /// The socket-creation arm this guards cannot be entered on a machine with a working
    /// IPv6 stack, so `cargo mutants` replaces the guard there and nothing notices. The
    /// rule itself is checkable, and the `&&` matters: under `||` an IPv4 address with a
    /// fallback behind it would be skipped in silence instead of reported.
    #[test]
    fn only_an_ipv6_address_with_something_behind_it_falls_back() {
        let v6 = at(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0);
        let v4 = at(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
        assert!(may_fall_back(v6, true));
        assert!(!may_fall_back(v6, false), "the last address has nowhere to go");
        assert!(!may_fall_back(v4, true), "an IPv4 failure is not a host without IPv6");
        assert!(!may_fall_back(v4, false));
    }

    #[test]
    fn nothing_to_listen_on_says_so() {
        let error = match bind(&[]) {
            Err(error) => error.to_string(),
            Ok(_) => "expected a refusal".to_owned(),
        };
        assert_eq!(error, BindError::Nothing.to_string());
    }
}
