//! The daemon's command line.
//!
//! **Nothing is accepted quietly and nothing is guessed**, which is the whole reason this
//! file has tests: the C parses `-p` with `atoi`
//! (`dfu-remote/main.c:1036`), so `-p abc` becomes port **0** and the daemon binds an
//! ephemeral port while printing `listening on port 0`, and `-p 70000` becomes **4464**
//! when `htons` truncates it (`:1089`). Its argument loop has no `else`
//! (`:1034-1047`), so an unknown or misspelled flag is ignored in silence. An earlier
//! implementation reproduced all three and **pinned them as correct with a test**.
//!
//! Two other shapes of the same bug, fixed here:
//!
//! * `-p` as the last argument is skipped by the C's `&& i + 1 < argc` guard, so a
//!   typo'd invocation silently runs with defaults.
//! * The startup line prints the port that was *asked for*. [`Options::startup_lines`]
//!   takes the address actually bound, so the number on screen is the number a client
//!   must dial.
//!
//! The additions here, `--bind` and the timeouts, are additions only:
//! no default the C set is changed, because no client can be broken by a flag it does
//! not pass. The timeout *defaults* are new behaviour and deliberately so; see
//! [`Timeouts`].

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use core::time::Duration;
use std::path::PathBuf;

use super::origin::{OriginError, Origins};
use super::wire::Timeouts;

/// The longest timeout an operator may ask for: a day.
const MAX_TIMEOUT_SECS: u64 = 86_400;

/// Which interfaces to listen on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BindAddr {
    /// All of them. The C's default and ours: it opens `AF_INET6` with `IPV6_V6ONLY`
    /// cleared so one socket serves both families, and falls back to `AF_INET` only
    /// where IPv6 is unavailable (`dfu-remote/main.c:1069-1100`).
    #[default]
    Any,
    /// One address, because the operator asked. **An addition**: the C's
    /// own comment calls binding every interface a "TODO Tier 2 posture".
    Only(IpAddr),
}

/// What the daemon was told to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    /// Which interfaces. An addition.
    pub bind: BindAddr,
    /// Which port. Default 5050 (`TDFU_DEFAULT_PORT`).
    pub port: u16,
    /// Where the loaders are. Default: `firmware/` beside the binary.
    pub firmware_dir: PathBuf,
    /// The `--token` secret, if any.
    pub token: Option<String>,
    /// `-d`/`--debug`.
    pub debug: bool,
    /// The deadlines. An addition, on by default.
    pub timeouts: Timeouts,
    /// Which browser origins may drive the daemon. An addition, and the only one that
    /// refuses something the C served: a page on an origin nobody named.
    pub origins: Origins,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            bind: BindAddr::Any,
            port: tdfu_proto::DEFAULT_PORT,
            firmware_dir: default_firmware_dir(),
            token: None,
            debug: false,
            timeouts: Timeouts::DEFAULT,
            origins: Origins::SHIPPED,
        }
    }
}

/// What a successful parse produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Parsed {
    /// `-h`/`--help`: print this and exit 0.
    Help(String),
    /// Run with these.
    Run(Box<Options>),
}

/// Why a command line was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum OptionsError {
    /// An argument nothing recognises.
    #[error("unrecognised argument `{0}`")]
    Unknown(String),
    /// A flag that takes a value, given none.
    #[error("`{0}` needs a value")]
    MissingValue(&'static str),
    /// A value that cannot mean what it would have to mean.
    #[error("`{flag} {value}` is not usable: {why}")]
    BadValue {
        /// Which flag.
        flag: &'static str,
        /// What was given, verbatim: the number that did not work is the one the
        /// operator needs to see.
        value: String,
        /// In words.
        why: &'static str,
    },
    /// An `--allow-origin` value that is not an origin.
    #[error("`--allow-origin` was given a value that is not one: {0}")]
    BadOrigin(#[from] OriginError),
}

impl Options {
    /// Parse the arguments **after** the program name.
    ///
    /// # Errors
    /// [`OptionsError`] for anything unrecognised, valueless or unusable. Nothing is
    /// silently defaulted and nothing is silently truncated.
    pub fn parse<I, S>(args: I) -> Result<Parsed, OptionsError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut options = Self::default();
        let mut args = args.into_iter().map(Into::into).peekable();
        // Collected rather than folded in one at a time, because `--allow-any-origin`
        // wins over the list whichever order the two are written in.
        let mut allowed_origins: Vec<String> = Vec::new();
        let mut any_origin = false;

        while let Some(argument) = args.next() {
            let (flag, inline) = match argument.split_once('=') {
                Some((flag, value)) if flag.starts_with("--") => (flag.to_owned(), Some(value.to_owned())),
                _ => (argument.clone(), None),
            };
            let mut value = |name: &'static str| -> Result<String, OptionsError> {
                inline
                    .clone()
                    .or_else(|| args.next())
                    .ok_or(OptionsError::MissingValue(name))
            };

            match flag.as_str() {
                "-p" | "--port" => options.port = parse_port(&value("--port")?)?,
                "--bind" => options.bind = parse_bind(&value("--bind")?)?,
                "--firmware-dir" => {
                    let dir = value("--firmware-dir")?;
                    if dir.is_empty() {
                        return Err(OptionsError::BadValue {
                            flag: "--firmware-dir",
                            value: dir,
                            why: "an empty path names nothing",
                        });
                    }
                    options.firmware_dir = PathBuf::from(dir);
                }
                "--token" => {
                    let token = value("--token")?;
                    if token.is_empty() {
                        return Err(OptionsError::BadValue {
                            flag: "--token",
                            value: token,
                            why: "an empty token would have to be sent by every client; \
                                  omit --token to require none",
                        });
                    }
                    options.token = Some(token);
                }
                "--handshake-timeout" => {
                    options.timeouts.handshake = parse_timeout("--handshake-timeout", &value("--handshake-timeout")?)?;
                }
                "--read-timeout" => {
                    options.timeouts.read = parse_timeout("--read-timeout", &value("--read-timeout")?)?;
                }
                "--idle-timeout" => {
                    options.timeouts.idle = parse_timeout("--idle-timeout", &value("--idle-timeout")?)?;
                }
                "--allow-origin" => allowed_origins.push(value("--allow-origin")?),
                "--allow-any-origin" => any_origin = true,
                "-d" | "--debug" => options.debug = true,
                "-h" | "--help" => return Ok(Parsed::Help(usage())),
                other => return Err(OptionsError::Unknown(other.to_owned())),
            }
        }
        options.origins = if any_origin {
            // `--allow-any-origin` wins over any list: an operator who asked for both
            // asked for the wider of the two, and refusing the combination would refuse
            // a command line that means something.
            Origins::any()
        } else {
            // Checked here, at the command line, so a misspelled origin is a refusal the
            // operator reads at once rather than a list entry that silently never
            // matches and a page refused for no stated reason.
            Origins::extended(&allowed_origins)?
        };
        Ok(Parsed::Run(Box::new(options)))
    }

    /// Parse this process's arguments.
    ///
    /// # Errors
    /// As [`Options::parse`].
    pub fn from_env() -> Result<Parsed, OptionsError> {
        Self::parse(std::env::args().skip(1))
    }

    /// The addresses to try binding, in order (`dfu-remote/main.c:1069-1100`).
    ///
    /// `BindAddr::Any` yields the IPv6 wildcard first — one socket serves both families
    /// with `IPV6_V6ONLY` cleared — and the IPv4 wildcard as the fallback for a host
    /// with no IPv6 at all.
    #[must_use]
    pub fn socket_addrs(&self) -> Vec<SocketAddr> {
        match self.bind {
            BindAddr::Any => vec![
                SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), self.port),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), self.port),
            ],
            BindAddr::Only(address) => vec![SocketAddr::new(address, self.port)],
        }
    }

    /// What the daemon prints on startup.
    ///
    /// Takes the address **actually bound**, which is the half a parser cannot reach on
    /// its own: an earlier implementation printed `listening on port 0` while listening
    /// on 35319.
    ///
    /// The address, the token and the origin list are all stated, because every one of
    /// them is a thing an operator can be wrong about: the wire carries no TLS, `[::]`
    /// means the daemon is reachable from the whole network, and a daemon with no token
    /// will flash a camera for anybody who can reach it.
    #[must_use]
    pub fn startup_lines(&self, bound: SocketAddr) -> Vec<String> {
        let token = if self.token.is_some() {
            "Token: required".to_owned()
        } else {
            "Token: none, so any client that can reach this port may flash the camera".to_owned()
        };
        vec![
            format!("dfu-remote listening on port {}", bound.port()),
            format!("Bound to {bound}"),
            format!("Firmware directory: {}", self.firmware_dir.display()),
            token,
            format!("Browser origins: {}", self.origins.describe()),
        ]
    }

    /// The `Auth` these options describe.
    #[must_use]
    pub fn auth(&self) -> crate::auth::Auth {
        self.token.as_ref().map_or_else(crate::auth::Auth::open, |token| {
            crate::auth::Auth::with_token(token.as_str())
        })
    }

    /// The origin allow list these options describe.
    #[must_use]
    pub fn origins(&self) -> Origins {
        self.origins.clone()
    }
}

/// `firmware/` beside this binary, resolved through `/proc/self/exe` as the C does
/// (`dfu-remote/main.c:1004-1028`), falling back to `./firmware`.
fn default_firmware_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join("firmware")))
        .unwrap_or_else(|| PathBuf::from("./firmware"))
}

/// A port, refusing everything `atoi` would swallow.
fn parse_port(value: &str) -> Result<u16, OptionsError> {
    let bad = |why| OptionsError::BadValue {
        flag: "--port",
        value: value.to_owned(),
        why,
    };
    let number: u32 = value.parse().map_err(|_| bad("not a number"))?;
    let port = u16::try_from(number).map_err(|_| bad("above 65535; the C wrapped this to a different port"))?;
    if port == 0 {
        // A daemon on an ephemeral port is a daemon no client can find, and printing
        // the requested `0` while listening elsewhere is exactly the lie bug 21 was.
        return Err(bad(
            "port 0 asks the OS for an ephemeral port, which no client can dial",
        ));
    }
    Ok(port)
}

/// An address for `--bind`.
fn parse_bind(value: &str) -> Result<BindAddr, OptionsError> {
    value
        .parse::<IpAddr>()
        .map(BindAddr::Only)
        .map_err(|_| OptionsError::BadValue {
            flag: "--bind",
            value: value.to_owned(),
            why: "not an IP address; use 127.0.0.1, ::1 or an interface address",
        })
}

/// Seconds, where `0` means off.
fn parse_timeout(flag: &'static str, value: &str) -> Result<Option<Duration>, OptionsError> {
    let bad = |why| OptionsError::BadValue {
        flag,
        value: value.to_owned(),
        why,
    };
    let seconds: u64 = value.parse().map_err(|_| bad("not a whole number of seconds"))?;
    if seconds > MAX_TIMEOUT_SECS {
        return Err(bad("longer than a day; use 0 to switch the deadline off"));
    }
    Ok((seconds > 0).then(|| Duration::from_secs(seconds)))
}

/// The `-h` text: the options, then the three deadlines and what `0` means.
fn usage() -> String {
    format!(
        "dfu-remote - thingino-dfu remote daemon\n\
         Usage: dfu-remote [options]\n\
         \n\
         Options:\n\
         \x20 -p, --port <port>         Listen port (default: {default_port})\n\
         \x20     --firmware-dir <dir>  Firmware root directory (default: firmware/ beside the binary)\n\
         \x20     --token <secret>      Require an auth token from clients\n\
         \x20     --bind <address>      Listen on one address only (default: every interface)\n\
         \x20     --allow-origin <url>  Also serve browser pages from this origin (repeatable)\n\
         \x20     --allow-any-origin    Serve a browser page from any origin at all\n\
         \x20 -d, --debug               Enable debug output\n\
         \x20 -h, --help                Show this help\n\
         \n\
         Who can reach it:\n\
         \x20 The wire is plain: there is no TLS, and no client needs a token unless\n\
         \x20 --token is given. With no --bind the daemon answers on every interface, so\n\
         \x20 anyone who can reach the port can read or write the camera's flash; use\n\
         \x20 --bind 127.0.0.1 for anything but a network you trust.\n\
         \x20 A browser page reaches it too. Pages served from {origins}\n\
         \x20 are answered; any other page is refused.\n\
         \n\
         Deadlines:\n\
         \x20     --handshake-timeout <s>  Give up on a connection that says nothing (default: {handshake})\n\
         \x20     --read-timeout <s>       Give up after this long with no progress on a read or a write (default: {read})\n\
         \x20     --idle-timeout <s>       Close a connection idle this long between commands (default: {idle})\n\
         \n\
         A timeout of 0 switches that deadline off. All three are on by default, so one\n\
         client that connects and makes no progress cannot wedge every other client.\n",
        default_port = tdfu_proto::DEFAULT_PORT,
        origins = Origins::SHIPPED.describe(),
        handshake = seconds(Timeouts::DEFAULT.handshake),
        read = seconds(Timeouts::DEFAULT.read),
        idle = seconds(Timeouts::DEFAULT.idle),
    )
}

/// `"10s"`, or `"off"`.
fn seconds(value: Option<Duration>) -> String {
    value.map_or_else(|| "off".to_owned(), |duration| format!("{}s", duration.as_secs()))
}

#[cfg(test)]
mod tests {
    use super::{BindAddr, Options, OptionsError, Parsed, Timeouts};
    use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use core::time::Duration;
    use std::path::{Path, PathBuf};

    /// A test that can fail on its own return value rather than on a `panic!` — the
    /// workspace denies `clippy::panic`, `unwrap_used` and `expect_used` in tests too
    /// workspace-wide.
    type TestResult = Result<(), OptionsError>;

    /// Parse, insisting on a runnable configuration.
    fn run(args: &[&str]) -> Result<Options, OptionsError> {
        match Options::parse(args.iter().copied())? {
            Parsed::Run(options) => Ok(*options),
            Parsed::Help(_) => Err(OptionsError::Unknown("expected a run, got help".to_owned())),
        }
    }

    /// Parse, insisting on a refusal. A sentinel rather than a panic: it fails the
    /// `matches!` every caller applies to it.
    fn bad(args: &[&str]) -> OptionsError {
        match Options::parse(args.iter().copied()) {
            Err(error) => error,
            Ok(_) => OptionsError::Unknown("expected a refusal, got a valid parse".to_owned()),
        }
    }

    /// A socket address without a fallible parse.
    fn at(ip: IpAddr, port: u16) -> SocketAddr {
        SocketAddr::new(ip, port)
    }

    /// The defaults.
    #[test]
    fn rpc_daemon_options() -> TestResult {
        let options = run(&[])?;
        assert_eq!(options.port, 5050, "TDFU_DEFAULT_PORT");
        assert_eq!(options.bind, BindAddr::Any);
        assert_eq!(options.token, None, "no --token means no handshake");
        assert!(!options.debug);
        assert!(options.firmware_dir.ends_with("firmware"));
        // **Beside the binary**, not `./firmware`. `ends_with("firmware")`
        // is true of the `current_exe` path and of the fallback alike, so on its own it
        // pins nothing: `default_firmware_dir` could collapse to its `unwrap_or_else` and
        // no test would notice, while the rule is `/proc/self/exe`.
        assert_eq!(
            options.firmware_dir.parent().map(Path::to_path_buf),
            std::env::current_exe()
                .ok()
                .and_then(|exe| exe.parent().map(Path::to_path_buf)),
            "the default is firmware/ beside the running binary"
        );

        let options = run(&["-p", "6000", "--firmware-dir", "/srv/fw", "--token", "s3cr3t", "-d"])?;
        assert_eq!(options.port, 6000);
        assert_eq!(options.firmware_dir, PathBuf::from("/srv/fw"));
        assert_eq!(options.token.as_deref(), Some("s3cr3t"));
        assert!(options.debug);

        // The long forms, and `--flag=value`.
        let options = run(&["--port=7000", "--token=abc", "--debug"])?;
        assert_eq!(options.port, 7000);
        assert_eq!(options.token.as_deref(), Some("abc"));
        assert!(options.debug);

        assert!(matches!(Options::parse(["-h"])?, Parsed::Help(_)));
        assert!(matches!(Options::parse(["--help"])?, Parsed::Help(_)));
        Ok(())
    }

    /// **Every branch of the quiet-coercion bug.** An earlier implementation pinned all
    /// of this as correct.
    #[test]
    fn garbage_is_refused_loudly() {
        // `atoi("abc")` is 0, and the C then bound an ephemeral port while printing
        // `listening on port 0`.
        let error = bad(&["-p", "abc"]);
        assert!(
            matches!(&error, OptionsError::BadValue { flag: "--port", .. }),
            "{error}"
        );
        assert!(error.to_string().contains("abc"), "{error}");
        assert!(error.to_string().contains("not a number"), "{error}");

        // `htons(70000)` is 4464. Silently.
        let error = bad(&["-p", "70000"]);
        assert!(
            matches!(&error, OptionsError::BadValue { flag: "--port", .. }),
            "{error}"
        );
        assert!(error.to_string().contains("70000"), "{error}");
        assert!(error.to_string().contains("65535"), "{error}");

        // Port 0 is the ephemeral-port lie itself.
        let error = bad(&["--port", "0"]);
        assert!(error.to_string().contains("ephemeral"), "{error}");

        // The C's argument loop has no `else`, so this ran with defaults.
        assert_eq!(
            bad(&["--firmware-directory", "/srv/fw"]),
            OptionsError::Unknown("--firmware-directory".to_owned())
        );
        assert_eq!(bad(&["-x"]), OptionsError::Unknown("-x".to_owned()));
        assert_eq!(bad(&["stray"]), OptionsError::Unknown("stray".to_owned()));

        // The C's `&& i + 1 < argc` guard drops a trailing flag in silence.
        assert_eq!(bad(&["-p"]), OptionsError::MissingValue("--port"));
        assert_eq!(bad(&["--token"]), OptionsError::MissingValue("--token"));
        assert_eq!(bad(&["--firmware-dir"]), OptionsError::MissingValue("--firmware-dir"));

        // Negative, decimal and padded ports are not ports.
        for value in ["-1", "80.5", "", " 80", "0x50", "5050\n"] {
            assert!(
                matches!(bad(&["-p", value]), OptionsError::BadValue { flag: "--port", .. }),
                "-p {value:?} was not refused"
            );
        }

        // `-p=5050` is not a long option. The `flag.starts_with("--")` guard is the only
        // thing stopping a short flag being split on `=`, and asserting the exact value
        // matters: `bad()`'s own sentinel is an `Unknown`, so `matches!(.., Unknown(_))`
        // would pass whether the guard worked or not.
        assert_eq!(bad(&["-p=5050"]), OptionsError::Unknown("-p=5050".to_owned()));
        assert_eq!(bad(&["-d=yes"]), OptionsError::Unknown("-d=yes".to_owned()));

        // An empty token or firmware directory is a typo, not a request.
        assert!(matches!(
            bad(&["--token", ""]),
            OptionsError::BadValue { flag: "--token", .. }
        ));
        assert!(matches!(
            bad(&["--firmware-dir", ""]),
            OptionsError::BadValue {
                flag: "--firmware-dir",
                ..
            }
        ));
    }

    /// A flag may be added, never a default changed.
    #[test]
    fn the_additions_are_additions() -> TestResult {
        let options = run(&["--bind", "127.0.0.1"])?;
        assert_eq!(options.bind, BindAddr::Only(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert_eq!(options.port, 5050, "an addition changed no default");
        assert_eq!(options.timeouts, Timeouts::DEFAULT);

        let options = run(&["--bind", "::1"])?;
        assert_eq!(options.bind, BindAddr::Only(IpAddr::V6(Ipv6Addr::LOCALHOST)));

        assert!(matches!(
            bad(&["--bind", "not-an-address"]),
            OptionsError::BadValue { flag: "--bind", .. }
        ));
        // A host name is not an address: resolving one at bind time is how a daemon ends
        // up listening somewhere nobody chose.
        assert!(matches!(bad(&["--bind", "localhost"]), OptionsError::BadValue { .. }));

        let options = run(&[
            "--idle-timeout",
            "30",
            "--read-timeout",
            "5",
            "--handshake-timeout",
            "1",
        ])?;
        assert_eq!(options.timeouts.idle, Some(Duration::from_secs(30)));
        assert_eq!(options.timeouts.read, Some(Duration::from_secs(5)));
        assert_eq!(options.timeouts.handshake, Some(Duration::from_secs(1)));

        // 0 is off, and asking for it is the only way to get the C's posture back.
        let options = run(&["--idle-timeout", "0"])?;
        assert_eq!(options.timeouts.idle, None);
        assert!(
            options.timeouts.read.is_some(),
            "one off does not switch the others off"
        );
        assert!(options.timeouts.handshake.is_some());

        assert!(matches!(
            bad(&["--idle-timeout", "forever"]),
            OptionsError::BadValue {
                flag: "--idle-timeout",
                ..
            }
        ));
        // Exactly a day is allowed: the refusal is `>`, not `>=`. This project has been
        // bitten by that distinction on the wire already (the payload cap), so the
        // boundary is pinned from both sides.
        assert_eq!(
            run(&["--read-timeout", "86400"])?.timeouts.read,
            Some(Duration::from_secs(86_400))
        );
        assert!(matches!(
            bad(&["--read-timeout", "86401"]),
            OptionsError::BadValue { .. }
        ));
        assert!(matches!(bad(&["--read-timeout", "-5"]), OptionsError::BadValue { .. }));
        Ok(())
    }

    /// `dfu-remote/main.c:1069-1100`: IPv6 first with `IPV6_V6ONLY` cleared, IPv4 as the
    /// fallback.
    #[test]
    fn the_bind_order_is_v6_then_v4() -> TestResult {
        let any = run(&["-p", "5050"])?;
        assert_eq!(
            any.socket_addrs(),
            vec![
                at(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 5050),
                at(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 5050),
            ]
        );

        let one = run(&["--bind", "127.0.0.1", "-p", "5051"])?;
        assert_eq!(
            one.socket_addrs(),
            vec![at(IpAddr::V4(Ipv4Addr::LOCALHOST), 5051)],
            "an explicit address gets no fallback: silently listening somewhere else is the bug"
        );
        Ok(())
    }

    /// The other half of bug 21: the number printed must be the number bound.
    #[test]
    fn the_startup_line_names_the_port_actually_bound() -> TestResult {
        let options = run(&["-p", "5050"])?;
        let lines = options.startup_lines(at(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 35_319));
        assert_eq!(lines[0], "dfu-remote listening on port 35319");
        assert!(!lines[0].contains("5050"), "the requested port is not the news");
        assert_eq!(lines[1], "Bound to [::]:35319", "which interfaces, always");
        assert!(lines[2].starts_with("Firmware directory: "), "{}", lines[2]);

        let options = run(&["--bind", "127.0.0.1"])?;
        let lines = options.startup_lines(at(IpAddr::V4(Ipv4Addr::LOCALHOST), 5050));
        assert_eq!(lines[1], "Bound to 127.0.0.1:5050");
        Ok(())
    }

    /// **What the operator is told about their own posture.** Three things an operator
    /// can be wrong about: which interfaces answer, whether a token is needed, and which
    /// browser pages are served. All three are on screen at startup.
    #[test]
    fn the_startup_lines_state_the_posture() -> TestResult {
        let open = run(&[])?.startup_lines(at(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 5050));
        let text = open.join("\n");
        assert!(text.contains("Bound to [::]:5050"), "{text}");
        assert!(text.contains("Token: none"), "a daemon with no token says so: {text}");
        assert!(text.contains("may flash the camera"), "{text}");
        assert!(text.contains("Browser origins: "), "{text}");
        assert!(text.contains("https://webflash.thingino.com"), "{text}");

        let guarded = run(&["--token", "s3cr3t"])?.startup_lines(at(IpAddr::V4(Ipv4Addr::LOCALHOST), 5050));
        let text = guarded.join("\n");
        assert!(text.contains("Token: required"), "{text}");
        assert!(!text.contains("s3cr3t"), "the token is never printed: {text}");

        let wide = run(&["--allow-any-origin"])?.startup_lines(at(IpAddr::V4(Ipv4Addr::LOCALHOST), 5050));
        assert!(wide.join("\n").contains("any page"), "{wide:?}");
        Ok(())
    }

    /// `--allow-origin` and `--allow-any-origin`: what they build, and what they refuse.
    #[test]
    fn the_origin_flags_build_the_list() -> TestResult {
        let shipped = run(&[])?.origins();
        assert!(shipped.decide(Some("https://webflash.thingino.com")).is_allowed());
        assert!(!shipped.decide(Some("https://flash.example.test")).is_allowed());
        assert!(!shipped.allows_any(), "the default checks");

        let extended = run(&["--allow-origin", "https://flash.example.test"])?.origins();
        assert!(extended.decide(Some("https://flash.example.test")).is_allowed());
        assert!(!extended.decide(Some("https://other.example")).is_allowed());

        // Repeatable, and both entries survive.
        let two = run(&["--allow-origin", "https://a.test", "--allow-origin=https://b.test:8443"])?.origins();
        assert!(two.decide(Some("https://a.test")).is_allowed());
        assert!(two.decide(Some("https://b.test:8443")).is_allowed());

        // The escape hatch, and it wins whichever order it is written in.
        assert!(run(&["--allow-any-origin"])?.origins().allows_any());
        assert!(
            run(&["--allow-any-origin", "--allow-origin", "https://a.test"])?
                .origins()
                .allows_any()
        );

        // A value that is not an origin is refused at the command line, naming itself:
        // a list entry that can never match is a page refused for no stated reason.
        let error = bad(&["--allow-origin", "flash.example.test"]);
        assert!(matches!(error, OptionsError::BadOrigin(_)), "{error}");
        assert!(error.to_string().contains("flash.example.test"), "{error}");
        assert!(matches!(
            bad(&["--allow-origin", "https://a.test/"]),
            OptionsError::BadOrigin(_)
        ));
        assert_eq!(bad(&["--allow-origin"]), OptionsError::MissingValue("--allow-origin"));
        Ok(())
    }

    /// The last of a repeated flag wins, as it does in the C.
    #[test]
    fn a_repeated_flag_takes_the_last_value() -> TestResult {
        let options = run(&["-p", "5050", "--port", "6000"])?;
        assert_eq!(options.port, 6000);
        Ok(())
    }

    #[test]
    fn options_produce_the_auth_they_describe() -> TestResult {
        assert!(!run(&[])?.auth().is_required());
        assert!(run(&["--token", "x"])?.auth().is_required());
        Ok(())
    }

    #[test]
    fn the_help_text_names_every_flag() -> TestResult {
        let Parsed::Help(text) = Options::parse(["-h"])? else {
            return Err(OptionsError::Unknown("expected help".to_owned()));
        };
        for flag in [
            "--port",
            "--firmware-dir",
            "--token",
            "--debug",
            "--help",
            "--bind",
            "--handshake-timeout",
            "--read-timeout",
            "--idle-timeout",
            "--allow-origin",
            "--allow-any-origin",
        ] {
            assert!(text.contains(flag), "help does not mention {flag}");
        }
        // **What the defaults expose.** The help said what the deadlines protect against
        // and nothing about the wire being plaintext, unauthenticated and answering on
        // every interface, so an operator reading it could conclude the defaults were
        // safe on a shared network.
        assert!(text.contains("no TLS"), "the help states the wire is plain: {text}");
        assert!(text.contains("unless\n"), "{text}");
        assert!(text.contains("--token"), "{text}");
        assert!(text.contains("--bind 127.0.0.1"), "{text}");
        assert!(
            text.contains("https://webflash.thingino.com"),
            "the help names the origins it serves: {text}"
        );
        assert!(text.contains("5050"), "the default port is part of the help");
        assert!(text.contains("10s"), "the default handshake timeout is stated");
        // The same value bounds every **write** (`Wire::write_all` uses
        // `Timeouts::read`), so `--read-timeout 0` switches the write bound off too. The
        // doc comment on `Timeouts::read` said so; the operator-facing string did not.
        assert!(
            text.contains("on a read or a write"),
            "--read-timeout bounds writes too, and the help has to say so: {text}"
        );
        Ok(())
    }
}
