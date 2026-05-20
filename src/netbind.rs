//! Bind outgoing sockets to a specific network interface — the VPN kill
//! switch. If the bound interface goes away (tunnel drops), the socket
//! `connect()` fails closed instead of falling back to the default route.
//!
//! Platform mapping:
//! - **macOS, \*BSD**: `IP_BOUND_IF` setsockopt with the interface index.
//! - **Linux**: `SO_BINDTODEVICE` setsockopt with the interface name
//!   (requires CAP_NET_RAW or being root, OR a recent enough kernel where
//!   the cap was relaxed for the `bind` path; see ip(7)).
//! - **Windows**: `IP_UNICAST_IF` setsockopt with the interface index.
//!
//! We accept the interface as a *name* string (`"utun0"`, `"en0"`, `"eth0"`)
//! and resolve it to the right form per-platform.
//!
//! Library substrate: `socket2` provides the platform-uniform setsockopt
//! wrapper plus interface-name → index lookup on macOS/BSD/Windows. We feed
//! the resulting bound socket into `tokio::net::TcpStream::from_std`.

use std::io;
use std::net::SocketAddr;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::TcpStream;

/// Connect to `target` with the outgoing socket bound to interface `iface`.
///
/// Returns an `io::Error` if the interface doesn't exist or is down (the
/// kill-switch guarantee: we never silently fall back to the default route).
///
/// Implementation: build a `socket2::Socket`, apply the per-platform
/// bind-to-interface setsockopt, connect synchronously (so kill-switch
/// failures surface here rather than mid-handshake), then switch to
/// non-blocking and hand the std socket to tokio.
pub async fn connect_via_interface(target: SocketAddr, iface: &str) -> io::Result<TcpStream> {
    let domain = if target.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    // `spawn_blocking` keeps the synchronous connect off the async runtime —
    // the connect can take up to a few seconds for a remote peer.
    let iface = iface.to_string();
    tokio::task::spawn_blocking(move || {
        let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
        bind_socket_to_interface(&socket, &iface, target.is_ipv4())?;
        let _ = socket.set_tcp_nodelay(true);
        socket.connect(&target.into())?;
        socket.set_nonblocking(true)?;
        let std_stream: std::net::TcpStream = socket.into();
        TcpStream::from_std(std_stream)
    })
    .await
    .map_err(|e| io::Error::other(format!("join error: {e}")))?
}

/// Apply the per-platform setsockopt that binds `socket` to `iface`.
///
/// On Linux/Android we pass the interface *name* via SO_BINDTODEVICE.
/// On macOS/BSD we resolve `iface` to its kernel index via libc and pass it
/// to IP_BOUND_IF / IPV6_BOUND_IF. Windows is intentionally unsupported in
/// this first cut — `IP_UNICAST_IF` needs a raw setsockopt and a different
/// index byte-order, which is left for a follow-up.
#[allow(unused_variables)] // `socket`/`is_v4` are only read on Unix codepaths
fn bind_socket_to_interface(socket: &Socket, iface: &str, is_v4: bool) -> io::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        // SO_BINDTODEVICE takes the interface name as a C string.
        socket.bind_device(Some(iface.as_bytes()))?;
        Ok(())
    }
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
    ))]
    {
        // IP_BOUND_IF / IPV6_BOUND_IF take an interface *index*.
        let idx = if_nametoindex(iface)?;
        if is_v4 {
            socket.bind_device_by_index_v4(std::num::NonZeroU32::new(idx))?;
        } else {
            socket.bind_device_by_index_v6(std::num::NonZeroU32::new(idx))?;
        }
        Ok(())
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
    )))]
    {
        let _ = iface;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "--bind-iface not yet implemented on this platform \
             (Linux/macOS/BSD only — see SECURITY_ROADMAP.md)",
        ))
    }
}

/// Resolve `iface` (e.g. "utun0", "en0") to its interface index via libc.
/// Only compiled on the macOS/BSD-style platforms that need the index for
/// the IP_BOUND_IF setsockopt path.
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
))]
fn if_nametoindex(iface: &str) -> io::Result<u32> {
    use std::ffi::CString;
    let c = CString::new(iface)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "interface name contains NUL"))?;
    // SAFETY: if_nametoindex reads a null-terminated string and returns
    // an unsigned int. We pass a valid C string with a trailing NUL.
    let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
    if idx == 0 {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("interface {iface} not found"),
        ));
    }
    Ok(idx)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_interface_is_rejected() {
        // Pick a name guaranteed not to exist. On all platforms we expect
        // an error rather than a silent fallback.
        let res = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(connect_via_interface(
                "127.0.0.1:1".parse().unwrap(),
                "rt_nonexistent_iface_xyz123",
            ));
        assert!(res.is_err(), "expected error for missing interface");
    }
}
