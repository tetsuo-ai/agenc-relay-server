//! Socket sources and their binding rules (spec 8.5, lines 548-568;
//! spec 25.1, lines 6659-6662).
//!
//! A TCP source binds a literal unicast address; a Unix source binds a
//! daemon-owned socket inside a directory of mode 0750 and sets the socket
//! to 0660. An inherited source adopts a listener the composing process
//! already owns, which is how integration tests reach an ephemeral port
//! without configuring one.

use std::error::Error;
use std::fmt;
use std::net::SocketAddr;
use std::os::unix::fs::{FileTypeExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use tokio::net::{TcpListener, UnixListener};

use crate::RuntimeError;

/// Mode of the directory that holds a daemon-owned socket (spec line 565).
pub const UNIX_SOCKET_DIRECTORY_MODE: u32 = 0o750;
/// Mode of a daemon-owned socket (spec line 565).
pub const UNIX_SOCKET_MODE: u32 = 0o660;

/// Where a listener's socket comes from.
pub enum ListenerSource {
    /// Bind this literal address.
    Tcp(SocketAddr),
    /// Bind this absolute socket path.
    Unix(PathBuf),
    /// Adopt a listener the process already owns.
    InheritedTcp(std::net::TcpListener),
    /// Adopt a Unix listener the process already owns.
    InheritedUnix(std::os::unix::net::UnixListener),
}

/// The address a listener ended up bound to.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BoundAddress {
    /// A TCP address, with the ephemeral port resolved.
    Tcp(SocketAddr),
    /// A Unix socket path.
    Unix(PathBuf),
}

/// Closed failures while opening or running listeners.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ListenerError {
    /// The purpose has no transport in this stage.
    UnsupportedPurpose,
    /// A TLS purpose was configured without a TLS configuration.
    MissingTls,
    /// A plain purpose was configured with a TLS configuration.
    UnexpectedTls,
    /// The source and the purpose disagree about TCP versus Unix sockets.
    SourceMismatch,
    /// The socket could not be bound.
    Bind,
    /// The Unix socket directory is absent or not mode 0750.
    SocketDirectory,
    /// The socket mode could not be set to 0660.
    SocketPermissions,
    /// The connection ceiling was zero or above the hard maximum.
    ConnectionCeiling,
    /// A local-admin purpose and its UID/GID policy disagreed.
    AdminPolicy,
    /// The parent token was cancelled before the listeners opened.
    Cancelled,
}

impl fmt::Display for ListenerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::UnsupportedPurpose => "listener purpose is not implemented in this stage",
            Self::MissingTls => "listener purpose requires a TLS configuration",
            Self::UnexpectedTls => "listener purpose does not use TLS",
            Self::SourceMismatch => "listener source does not match its purpose",
            Self::Bind => "listener socket could not be bound",
            Self::SocketDirectory => "socket directory is absent or not mode 0750",
            Self::SocketPermissions => "socket mode could not be set to 0660",
            Self::ConnectionCeiling => "listener connection ceiling is out of range",
            Self::AdminPolicy => "local administrative admission policy is invalid",
            Self::Cancelled => "listener set was cancelled before opening",
        };
        formatter.write_str(message)
    }
}

impl Error for ListenerError {}

impl From<ListenerError> for RuntimeError {
    fn from(_: ListenerError) -> Self {
        Self::InvalidValue
    }
}

/// A bound, non-blocking listener ready for the accept loop.
pub(crate) enum BoundListener {
    Tcp(TcpListener),
    Unix(UnixListener),
}

impl BoundListener {
    pub(crate) fn is_unix(&self) -> bool {
        matches!(self, Self::Unix(_))
    }
}

/// Binds or adopts the source, returning the listener and its address.
///
/// Registers the socket with the current Tokio reactor, so this runs inside
/// the runtime, which is where `ListenerSet::start` is called.
pub(crate) fn bind(source: ListenerSource) -> Result<(BoundListener, BoundAddress), ListenerError> {
    match source {
        ListenerSource::Tcp(address) => {
            let listener = std::net::TcpListener::bind(address).map_err(|_| ListenerError::Bind)?;
            adopt_tcp(listener)
        }
        ListenerSource::InheritedTcp(listener) => adopt_tcp(listener),
        ListenerSource::Unix(path) => {
            let listener = bind_unix(&path)?;
            adopt_unix(listener, path)
        }
        ListenerSource::InheritedUnix(listener) => {
            let path = listener
                .local_addr()
                .ok()
                .and_then(|address| address.as_pathname().map(Path::to_path_buf))
                .unwrap_or_default();
            adopt_unix(listener, path)
        }
    }
}

fn adopt_tcp(
    listener: std::net::TcpListener,
) -> Result<(BoundListener, BoundAddress), ListenerError> {
    listener
        .set_nonblocking(true)
        .map_err(|_| ListenerError::Bind)?;
    let address = listener.local_addr().map_err(|_| ListenerError::Bind)?;
    let listener = TcpListener::from_std(listener).map_err(|_| ListenerError::Bind)?;
    Ok((BoundListener::Tcp(listener), BoundAddress::Tcp(address)))
}

fn adopt_unix(
    listener: std::os::unix::net::UnixListener,
    path: PathBuf,
) -> Result<(BoundListener, BoundAddress), ListenerError> {
    listener
        .set_nonblocking(true)
        .map_err(|_| ListenerError::Bind)?;
    let listener = UnixListener::from_std(listener).map_err(|_| ListenerError::Bind)?;
    Ok((BoundListener::Unix(listener), BoundAddress::Unix(path)))
}

/// Binds a daemon-owned socket: the parent directory must already exist
/// with mode 0750, a stale socket file is replaced, and the new socket is
/// set to mode 0660 before it is returned.
fn bind_unix(path: &Path) -> Result<std::os::unix::net::UnixListener, ListenerError> {
    let parent = path.parent().ok_or(ListenerError::SocketDirectory)?;
    let directory =
        std::fs::symlink_metadata(parent).map_err(|_| ListenerError::SocketDirectory)?;
    if !directory.is_dir() || directory.permissions().mode() & 0o7777 != UNIX_SOCKET_DIRECTORY_MODE
    {
        return Err(ListenerError::SocketDirectory);
    }
    if let Ok(existing) = std::fs::symlink_metadata(path) {
        if !existing.file_type().is_socket() {
            return Err(ListenerError::Bind);
        }
        std::fs::remove_file(path).map_err(|_| ListenerError::Bind)?;
    }
    let listener = std::os::unix::net::UnixListener::bind(path).map_err(|_| ListenerError::Bind)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(UNIX_SOCKET_MODE))
        .map_err(|_| ListenerError::SocketPermissions)?;
    Ok(listener)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let unique = format!(
            "agenc-socket-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        );
        std::env::temp_dir().join(unique)
    }

    #[tokio::test]
    async fn tcp_sources_bind_and_report_the_resolved_port() -> Result<(), ListenerError> {
        let (listener, address) = bind(ListenerSource::Tcp(SocketAddr::from(([127, 0, 0, 1], 0))))?;
        assert!(!listener.is_unix());
        let BoundAddress::Tcp(address) = address else {
            return Err(ListenerError::Bind);
        };
        assert_ne!(address.port(), 0);
        let inherited =
            std::net::TcpListener::bind("127.0.0.1:0").map_err(|_| ListenerError::Bind)?;
        let expected = inherited.local_addr().map_err(|_| ListenerError::Bind)?;
        let (adopted, address) = bind(ListenerSource::InheritedTcp(inherited))?;
        assert_eq!(address, BoundAddress::Tcp(expected));
        assert_eq!(
            bind(ListenerSource::Tcp(expected)).err(),
            Some(ListenerError::Bind),
            "the port is still held by the adopted listener"
        );
        drop(adopted);
        Ok(())
    }

    #[tokio::test]
    async fn unix_sources_require_a_0750_directory_and_set_0660() -> Result<(), ListenerError> {
        let directory = scratch("dir");
        std::fs::create_dir(&directory).map_err(|_| ListenerError::Bind)?;
        let path = directory.join("onion.sock");
        assert_eq!(
            bind(ListenerSource::Unix(path.clone())).err(),
            Some(ListenerError::SocketDirectory),
            "default directory mode is not 0750"
        );
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o750))
            .map_err(|_| ListenerError::Bind)?;
        let (listener, address) = bind(ListenerSource::Unix(path.clone()))?;
        assert!(listener.is_unix());
        assert_eq!(address, BoundAddress::Unix(path.clone()));
        let mode = std::fs::symlink_metadata(&path)
            .map_err(|_| ListenerError::Bind)?
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(mode, UNIX_SOCKET_MODE);
        drop(listener);
        let (_, _) = bind(ListenerSource::Unix(path.clone()))?;
        let regular = directory.join("regular");
        std::fs::write(&regular, b"x").map_err(|_| ListenerError::Bind)?;
        assert_eq!(
            bind(ListenerSource::Unix(regular)).err(),
            Some(ListenerError::Bind)
        );
        assert_eq!(
            bind(ListenerSource::Unix(PathBuf::from("/"))).err(),
            Some(ListenerError::SocketDirectory)
        );
        assert_eq!(
            bind(ListenerSource::Unix(
                directory.join("missing").join("x.sock")
            ))
            .err(),
            Some(ListenerError::SocketDirectory)
        );
        let inherited = std::os::unix::net::UnixListener::bind(directory.join("inherited.sock"))
            .map_err(|_| ListenerError::Bind)?;
        let (_, address) = bind(ListenerSource::InheritedUnix(inherited))?;
        assert_eq!(
            address,
            BoundAddress::Unix(directory.join("inherited.sock"))
        );
        let _ = std::fs::remove_dir_all(directory);
        Ok(())
    }

    #[test]
    fn errors_render_fixed_text_and_map_to_invalid_value() {
        for error in [
            ListenerError::UnsupportedPurpose,
            ListenerError::MissingTls,
            ListenerError::UnexpectedTls,
            ListenerError::SourceMismatch,
            ListenerError::Bind,
            ListenerError::SocketDirectory,
            ListenerError::SocketPermissions,
            ListenerError::ConnectionCeiling,
            ListenerError::Cancelled,
        ] {
            assert!(error.to_string().is_ascii());
            assert_eq!(RuntimeError::from(error), RuntimeError::InvalidValue);
        }
    }
}
