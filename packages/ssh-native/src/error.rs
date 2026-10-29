//! Error codes of the binding.
//!
//! Native errors cross the boundary as a plain `napi::Error` whose reason is
//! `CODE|detail|message`. The JS wrapper (`index.js`) parses that triple into
//! an `Error` with `.code` (and `.errno` / `.sftpStatus` where relevant).
//! Messages are fixed, secret-free texts written here; native causes are only
//! appended for protocol errors whose text cannot contain key material.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {
    AuthFailed,
    HostKeyRejected,
    Timeout,
    Aborted,
    ConnectFailed,
    Protocol,
    ChannelOpenFailed,
    Disconnected,
    SftpStatus,
    UnsupportedKey,
    EncryptedKey,
    Internal,
}

impl Code {
    pub fn as_str(self) -> &'static str {
        match self {
            Code::AuthFailed => "AUTH_FAILED",
            Code::HostKeyRejected => "HOST_KEY_REJECTED",
            Code::Timeout => "TIMEOUT",
            Code::Aborted => "ABORTED",
            Code::ConnectFailed => "CONNECT_FAILED",
            Code::Protocol => "PROTOCOL",
            Code::ChannelOpenFailed => "CHANNEL_OPEN_FAILED",
            Code::Disconnected => "DISCONNECTED",
            Code::SftpStatus => "SFTP_STATUS",
            Code::UnsupportedKey => "UNSUPPORTED_KEY",
            Code::EncryptedKey => "ENCRYPTED_KEY",
            Code::Internal => "INTERNAL",
        }
    }
}

#[derive(Debug, Clone)]
pub struct SpikeError {
    pub code: Code,
    /// Machine-readable detail: errno for CONNECT_FAILED, SFTP status code for
    /// SFTP_STATUS, channel-open reason for CHANNEL_OPEN_FAILED.
    pub detail: String,
    pub message: String,
}

pub type SpikeResult<T> = std::result::Result<T, SpikeError>;

impl SpikeError {
    pub fn new(code: Code, message: impl Into<String>) -> Self {
        Self {
            code,
            detail: String::new(),
            message: message.into(),
        }
    }

    pub fn with_detail(code: Code, detail: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
            message: message.into(),
        }
    }

    pub fn internal() -> Self {
        Self::new(Code::Internal, "internal error in the native SSH binding")
    }

    pub fn disconnected() -> Self {
        Self::new(Code::Disconnected, "the SSH connection is closed")
    }
}

impl fmt::Display for SpikeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}|{}|{}", self.code.as_str(), self.detail, self.message)
    }
}

impl From<SpikeError> for napi::Error {
    fn from(err: SpikeError) -> Self {
        napi::Error::new(napi::Status::GenericFailure, err.to_string())
    }
}

impl From<tokio::task::JoinError> for SpikeError {
    fn from(_: tokio::task::JoinError) -> Self {
        SpikeError::internal()
    }
}

fn channel_open_reason(reason: &russh::ChannelOpenFailure) -> String {
    match reason {
        russh::ChannelOpenFailure::AdministrativelyProhibited => {
            "administratively-prohibited".into()
        }
        russh::ChannelOpenFailure::ConnectFailed => "connect-failed".into(),
        russh::ChannelOpenFailure::UnknownChannelType => "unknown-channel-type".into(),
        russh::ChannelOpenFailure::ResourceShortage => "resource-shortage".into(),
        russh::ChannelOpenFailure::Other { code, .. } => format!("other-{code}"),
    }
}

/// Maps key-parsing errors without echoing any key material.
pub fn from_key_error(err: &russh::keys::Error) -> SpikeError {
    use russh::keys::Error as K;
    match err {
        K::KeyIsEncrypted => SpikeError::new(
            Code::EncryptedKey,
            "the private key is encrypted; passphrases are not supported",
        ),
        K::UnsupportedKeyType {
            key_type_string, ..
        } => SpikeError::with_detail(
            Code::UnsupportedKey,
            key_type_string.clone(),
            "the private key type is not supported",
        ),
        K::UnknownAlgorithm(oid) => SpikeError::with_detail(
            Code::UnsupportedKey,
            oid.to_string(),
            "the private key algorithm is not supported",
        ),
        _ => SpikeError::new(
            Code::UnsupportedKey,
            "the private key could not be parsed (unsupported or corrupt format)",
        ),
    }
}

pub fn from_russh(err: &russh::Error) -> SpikeError {
    use russh::Error as E;
    match err {
        E::UnknownKey => SpikeError::new(Code::HostKeyRejected, "the host key was rejected"),
        E::ChannelOpenFailure(reason) => SpikeError::with_detail(
            Code::ChannelOpenFailed,
            channel_open_reason(reason),
            "the server rejected the channel open request",
        ),
        E::Disconnect | E::HUP | E::SendError | E::RecvError => SpikeError::disconnected(),
        E::ConnectionTimeout | E::Elapsed(_) => {
            SpikeError::new(Code::Timeout, "the SSH operation timed out")
        }
        E::KeepaliveTimeout | E::InactivityTimeout => {
            SpikeError::new(Code::Timeout, "the SSH connection timed out")
        }
        E::NotAuthenticated | E::NoAuthMethod | E::UnsupportedAuthMethod => {
            SpikeError::new(Code::AuthFailed, "authentication failed")
        }
        E::Keys(k) => from_key_error(k),
        E::IO(io) => SpikeError::with_detail(
            Code::Disconnected,
            io.raw_os_error().map(|n| n.to_string()).unwrap_or_default(),
            "the SSH connection failed with an I/O error",
        ),
        E::Join(_) => SpikeError::internal(),
        other => SpikeError::new(Code::Protocol, format!("SSH protocol error: {other}")),
    }
}

impl From<russh::Error> for SpikeError {
    fn from(err: russh::Error) -> Self {
        from_russh(&err)
    }
}

pub fn from_sftp(err: &russh_sftp::client::error::Error) -> SpikeError {
    use russh_sftp::client::error::Error as S;
    match err {
        S::Status(status) => SpikeError::with_detail(
            Code::SftpStatus,
            (status.status_code as u32).to_string(),
            "the SFTP server returned an error status",
        ),
        S::Timeout => SpikeError::new(Code::Timeout, "the SFTP request timed out"),
        S::IO(_) => SpikeError::disconnected(),
        _ => SpikeError::new(Code::Protocol, "SFTP protocol error"),
    }
}

/// A write/close error from `russh_sftp::client::fs::File` arrives as a plain
/// `io::Error`. russh-sftp flattens SFTP status replies of WRITE/CLOSE into
/// `io::Error::other(message)`, so the numeric status code is lost there.
pub fn from_sftp_io(err: &std::io::Error) -> SpikeError {
    if let Some(inner) = err
        .get_ref()
        .and_then(|e| e.downcast_ref::<russh_sftp::client::error::Error>())
    {
        return from_sftp(inner);
    }
    if err.kind() == std::io::ErrorKind::TimedOut {
        return SpikeError::new(Code::Timeout, "the SFTP request timed out");
    }
    SpikeError::with_detail(
        Code::SftpStatus,
        "unknown",
        "the SFTP write or close failed (status code not exposed by russh-sftp)",
    )
}
