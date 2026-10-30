//! Error codes of the binding.
//!
//! Native errors cross the boundary as a plain `napi::Error` whose reason is
//! `CODE|detail|message`. The JS wrapper (`lib/errors.js`) parses that triple
//! into an `Error` with `.code` (and `.errno` / `.sftpStatus` where relevant).
//! Every other error text, for example the payload of a panic, becomes
//! `INTERNAL` with a fixed message there. Messages are fixed, secret-free texts
//! written here; native causes are only appended for protocol errors whose
//! text cannot contain key material.

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

/// Fixed message of every `INTERNAL` error, also used by the JS wrapper.
pub const INTERNAL_MESSAGE: &str = "internal error in the native SSH binding";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingError {
    pub code: Code,
    /// Machine-readable detail: errno for CONNECT_FAILED, SFTP status code for
    /// SFTP_STATUS, channel-open reason for CHANNEL_OPEN_FAILED.
    pub detail: String,
    pub message: String,
}

pub type BindingResult<T> = std::result::Result<T, BindingError>;

impl BindingError {
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
        Self::new(Code::Internal, INTERNAL_MESSAGE)
    }

    pub fn disconnected() -> Self {
        Self::new(Code::Disconnected, "the SSH connection is closed")
    }

    pub fn aborted() -> Self {
        Self::new(Code::Aborted, "the SSH operation was aborted")
    }

    pub fn timeout(message: &str) -> Self {
        Self::new(Code::Timeout, message)
    }

    /// `UNSUPPORTED_KEY` for a key type the binding cannot use; `detail` carries
    /// the key type name.
    pub fn unsupported_key_type(detail: impl Into<String>) -> Self {
        Self::with_detail(
            Code::UnsupportedKey,
            detail,
            "the private key type is not supported",
        )
    }
}

impl fmt::Display for BindingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `|` separates the fields; it never appears in code or detail.
        write!(
            f,
            "{}|{}|{}",
            self.code.as_str(),
            self.detail.replace('|', "/"),
            self.message
        )
    }
}

impl From<BindingError> for napi::Error {
    fn from(err: BindingError) -> Self {
        napi::Error::new(napi::Status::GenericFailure, err.to_string())
    }
}

impl From<tokio::task::JoinError> for BindingError {
    fn from(_: tokio::task::JoinError) -> Self {
        BindingError::internal()
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
pub fn from_key_error(err: &russh::keys::Error) -> BindingError {
    use russh::keys::Error as K;
    match err {
        K::KeyIsEncrypted => BindingError::new(
            Code::EncryptedKey,
            "the private key is encrypted; passphrases are not supported",
        ),
        K::UnsupportedKeyType {
            key_type_string, ..
        } => BindingError::unsupported_key_type(key_type_string.clone()),
        K::UnknownAlgorithm(oid) => BindingError::with_detail(
            Code::UnsupportedKey,
            oid.to_string(),
            "the private key algorithm is not supported",
        ),
        _ => BindingError::new(
            Code::UnsupportedKey,
            "the private key could not be parsed (unsupported or corrupt format)",
        ),
    }
}

pub fn from_russh(err: &russh::Error) -> BindingError {
    use russh::Error as E;
    match err {
        E::UnknownKey => BindingError::new(Code::HostKeyRejected, "the host key was rejected"),
        E::ChannelOpenFailure(reason) => BindingError::with_detail(
            Code::ChannelOpenFailed,
            channel_open_reason(reason),
            "the server rejected the channel open request",
        ),
        E::Disconnect | E::HUP | E::SendError | E::RecvError => BindingError::disconnected(),
        E::ConnectionTimeout | E::Elapsed(_) => {
            BindingError::timeout("the SSH operation timed out")
        }
        E::KeepaliveTimeout | E::InactivityTimeout => {
            BindingError::timeout("the SSH connection timed out")
        }
        E::NotAuthenticated | E::NoAuthMethod | E::UnsupportedAuthMethod => {
            BindingError::new(Code::AuthFailed, "authentication failed")
        }
        E::Keys(k) => from_key_error(k),
        E::IO(io) => BindingError::with_detail(
            Code::Disconnected,
            io.raw_os_error().map(|n| n.to_string()).unwrap_or_default(),
            "the SSH connection failed with an I/O error",
        ),
        E::Join(_) => BindingError::internal(),
        other => BindingError::new(Code::Protocol, format!("SSH protocol error: {other}")),
    }
}

impl From<russh::Error> for BindingError {
    fn from(err: russh::Error) -> Self {
        from_russh(&err)
    }
}

/// Maps errors of the raw SFTP session. Status replies keep their numeric
/// code in `detail`, including those of WRITE and CLOSE, because the binding
/// talks to `RawSftpSession` directly instead of russh-sftp's `File`.
pub fn from_sftp(err: &russh_sftp::client::error::Error) -> BindingError {
    use russh_sftp::client::error::Error as S;
    match err {
        S::Status(status) => BindingError::with_detail(
            Code::SftpStatus,
            (status.status_code as u32).to_string(),
            "the SFTP server returned an error status",
        ),
        S::Timeout => BindingError::timeout("the SFTP request timed out"),
        S::IO(_) => BindingError::disconnected(),
        S::UnexpectedBehavior(_) => BindingError::disconnected(),
        _ => BindingError::new(Code::Protocol, "SFTP protocol error"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_uses_the_wire_format() {
        let err = BindingError::with_detail(Code::SftpStatus, "3", "denied");
        assert_eq!(err.to_string(), "SFTP_STATUS|3|denied");
    }

    #[test]
    fn display_never_emits_a_separator_inside_detail() {
        let err = BindingError::with_detail(Code::UnsupportedKey, "a|b", "m");
        assert_eq!(err.to_string(), "UNSUPPORTED_KEY|a/b|m");
    }

    #[test]
    fn internal_uses_the_fixed_message() {
        assert_eq!(
            BindingError::internal().to_string(),
            format!("INTERNAL||{INTERNAL_MESSAGE}")
        );
    }

    #[test]
    fn sftp_status_keeps_the_numeric_code() {
        use russh_sftp::protocol::{Status, StatusCode};
        let status = Status {
            id: 1,
            status_code: StatusCode::PermissionDenied,
            error_message: "denied".into(),
            language_tag: "en".into(),
        };
        let err = from_sftp(&russh_sftp::client::error::Error::Status(status));
        assert_eq!(err.code, Code::SftpStatus);
        assert_eq!(err.detail, "3");
    }
}
