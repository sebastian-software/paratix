//! russh client configuration, TCP + SSH handshake shared by `scan()` and
//! `connect()`, and the deadline/abort race around them.

use std::borrow::Cow;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use russh::client::{self, Handle};
use russh::keys::{Algorithm, EcdsaCurve, HashAlg};
use russh::Preferred;
use tokio::net::TcpStream;

use crate::error::{BindingError, BindingResult, Code};
use crate::handler::{ClientHandler, Shared};
use crate::signal::Flag;

/// Initial SSH channel window announced to the server, in bytes. Set
/// explicitly (russh's default) because the backpressure bound depends on it.
pub const WINDOW_SIZE: u32 = 2_097_152;

/// Maximum SSH packet size announced to the server, in bytes (russh's default).
pub const MAXIMUM_PACKET_SIZE: u32 = 32_768;

/// Number of unread messages russh buffers per channel before its session
/// loop blocks (russh's default). Together with the two values above it
/// bounds what the server can send while JS does not read stdout.
pub const CHANNEL_BUFFER_SIZE: usize = 100;

/// Host key order of ssh2 1.17 (`DEFAULT_SERVER_HOST_KEY`): ed25519, ecdsa,
/// rsa-sha2-512, rsa-sha2-256, ssh-rsa.
const SSH2_HOST_KEY_ORDER: &[Algorithm] = &[
    Algorithm::Ed25519,
    Algorithm::Ecdsa {
        curve: EcdsaCurve::NistP256,
    },
    Algorithm::Ecdsa {
        curve: EcdsaCurve::NistP384,
    },
    Algorithm::Ecdsa {
        curve: EcdsaCurve::NistP521,
    },
    Algorithm::Rsa {
        hash: Some(HashAlg::Sha512),
    },
    Algorithm::Rsa {
        hash: Some(HashAlg::Sha256),
    },
    Algorithm::Rsa { hash: None },
];

pub fn client_config() -> Arc<client::Config> {
    let preferred = Preferred {
        key: Cow::Borrowed(SSH2_HOST_KEY_ORDER),
        // No host-certificate algorithms are offered (certificates arrive
        // with work packages D and E).
        host_key_certificates: Cow::Borrowed(&[]),
        ..Preferred::default()
    };
    Arc::new(client::Config {
        preferred,
        window_size: WINDOW_SIZE,
        maximum_packet_size: MAXIMUM_PACKET_SIZE,
        channel_buffer_size: CHANNEL_BUFFER_SIZE,
        // No keepalive and no inactivity timeout: a long silent command is
        // never cut off.
        inactivity_timeout: None,
        keepalive_interval: None,
        nodelay: true,
        ..Default::default()
    })
}

fn connect_failed(err: &std::io::Error) -> BindingError {
    BindingError::with_detail(
        Code::ConnectFailed,
        err.raw_os_error()
            .map(|n| n.to_string())
            .unwrap_or_default(),
        "the TCP connection could not be established",
    )
}

/// Opens TCP, registers a kill switch in `shared`, and runs the handshake
/// (including the host key check) with russh.
pub async fn tcp_and_handshake(
    host: &str,
    port: u16,
    handler: ClientHandler,
) -> BindingResult<Handle<ClientHandler>> {
    let shared = handler.shared.clone();
    let tcp = TcpStream::connect((host, port))
        .await
        .map_err(|e| connect_failed(&e))?;
    let _ = tcp.set_nodelay(true);
    let std_stream = tcp.into_std().map_err(|e| connect_failed(&e))?;
    let killer = std_stream.try_clone().map_err(|e| connect_failed(&e))?;
    shared.set_killer(killer);
    if shared.is_killed() {
        // destroy()/abort raced with the TCP connect.
        shared.kill();
    }
    let tcp = TcpStream::from_std(std_stream).map_err(|e| connect_failed(&e))?;
    client::connect_stream(client_config(), tcp, handler)
        .await
        .map_err(|e| e.into_binding_error())
}

/// Runs `fut` under an overall deadline and an abort flag. On expiry or
/// abort the socket is shut down and the pending host-key verifier is
/// cancelled, so russh's session task ends too: half-open TCP or a verifier
/// that never answers cannot keep the caller or the event loop waiting.
pub async fn bounded<T>(
    shared: &Arc<Shared>,
    timeout_ms: u32,
    abort: &Flag,
    timeout_message: &str,
    fut: impl Future<Output = BindingResult<T>>,
) -> BindingResult<T> {
    let deadline = tokio::time::sleep(Duration::from_millis(u64::from(timeout_ms)));
    let result = tokio::select! {
        biased;
        () = abort.fired() => Err(BindingError::aborted()),
        () = deadline => Err(BindingError::timeout(timeout_message)),
        result = fut => result,
    };
    if result.is_err() {
        shared.cancel();
    }
    result
}
