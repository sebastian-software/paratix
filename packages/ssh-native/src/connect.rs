//! TCP + SSH handshake shared by `scan()` and `connect()`.

use std::borrow::Cow;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use russh::client::{self, Handle};
use russh::keys::{Algorithm, EcdsaCurve, HashAlg};
use russh::Preferred;
use tokio::net::TcpStream;

use crate::error::{Code, SpikeError, SpikeResult};
use crate::handler::{ClientHandler, Shared};

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

pub fn client_config(host_certificates: bool) -> Arc<client::Config> {
    let preferred = Preferred {
        key: Cow::Borrowed(SSH2_HOST_KEY_ORDER),
        host_key_certificates: if host_certificates {
            Cow::Borrowed(SSH2_HOST_KEY_ORDER)
        } else {
            Cow::Borrowed(&[])
        },
        ..Preferred::default()
    };
    Arc::new(client::Config {
        preferred,
        // Plan decision 6: no keepalive and no inactivity timeout.
        inactivity_timeout: None,
        keepalive_interval: None,
        nodelay: true,
        ..Default::default()
    })
}

fn connect_failed(err: &std::io::Error) -> SpikeError {
    SpikeError::with_detail(
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
    host_certificates: bool,
    handler: ClientHandler,
) -> SpikeResult<Handle<ClientHandler>> {
    let shared = handler.shared.clone();
    let tcp = TcpStream::connect((host, port))
        .await
        .map_err(|e| connect_failed(&e))?;
    let _ = tcp.set_nodelay(true);
    let std_stream = tcp.into_std().map_err(|e| connect_failed(&e))?;
    let killer = std_stream.try_clone().map_err(|e| connect_failed(&e))?;
    shared.set_killer(killer);
    let tcp = TcpStream::from_std(std_stream).map_err(|e| connect_failed(&e))?;
    let handle = client::connect_stream(client_config(host_certificates), tcp, handler).await?;
    Ok(handle)
}

/// Runs `fut` under an overall deadline. On expiry the socket is shut down so
/// russh's session task ends too (half-open TCP cannot hang the caller).
pub async fn with_deadline<T>(
    shared: &Arc<Shared>,
    timeout_ms: u32,
    fut: impl Future<Output = SpikeResult<T>>,
) -> SpikeResult<T> {
    match tokio::time::timeout(Duration::from_millis(u64::from(timeout_ms)), fut).await {
        Ok(result) => {
            if result.is_err() {
                shared.kill();
            }
            result
        }
        Err(_) => {
            shared.kill();
            Err(SpikeError::new(
                Code::Timeout,
                "the SSH handshake timed out",
            ))
        }
    }
}
