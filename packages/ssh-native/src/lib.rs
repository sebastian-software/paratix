//! `@paratix/ssh-native`: a thin napi-rs binding over russh 0.65 and
//! russh-sftp 3, consumed by Paratix through the JS wrapper in `index.js`.
//!
//! Every raw export here is hidden from `index.d.ts` (`skip_typescript`);
//! the wrapper reshapes them into the public API declared in
//! `dts-header.txt`. Every synchronous export carries `catch_unwind`, so a
//! panic (including one during argument or return conversion) becomes a JS
//! error that the wrapper maps to `INTERNAL`.

#![deny(clippy::unwrap_used, clippy::expect_used)]
// napi-derive does not register exports in test builds, so everything that
// is only reachable from a `#[napi]` export looks unused to `cargo test`.
#![cfg_attr(test, allow(dead_code))]

use std::future::Future;

mod auth;
mod connect;
mod error;
mod exec;
mod handler;
mod hostkey;
mod js;
mod probe;
mod secret;
mod session;
mod sftp;
mod signal;

use error::{BindingError, BindingResult};
use napi_derive::napi;

/// Silent panic hook: a panic never prints anything (no secrets on stderr).
#[napi_derive::module_init]
fn init() {
    std::panic::set_hook(Box::new(|_| {}));
}

/// Runs `fut` as its own tokio task so a panic becomes a JoinError, which is
/// mapped to `INTERNAL` instead of leaving the JS promise pending.
pub(crate) async fn guarded<T, F>(fut: F) -> napi::Result<T>
where
    T: Send + 'static,
    F: Future<Output = BindingResult<T>> + Send + 'static,
{
    match tokio::spawn(fut).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(err)) => Err(err.into()),
        Err(join) => Err(BindingError::from(join).into()),
    }
}

/// Name of the crypto backend compiled in.
#[napi(skip_typescript, catch_unwind)]
pub fn crypto_backend() -> &'static str {
    if cfg!(feature = "ring") && !cfg!(feature = "aws-lc-rs") {
        "ring"
    } else {
        "aws-lc-rs"
    }
}

#[cfg(test)]
mod tests {
    use crate::connect::{CHANNEL_BUFFER_SIZE, MAXIMUM_PACKET_SIZE, WINDOW_SIZE};
    use crate::exec::STDOUT_QUEUE_LIMIT;

    /// These values are mirrored in `test/backpressure.test.mjs`; change both.
    #[test]
    fn flow_control_constants_match_the_node_test_mirror() {
        assert_eq!(STDOUT_QUEUE_LIMIT, 1_048_576);
        assert_eq!(WINDOW_SIZE, 2_097_152);
        assert_eq!(MAXIMUM_PACKET_SIZE, 32_768);
        assert_eq!(CHANNEL_BUFFER_SIZE, 100);
    }

    #[test]
    fn the_client_config_uses_the_explicit_flow_control_values() {
        let config = crate::connect::client_config();
        assert_eq!(config.window_size, WINDOW_SIZE);
        assert_eq!(config.maximum_packet_size, MAXIMUM_PACKET_SIZE);
        assert_eq!(config.channel_buffer_size, CHANNEL_BUFFER_SIZE);
        assert!(config.keepalive_interval.is_none());
        assert!(config.inactivity_timeout.is_none());
        assert!(config.preferred.host_key_certificates.is_empty());
    }
}
