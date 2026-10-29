//! THROWAWAY SPIKE (issue #254, work package A): a thin napi-rs binding over
//! russh 0.65 and russh-sftp 3. Evidence for ADR 0008, not production code.

#![deny(clippy::unwrap_used, clippy::expect_used)]

use std::future::Future;

mod auth;
mod connect;
mod error;
mod exec;
mod handler;
mod hostkey;
mod session;
mod sftp;

use error::{SpikeError, SpikeResult};
use napi::bindgen_prelude::PromiseRaw;
use napi::Env;
use napi_derive::napi;

/// Silent panic hook: a panic never prints anything (no secrets on stderr).
/// Panics inside spawned tasks surface as JoinError and become `INTERNAL`.
#[napi_derive::module_init]
fn init() {
    std::panic::set_hook(Box::new(|_| {}));
}

/// Runs `fut` as its own tokio task so a panic becomes a JoinError, which is
/// mapped to `INTERNAL` instead of leaving the JS promise pending.
pub(crate) async fn guarded<T, F>(fut: F) -> napi::Result<T>
where
    T: Send + 'static,
    F: Future<Output = SpikeResult<T>> + Send + 'static,
{
    match tokio::spawn(fut).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(err)) => Err(err.into()),
        Err(join) => Err(SpikeError::from(join).into()),
    }
}

/// Spike-only probe: panics inside a task to prove the `INTERNAL` mapping and
/// the silent panic hook.
#[napi]
pub fn internal_panic_probe(env: &Env) -> napi::Result<PromiseRaw<'_, ()>> {
    env.spawn_future(guarded(async {
        #[allow(clippy::panic)]
        if std::hint::black_box(true) {
            panic!("spike panic probe");
        }
        Ok(())
    }))
}

/// Name of the crypto backend compiled in.
#[napi]
pub fn crypto_backend() -> &'static str {
    if cfg!(feature = "ring") && !cfg!(feature = "aws-lc-rs") {
        "ring"
    } else {
        "aws-lc-rs"
    }
}
