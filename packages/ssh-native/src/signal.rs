//! A one-shot, cloneable "fired" flag that async code can wait on.
//!
//! Used for cancellation (AbortSignal, `cancel()`, `destroy()`) and for the
//! end of a russh session. Built on `tokio::sync::watch`, so a waiter that
//! subscribes after the flag fired still sees it (no lost wake-ups), and
//! firing works from any thread without a runtime.

use napi::bindgen_prelude::External;
use napi_derive::napi;
use tokio::sync::watch;

#[derive(Clone, Debug)]
pub struct Flag {
    tx: std::sync::Arc<watch::Sender<bool>>,
}

impl Default for Flag {
    fn default() -> Self {
        Self::new()
    }
}

impl Flag {
    pub fn new() -> Self {
        let (tx, _) = watch::channel(false);
        Self {
            tx: std::sync::Arc::new(tx),
        }
    }

    /// Sets the flag. Idempotent.
    pub fn fire(&self) {
        self.tx.send_replace(true);
    }

    pub fn is_fired(&self) -> bool {
        *self.tx.borrow()
    }

    /// Resolves once the flag is set (immediately if it already is).
    pub async fn fired(&self) {
        let mut rx = self.tx.subscribe();
        // `wait_for` only fails when the sender is dropped; `self` owns it.
        let _ = rx.wait_for(|fired| *fired).await;
    }
}

/// Cancellation handle passed from JS to `scan`, `connect` and `exec`.
/// The JS wrapper creates one per operation and calls `abortHandleFire()`
/// from the AbortSignal listener; firing is synchronous and thread-safe.
pub type AbortHandle = External<Flag>;

#[napi(js_name = "abortHandleCreate", skip_typescript, catch_unwind)]
pub fn abort_handle_create() -> AbortHandle {
    External::new(Flag::new())
}

#[napi(js_name = "abortHandleFire", skip_typescript, catch_unwind)]
pub fn abort_handle_fire(handle: &AbortHandle) {
    handle.fire();
}

#[cfg(test)]
mod tests {
    use super::Flag;

    #[tokio::test]
    async fn late_waiters_see_an_already_fired_flag() {
        let flag = Flag::new();
        flag.fire();
        flag.fired().await;
        assert!(flag.is_fired());
    }

    #[tokio::test]
    async fn waiters_wake_up_when_the_flag_fires() {
        let flag = Flag::new();
        let waiter = tokio::spawn({
            let flag = flag.clone();
            async move { flag.fired().await }
        });
        flag.fire();
        assert!(waiter.await.is_ok());
    }
}
