//! russh client handler: host key check, server-initiated channels and the
//! connection-lifetime bookkeeping that keeps the Node event loop alive.
//!
//! Every handler callback runs through [`protect`], which catches a panic and
//! turns it into an `INTERNAL` error that ends the session instead of
//! unwinding through russh's session task.

use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use futures::FutureExt;
use napi::bindgen_prelude::Promise;
use napi::threadsafe_function::{ThreadsafeFunction, ThreadsafeFunctionCallMode};
use napi::{sys, Status};
use russh::client::ChannelOpenHandle;
use russh::client::{DisconnectReason, Handler, Msg, Session};
use russh::keys::agent::AgentSessionBinding;
use russh::keys::PublicKeyOrCertificate;
use russh::{Channel, ChannelOpenFailure};

use crate::error::{from_russh, BindingError, Code};
use crate::hostkey::{describe, HostKeyInfo};
use crate::js::JsObjectBuilder;
use crate::signal::Flag;

/// Async JS host-key verifier (the wrapper always returns a promise of a
/// boolean that never rejects). Weak: while the verifier runs, the ref'd
/// `DisconnectFn` of the same connection keeps the event loop alive (a
/// pending promise alone does not).
pub type VerifyFn =
    ThreadsafeFunction<HostKeyInfo, Promise<bool>, sys::napi_value, Status, false, true>;

/// Disconnect callback. NOT weak: as long as this threadsafe function is
/// referenced, the Node process stays alive, like an open `ssh2` socket.
pub type DisconnectFn =
    ThreadsafeFunction<DisconnectInfo, (), sys::napi_value, Status, false, false>;

/// Why a session ended, delivered once to the JS `onDisconnect` listeners.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DisconnectInfo {
    /// `remote` (the server sent SSH_MSG_DISCONNECT), `local` (`close()` or
    /// `destroy()`), or `error` (I/O or protocol failure, see `code`).
    pub reason: &'static str,
    pub code: Option<Code>,
}

impl DisconnectInfo {
    /// `{ kind: "disconnect", reason, code? }`
    pub fn to_js(&self, env: &napi::Env) -> napi::Result<sys::napi_value> {
        Ok(JsObjectBuilder::new(env, "disconnect")?
            .set("reason", Some(self.reason))?
            .set("code", self.code.map(Code::as_str))?
            .finish())
    }
}

/// Error type of the handler. Binding errors (abort, timeout, panic) travel
/// through russh unchanged, so `connect()` reports the right code.
#[derive(Debug)]
pub enum HandlerError {
    Russh(russh::Error),
    Binding(BindingError),
}

impl From<russh::Error> for HandlerError {
    fn from(err: russh::Error) -> Self {
        HandlerError::Russh(err)
    }
}

impl HandlerError {
    pub fn into_binding_error(self) -> BindingError {
        match self {
            HandlerError::Russh(err) => from_russh(&err),
            HandlerError::Binding(err) => err,
        }
    }
}

/// Runs a handler callback and turns a panic into an `INTERNAL` error.
pub async fn protect<T>(
    fut: impl Future<Output = Result<T, HandlerError>>,
) -> Result<T, HandlerError> {
    AssertUnwindSafe(fut)
        .catch_unwind()
        .await
        .unwrap_or_else(|_| Err(HandlerError::Binding(BindingError::internal())))
}

/// State shared between the handler (moved into russh's session task) and
/// the `NativeSession` object owned by JS.
pub struct Shared {
    keepalive: Mutex<Option<DisconnectFn>>,
    /// Set exactly when russh's session task is gone (handler dropped).
    pub ended: Flag,
    /// Set by `destroy()`, abort and timeouts: the socket is shut down and
    /// every exec reader stops waiting for stdout credit.
    killed: Flag,
    /// Cancels a pending host-key verifier.
    verifier_cancel: Flag,
    /// Duplicate of the TCP socket fd. `shutdown(Both)` on it ends the session
    /// task immediately and synchronously (used by `destroy()` and timeouts).
    killer: Mutex<Option<std::net::TcpStream>>,
    pub binding: OnceLock<AgentSessionBinding>,
    reason: Mutex<Option<DisconnectInfo>>,
    local_close: AtomicBool,
    /// Server-initiated channel types this client rejected (diagnostics).
    pub rejected: Mutex<Vec<String>>,
    /// Server-initiated agent channels that were accepted and bridged.
    pub agent_channels_bridged: AtomicU32,
}

impl Shared {
    pub fn new(keepalive: Option<DisconnectFn>) -> Arc<Self> {
        Arc::new(Self {
            keepalive: Mutex::new(keepalive),
            ended: Flag::new(),
            killed: Flag::new(),
            verifier_cancel: Flag::new(),
            killer: Mutex::new(None),
            binding: OnceLock::new(),
            reason: Mutex::new(None),
            local_close: AtomicBool::new(false),
            rejected: Mutex::new(Vec::new()),
            agent_channels_bridged: AtomicU32::new(0),
        })
    }

    pub fn set_killer(&self, socket: std::net::TcpStream) {
        if let Ok(mut slot) = self.killer.lock() {
            *slot = Some(socket);
        }
    }

    /// Shuts the TCP socket down and releases every exec reader that waits
    /// for stdout credit. Synchronous, no runtime needed.
    pub fn kill(&self) {
        self.killed.fire();
        if let Ok(slot) = self.killer.lock() {
            if let Some(socket) = slot.as_ref() {
                let _ = socket.shutdown(std::net::Shutdown::Both);
            }
        }
    }

    pub fn is_killed(&self) -> bool {
        self.killed.is_fired()
    }

    pub fn killed(&self) -> Flag {
        self.killed.clone()
    }

    /// Abort or deadline during connect: cancel the verifier and kill the socket.
    pub fn cancel(&self) {
        self.verifier_cancel.fire();
        self.kill();
    }

    pub fn mark_local_close(&self) {
        self.local_close.store(true, Ordering::SeqCst);
    }

    pub fn take_keepalive(&self) -> Option<DisconnectFn> {
        self.keepalive.lock().ok().and_then(|mut k| k.take())
    }

    pub fn is_ended(&self) -> bool {
        self.ended.is_fired()
    }

    fn set_reason(&self, info: DisconnectInfo) {
        if let Ok(mut slot) = self.reason.lock() {
            if slot.is_none() {
                *slot = Some(info);
            }
        }
    }

    /// The reason reported to JS. A local `close()`/`destroy()` wins over
    /// the transport error it causes.
    pub fn disconnect_info(&self) -> DisconnectInfo {
        if self.local_close.load(Ordering::SeqCst) {
            return DisconnectInfo {
                reason: "local",
                code: None,
            };
        }
        self.reason
            .lock()
            .ok()
            .and_then(|r| r.clone())
            .unwrap_or(DisconnectInfo {
                reason: "error",
                code: Some(Code::Disconnected),
            })
    }

    /// Called exactly when russh's session task is gone (handler dropped).
    fn finish(&self) {
        if let Some(callback) = self.take_keepalive() {
            callback.call(
                self.disconnect_info(),
                ThreadsafeFunctionCallMode::NonBlocking,
            );
            // Dropping releases the threadsafe function, so the event loop may exit.
            drop(callback);
        }
        self.ended.fire();
    }

    fn record_rejected(&self, kind: &str) {
        if let Ok(mut list) = self.rejected.lock() {
            list.push(kind.to_owned());
        }
    }
}

pub enum HostCheck {
    /// `scan()`: capture the key, then refuse to continue (no authentication).
    Scan(Arc<Mutex<Option<HostKeyInfo>>>),
    /// `connect()`: ask JS, await its promise (or the cancel flag).
    Verify(Option<VerifyFn>),
    /// `__internalPanicProbe("handler")`: panics inside the protected path.
    PanicProbe,
}

pub struct ClientHandler {
    pub host_check: HostCheck,
    /// Agent socket to bridge `auth-agent@openssh.com` channels to. `None`
    /// means every such channel is rejected and no agent socket is opened.
    pub agent_forward_socket: Option<String>,
    pub shared: Arc<Shared>,
}

impl Drop for ClientHandler {
    fn drop(&mut self) {
        self.shared.finish();
    }
}

impl ClientHandler {
    async fn reject(&self, kind: &str, reply: ChannelOpenHandle) -> Result<(), HandlerError> {
        self.shared.record_rejected(kind);
        reply
            .reject(ChannelOpenFailure::AdministrativelyProhibited)
            .await;
        Ok(())
    }

    async fn verify(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, HandlerError> {
        match &mut self.host_check {
            HostCheck::Scan(slot) => {
                let info = describe(server_public_key);
                if let Ok(mut slot) = slot.lock() {
                    *slot = Some(info);
                }
                Ok(false)
            }
            HostCheck::Verify(verifier) => {
                // Fail closed: a missing verifier, a failed call or a rejected
                // promise all reject the host key.
                let Some(verifier) = verifier.take() else {
                    return Ok(false);
                };
                let info = describe(server_public_key);
                let cancel = self.shared.verifier_cancel.clone();
                let verdict = async move {
                    match verifier.call_async_catch(info).await {
                        // The wrapper's promise never rejects. An error here
                        // means no verdict will ever come (for example the
                        // promise was garbage-collected while pending), so
                        // wait for the abort or the deadline instead of
                        // reporting a rejection the verifier never made.
                        // The host key stays unaccepted either way.
                        Ok(promise) => match promise.await {
                            Ok(accepted) => accepted,
                            Err(_) => std::future::pending().await,
                        },
                        Err(_) => false,
                    }
                };
                // A verifier that never settles must not pin the session
                // task: on abort or deadline the select drops the pending
                // promise (a late result is discarded) and the session ends,
                // which drops the handler and releases the ref'd callback.
                tokio::select! {
                    biased;
                    () = cancel.fired() => Err(HandlerError::Binding(BindingError::aborted())),
                    accepted = verdict => Ok(accepted),
                }
            }
            HostCheck::PanicProbe => panic_probe(),
        }
    }
}

#[allow(clippy::panic)]
fn panic_probe() -> Result<bool, HandlerError> {
    if std::hint::black_box(true) {
        panic!("handler panic probe");
    }
    Ok(false)
}

/// Runs `check_server_key` of a probe handler without any network, through
/// the same protected path russh uses.
pub async fn run_handler_probe() -> BindingError {
    let handler_shared = Shared::new(None);
    let mut handler = ClientHandler {
        host_check: HostCheck::PanicProbe,
        agent_forward_socket: None,
        shared: handler_shared,
    };
    let key = russh::keys::PublicKey::from_openssh(PROBE_KEY).map(|key| {
        PublicKeyOrCertificate::PublicKey {
            key,
            hash_alg: None,
        }
    });
    match key {
        Ok(key) => match handler.check_server_key(&key).await {
            Ok(_) => BindingError::new(Code::Protocol, "the handler probe did not panic"),
            Err(err) => err.into_binding_error(),
        },
        Err(_) => BindingError::new(Code::Protocol, "the handler probe key is invalid"),
    }
}

/// Fixed public test key for the handler probe (no secret material).
const PROBE_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGB9FLjCqKSu7CznTxatG/otTEPosy3oIiq8l4ZUw3uO probe";

#[cfg(unix)]
async fn bridge_agent(channel: Channel<Msg>, socket: String, binding: Option<AgentSessionBinding>) {
    use russh::keys::agent::client::AgentClient;
    let Ok(stream) = tokio::net::UnixStream::connect(&socket).await else {
        let _ = channel.close().await;
        return;
    };
    let mut agent = AgentClient::connect(stream);
    if let Some(binding) = binding {
        // OpenSSH binds a forwarded agent connection to the session before
        // relaying; failures (agent without the extension) are ignored.
        let _ = agent.bind_session(&binding, true).await;
    }
    let mut agent_stream = agent.into_inner();
    let mut channel_stream = channel.into_stream();
    let _ = tokio::io::copy_bidirectional(&mut channel_stream, &mut agent_stream).await;
}

impl Handler for ClientHandler {
    type Error = HandlerError;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        protect(self.verify(server_public_key)).await
    }

    async fn disconnected(
        &mut self,
        reason: DisconnectReason<Self::Error>,
    ) -> Result<(), Self::Error> {
        protect(async move {
            let info = match reason {
                DisconnectReason::ReceivedDisconnect(_) => DisconnectInfo {
                    reason: "remote",
                    code: None,
                },
                DisconnectReason::Error(e) => DisconnectInfo {
                    reason: "error",
                    code: Some(e.into_binding_error().code),
                },
            };
            self.shared.set_reason(info);
            Ok(())
        })
        .await
    }

    async fn server_channel_open_agent_forward(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        protect(async move {
            #[cfg(unix)]
            if let Some(socket) = self.agent_forward_socket.clone() {
                reply.accept().await;
                self.shared
                    .agent_channels_bridged
                    .fetch_add(1, Ordering::SeqCst);
                let binding = self.shared.binding.get().cloned();
                // A panic in the bridge only ends the bridge task.
                tokio::spawn(
                    AssertUnwindSafe(bridge_agent(channel, socket, binding)).catch_unwind(),
                );
                return Ok(());
            }
            drop(channel);
            self.reject("auth-agent@openssh.com", reply).await
        })
        .await
    }

    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        _channel: Channel<Msg>,
        _connected_address: &str,
        _connected_port: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        protect(self.reject("forwarded-tcpip", reply)).await
    }

    async fn server_channel_open_forwarded_streamlocal(
        &mut self,
        _channel: Channel<Msg>,
        _socket_path: &str,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        protect(self.reject("forwarded-streamlocal@openssh.com", reply)).await
    }

    async fn server_channel_open_x11(
        &mut self,
        _channel: Channel<Msg>,
        _originator_address: &str,
        _originator_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        protect(self.reject("x11", reply)).await
    }

    async fn server_channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        protect(self.reject("session", reply)).await
    }

    async fn server_channel_open_direct_tcpip(
        &mut self,
        _channel: Channel<Msg>,
        _host_to_connect: &str,
        _port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        protect(self.reject("direct-tcpip", reply)).await
    }

    async fn server_channel_open_direct_streamlocal(
        &mut self,
        _channel: Channel<Msg>,
        _socket_path: &str,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        protect(self.reject("direct-streamlocal@openssh.com", reply)).await
    }

    async fn should_accept_unknown_server_channel(
        &mut self,
        _id: russh::ChannelId,
        channel_type: &str,
    ) -> bool {
        // Never accepted; a panic while recording is caught and also rejects.
        let shared = &self.shared;
        let _ = protect(async move {
            shared.record_rejected(channel_type);
            Ok(())
        })
        .await;
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_panicking_handler_callback_becomes_internal() {
        let err = run_handler_probe().await;
        assert_eq!(err, BindingError::internal());
    }

    #[test]
    fn a_local_close_wins_over_the_transport_error() {
        let shared = Shared::new(None);
        shared.set_reason(DisconnectInfo {
            reason: "error",
            code: Some(Code::Disconnected),
        });
        shared.mark_local_close();
        assert_eq!(shared.disconnect_info().reason, "local");
    }
}
