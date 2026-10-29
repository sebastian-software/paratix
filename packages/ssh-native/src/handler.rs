//! russh client handler: host key check, server-initiated channels and the
//! connection-lifetime bookkeeping that keeps the Node event loop alive.

use std::sync::{Arc, Mutex, OnceLock};

use napi::bindgen_prelude::Promise;
use napi::threadsafe_function::{ThreadsafeFunction, ThreadsafeFunctionCallMode};
use napi::Status;
use russh::client::ChannelOpenHandle;
use russh::client::{DisconnectReason, Handler, Msg, Session};
use russh::keys::agent::AgentSessionBinding;
use russh::keys::PublicKeyOrCertificate;
use russh::{Channel, ChannelOpenFailure};
use tokio::sync::watch;

use crate::error::from_russh;
use crate::hostkey::{describe, HostKeyInfo};

/// Async JS host-key verifier. Weak: the pending `connect()` promise already
/// keeps the event loop alive while the verifier runs.
pub type VerifyFn =
    ThreadsafeFunction<HostKeyInfo, Promise<bool>, HostKeyInfo, Status, false, true>;

/// Disconnect callback. NOT weak: as long as this threadsafe function is
/// referenced, the Node process stays alive, like an open `ssh2` socket.
pub type DisconnectFn = ThreadsafeFunction<String, (), String, Status, false, false>;

/// State shared between the handler (moved into russh's session task) and
/// the `NativeSession` object owned by JS.
pub struct Shared {
    keepalive: Mutex<Option<DisconnectFn>>,
    ended_tx: watch::Sender<bool>,
    /// Duplicate of the TCP socket fd. `shutdown(Both)` on it ends the session
    /// task immediately and synchronously (used by `destroy()` and timeouts).
    killer: Mutex<Option<std::net::TcpStream>>,
    pub binding: OnceLock<AgentSessionBinding>,
    reason: Mutex<Option<String>>,
    /// Server-initiated channel types this client rejected (test observability).
    pub rejected: Mutex<Vec<String>>,
    /// Server-initiated agent channels that were accepted and bridged.
    pub agent_channels_bridged: Mutex<u32>,
}

impl Shared {
    pub fn new(keepalive: Option<DisconnectFn>) -> Arc<Self> {
        let (ended_tx, _) = watch::channel(false);
        Arc::new(Self {
            keepalive: Mutex::new(keepalive),
            ended_tx,
            killer: Mutex::new(None),
            binding: OnceLock::new(),
            reason: Mutex::new(None),
            rejected: Mutex::new(Vec::new()),
            agent_channels_bridged: Mutex::new(0),
        })
    }

    pub fn set_killer(&self, socket: std::net::TcpStream) {
        if let Ok(mut slot) = self.killer.lock() {
            *slot = Some(socket);
        }
    }

    /// Shuts the TCP socket down. Synchronous, no runtime needed.
    pub fn kill(&self) {
        if let Ok(slot) = self.killer.lock() {
            if let Some(socket) = slot.as_ref() {
                let _ = socket.shutdown(std::net::Shutdown::Both);
            }
        }
    }

    pub fn take_keepalive(&self) -> Option<DisconnectFn> {
        self.keepalive.lock().ok().and_then(|mut k| k.take())
    }

    pub fn subscribe_ended(&self) -> watch::Receiver<bool> {
        self.ended_tx.subscribe()
    }

    pub fn is_ended(&self) -> bool {
        *self.ended_tx.borrow()
    }

    fn set_reason(&self, reason: String) {
        if let Ok(mut slot) = self.reason.lock() {
            if slot.is_none() {
                *slot = Some(reason);
            }
        }
    }

    /// Called exactly when russh's session task is gone (handler dropped).
    fn finish(&self) {
        let reason = self
            .reason
            .lock()
            .ok()
            .and_then(|r| r.clone())
            .unwrap_or_else(|| "closed".into());
        if let Some(callback) = self.take_keepalive() {
            callback.call(reason, ThreadsafeFunctionCallMode::NonBlocking);
            // Dropping releases the threadsafe function, so the event loop may exit.
            drop(callback);
        }
        self.ended_tx.send_replace(true);
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
    /// `connect()`: ask JS, await its promise.
    Verify(Option<VerifyFn>),
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
    async fn reject(&self, kind: &str, reply: ChannelOpenHandle) {
        self.shared.record_rejected(kind);
        reply
            .reject(ChannelOpenFailure::AdministrativelyProhibited)
            .await;
    }
}

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
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let info = describe(server_public_key);
        match &mut self.host_check {
            HostCheck::Scan(slot) => {
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
                let accepted = match verifier.call_async_catch(info).await {
                    Ok(promise) => promise.await.unwrap_or(false),
                    Err(_) => false,
                };
                Ok(accepted)
            }
        }
    }

    async fn disconnected(
        &mut self,
        reason: DisconnectReason<Self::Error>,
    ) -> Result<(), Self::Error> {
        match reason {
            DisconnectReason::ReceivedDisconnect(_) => self.shared.set_reason("remote".into()),
            DisconnectReason::Error(e) => self
                .shared
                .set_reason(from_russh(&e).code.as_str().to_owned()),
        }
        Ok(())
    }

    async fn server_channel_open_agent_forward(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        #[cfg(unix)]
        if let Some(socket) = self.agent_forward_socket.clone() {
            reply.accept().await;
            if let Ok(mut n) = self.shared.agent_channels_bridged.lock() {
                *n += 1;
            }
            let binding = self.shared.binding.get().cloned();
            tokio::spawn(bridge_agent(channel, socket, binding));
            return Ok(());
        }
        drop(channel);
        self.reject("auth-agent@openssh.com", reply).await;
        Ok(())
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
        self.reject("forwarded-tcpip", reply).await;
        Ok(())
    }

    async fn server_channel_open_forwarded_streamlocal(
        &mut self,
        _channel: Channel<Msg>,
        _socket_path: &str,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.reject("forwarded-streamlocal@openssh.com", reply)
            .await;
        Ok(())
    }

    async fn server_channel_open_x11(
        &mut self,
        _channel: Channel<Msg>,
        _originator_address: &str,
        _originator_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.reject("x11", reply).await;
        Ok(())
    }

    async fn server_channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.reject("session", reply).await;
        Ok(())
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
        self.reject("direct-tcpip", reply).await;
        Ok(())
    }

    async fn server_channel_open_direct_streamlocal(
        &mut self,
        _channel: Channel<Msg>,
        _socket_path: &str,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.reject("direct-streamlocal@openssh.com", reply).await;
        Ok(())
    }

    async fn should_accept_unknown_server_channel(
        &mut self,
        _id: russh::ChannelId,
        channel_type: &str,
    ) -> bool {
        self.shared.record_rejected(channel_type);
        false
    }
}
