//! `scan()`, `connect()` and the `NativeSession` class.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use napi::bindgen_prelude::{Buffer, PromiseRaw};
use napi::Env;
use napi_derive::napi;
use russh::client::Handle;
use russh::Disconnect;
use zeroize::Zeroizing;

use crate::auth::{authenticate, AuthInfo, AuthInput};
use crate::connect::{tcp_and_handshake, with_deadline};
use crate::error::{Code, SpikeError};
use crate::exec::{start_exec, ExecChannel, ExecEventFn};
use crate::guarded;
use crate::handler::{ClientHandler, DisconnectFn, HostCheck, Shared, VerifyFn};
use crate::hostkey::HostKeyInfo;
use crate::sftp::{open_writer, SftpWriter};

#[napi(object)]
pub struct ScanOptions {
    pub host: String,
    pub port: u32,
    pub timeout_ms: u32,
    pub host_certificates: Option<bool>,
}

#[napi(object)]
pub struct ConnectOptions {
    pub host: String,
    pub port: u32,
    pub user: String,
    pub ready_timeout_ms: Option<u32>,
    pub agent: Option<String>,
    pub private_key: Option<Buffer>,
    pub password: Option<Buffer>,
    pub agent_forward: Option<bool>,
    pub host_certificates: Option<bool>,
}

fn port_of(port: u32) -> napi::Result<u16> {
    u16::try_from(port).map_err(|_| SpikeError::new(Code::ConnectFailed, "invalid port").into())
}

/// Handshake without authentication; returns the presented host key.
#[napi]
pub fn scan(env: &Env, options: ScanOptions) -> napi::Result<PromiseRaw<'_, HostKeyInfo>> {
    let port = port_of(options.port)?;
    let host_certificates = options.host_certificates.unwrap_or(false);
    let timeout_ms = options.timeout_ms;
    let host = options.host;
    env.spawn_future(guarded(async move {
        let slot = Arc::new(Mutex::new(None));
        let shared = Shared::new(None);
        let handler = ClientHandler {
            host_check: HostCheck::Scan(slot.clone()),
            agent_forward_socket: None,
            shared: shared.clone(),
        };
        let result = with_deadline(&shared, timeout_ms, async {
            tcp_and_handshake(&host, port, host_certificates, handler).await
        })
        .await;
        shared.kill();
        let captured = slot.lock().ok().and_then(|mut s| s.take());
        match (captured, result) {
            (Some(info), _) => Ok(info),
            (None, Err(err)) => Err(err),
            (None, Ok(_)) => Err(SpikeError::new(
                Code::Protocol,
                "the server completed the handshake without presenting a host key",
            )),
        }
    }))
}

struct SessionInner {
    handle: Handle<ClientHandler>,
    shared: Arc<Shared>,
    agent_forward: bool,
}

#[napi]
pub struct NativeSession {
    inner: Arc<SessionInner>,
    auth: AuthInfo,
}

/// Connects, verifies the host key through `verify_host` (async JS) and
/// authenticates. `on_disconnect` doubles as the ref'd event-loop handle.
#[napi]
pub fn connect<'env>(
    env: &'env Env,
    options: ConnectOptions,
    verify_host: VerifyFn,
    on_disconnect: DisconnectFn,
) -> napi::Result<PromiseRaw<'env, NativeSession>> {
    let port = port_of(options.port)?;
    // Copy secrets synchronously: JS zero-fills its buffers right after this
    // call returns, before the future below runs.
    let auth = if let Some(socket) = options.agent.clone() {
        AuthInput::Agent(socket)
    } else if let Some(key) = options.private_key.as_ref() {
        AuthInput::PrivateKey(Zeroizing::new(key.to_vec()))
    } else if let Some(password) = options.password.as_ref() {
        AuthInput::Password(Zeroizing::new(password.to_vec()))
    } else {
        return Err(SpikeError::new(Code::AuthFailed, "no authentication method given").into());
    };
    let agent_forward = options.agent_forward.unwrap_or(false);
    let agent_forward_socket = if agent_forward {
        match options.agent.clone() {
            Some(socket) => Some(socket),
            None => {
                return Err(SpikeError::new(
                    Code::AuthFailed,
                    "agentForward requires an agent socket",
                )
                .into())
            }
        }
    } else {
        None
    };
    let host_certificates = options.host_certificates.unwrap_or(false);
    let timeout_ms = options.ready_timeout_ms.unwrap_or(20_000);
    let host = options.host;
    let user = options.user;
    drop(options.private_key);
    drop(options.password);

    env.spawn_future(guarded(async move {
        let shared = Shared::new(Some(on_disconnect));
        let handler = ClientHandler {
            host_check: HostCheck::Verify(Some(verify_host)),
            agent_forward_socket,
            shared: shared.clone(),
        };
        let shared_for_deadline = shared.clone();
        let (handle, auth_info) = with_deadline(&shared_for_deadline, timeout_ms, async move {
            let mut handle = tcp_and_handshake(&host, port, host_certificates, handler).await?;
            if let Some(binding) = handle.agent_session_binding() {
                let _ = shared.binding.set(binding.clone());
            }
            let info = authenticate(&mut handle, &user, auth).await?;
            Ok((handle, info))
        })
        .await?;
        Ok(NativeSession {
            inner: Arc::new(SessionInner {
                handle,
                shared: shared_for_deadline,
                agent_forward,
            }),
            auth: auth_info,
        })
    }))
}

#[napi(object)]
pub struct ChannelStats {
    pub rejected: Vec<String>,
    pub agent_channels_bridged: u32,
}

#[napi]
impl NativeSession {
    #[napi(getter)]
    pub fn auth_info(&self) -> AuthInfo {
        self.auth.clone()
    }

    #[napi]
    pub fn channel_stats(&self) -> ChannelStats {
        let shared = &self.inner.shared;
        ChannelStats {
            rejected: shared
                .rejected
                .lock()
                .map(|l| l.clone())
                .unwrap_or_default(),
            agent_channels_bridged: shared
                .agent_channels_bridged
                .lock()
                .map(|n| *n)
                .unwrap_or(0),
        }
    }

    #[napi]
    pub fn exec<'env>(
        &self,
        env: &'env Env,
        command: String,
        on_event: ExecEventFn,
    ) -> napi::Result<PromiseRaw<'env, ExecChannel>> {
        let inner = self.inner.clone();
        env.spawn_future(guarded(async move {
            if inner.shared.is_ended() {
                return Err(SpikeError::disconnected());
            }
            start_exec(&inner.handle, command, inner.agent_forward, on_event).await
        }))
    }

    #[napi]
    pub fn sftp_open_write<'env>(
        &self,
        env: &'env Env,
        remote_path: String,
        mode: Option<u32>,
    ) -> napi::Result<PromiseRaw<'env, SftpWriter>> {
        let inner = self.inner.clone();
        env.spawn_future(guarded(async move {
            if inner.shared.is_ended() {
                return Err(SpikeError::disconnected());
            }
            open_writer(&inner.handle, remote_path, mode).await
        }))
    }

    /// Graceful close: SSH_MSG_DISCONNECT, wait for the session task to end
    /// (bounded), then the event-loop handle is released.
    #[napi]
    pub fn close<'env>(&self, env: &'env Env) -> napi::Result<PromiseRaw<'env, ()>> {
        let inner = self.inner.clone();
        env.spawn_future(guarded(async move {
            let mut ended = inner.shared.subscribe_ended();
            if !*ended.borrow() {
                let _ = inner
                    .handle
                    .disconnect(Disconnect::ByApplication, "", "en")
                    .await;
                let waited =
                    tokio::time::timeout(Duration::from_secs(5), ended.wait_for(|done| *done))
                        .await;
                if waited.is_err() {
                    inner.shared.kill();
                }
            }
            // Normally already released by the handler; this covers the kill path.
            drop(inner.shared.take_keepalive());
            Ok(())
        }))
    }

    /// Synchronous hard stop, safe right before `process.exit()`: shuts the
    /// socket down and un-refs the event-loop handle on the JS thread.
    #[napi]
    pub fn destroy(&self, env: Env) {
        self.inner.shared.kill();
        if let Some(mut keepalive) = self.inner.shared.take_keepalive() {
            #[allow(deprecated)]
            let _ = keepalive.unref(&env);
            drop(keepalive);
        }
    }

    #[napi(getter)]
    pub fn closed(&self) -> bool {
        self.inner.shared.is_ended()
    }
}
