//! `scan()`, `connect()` and the `NativeSession` class.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use napi::bindgen_prelude::{Buffer, External, Function, Promise, PromiseRaw};
use napi::{sys, Env};
use napi_derive::napi;
use russh::client::Handle;
use russh::Disconnect;

use crate::auth::{authenticate, AuthInfo, AuthInput};
use crate::connect::{bounded, tcp_and_handshake};
use crate::error::{BindingError, Code};
use crate::exec::{event_sink, start_exec, ExecChannel, ExecRequest};
use crate::guarded;
use crate::handler::{ClientHandler, DisconnectFn, DisconnectInfo, HostCheck, Shared, VerifyFn};
use crate::hostkey::HostKeyInfo;
use crate::js::{guarded_value, to_js};
use crate::secret::copy_secret;
use crate::sftp::{open_sftp, NativeSftp};
use crate::signal::{AbortHandle, Flag};

fn port_of(port: u32) -> napi::Result<u16> {
    u16::try_from(port)
        .ok()
        .filter(|p| *p != 0)
        .ok_or_else(|| BindingError::new(Code::ConnectFailed, "invalid port").into())
}

/// Handshake without authentication; returns the presented host key.
#[napi(skip_typescript, catch_unwind)]
pub fn scan<'env>(
    env: &'env Env,
    host: String,
    port: u32,
    timeout_ms: u32,
    abort: &AbortHandle,
) -> napi::Result<PromiseRaw<'env, HostKeyInfo>> {
    let port = port_of(port)?;
    let abort: Flag = (**abort).clone();
    env.spawn_future(guarded(async move {
        let slot = Arc::new(Mutex::new(None));
        let shared = Shared::new(None);
        let handler = ClientHandler {
            host_check: HostCheck::Scan(slot.clone()),
            agent_forward_socket: None,
            shared: shared.clone(),
        };
        let result = bounded(
            &shared,
            timeout_ms,
            &abort,
            "the host key scan timed out",
            async { tcp_and_handshake(&host, port, handler).await },
        )
        .await;
        shared.kill();
        let captured = slot.lock().ok().and_then(|mut s| s.take());
        match (captured, result) {
            (Some(info), _) => Ok(info),
            (None, Err(err)) => Err(err),
            (None, Ok(_)) => Err(BindingError::new(
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

/// Native side of one connection, handed to JS as an external.
pub struct SessionCore {
    inner: Arc<SessionInner>,
    auth: AuthInfo,
}

pub type NativeSession = External<SessionCore>;

fn verifier(listener: &Function<'_, sys::napi_value, Promise<bool>>) -> napi::Result<VerifyFn> {
    listener
        .build_threadsafe_function::<HostKeyInfo>()
        .weak::<true>()
        .build_callback(|ctx| Ok(guarded_value(&ctx.env, |env| to_js(env, ctx.value))))
}

fn disconnect_listener(listener: &Function<'_, sys::napi_value, ()>) -> napi::Result<DisconnectFn> {
    listener
        .build_threadsafe_function::<DisconnectInfo>()
        .weak::<false>()
        .build_callback(|ctx| Ok(guarded_value(&ctx.env, |env| ctx.value.to_js(env))))
}

struct ConnectInput {
    host: String,
    port: u32,
    user: String,
    ready_timeout_ms: u32,
    agent: Option<String>,
    private_key: Option<Buffer>,
    password: Option<Buffer>,
    agent_forward: bool,
}

/// Connects, verifies the host key through `verify_host` (async JS) and
/// authenticates. `on_disconnect` doubles as the ref'd event-loop handle.
#[napi(skip_typescript, catch_unwind)]
#[allow(clippy::too_many_arguments)]
pub fn connect<'env>(
    env: &'env Env,
    host: String,
    port: u32,
    user: String,
    ready_timeout_ms: u32,
    agent: Option<String>,
    private_key: Option<Buffer>,
    password: Option<Buffer>,
    agent_forward: bool,
    verify_host: Function<'_, sys::napi_value, Promise<bool>>,
    on_disconnect: Function<'_, sys::napi_value, ()>,
    abort: &AbortHandle,
) -> napi::Result<PromiseRaw<'env, NativeSession>> {
    let options = ConnectInput {
        host,
        port,
        user,
        ready_timeout_ms,
        agent,
        private_key,
        password,
        agent_forward,
    };
    let port = port_of(options.port)?;
    // Copy secrets synchronously: JS zero-fills its buffers right after this
    // call returns, before the future below runs.
    let auth = if let Some(socket) = options.agent.clone() {
        AuthInput::Agent(socket)
    } else if let Some(key) = options.private_key.as_ref() {
        AuthInput::PrivateKey(copy_secret(key))
    } else if let Some(password) = options.password.as_ref() {
        AuthInput::Password(copy_secret(password))
    } else {
        return Err(BindingError::new(Code::AuthFailed, "no authentication method given").into());
    };
    let agent_forward = options.agent_forward;
    let agent_forward_socket = match (agent_forward, options.agent.clone()) {
        (false, _) => None,
        (true, Some(socket)) => Some(socket),
        (true, None) => {
            return Err(BindingError::new(
                Code::AuthFailed,
                "agentForward requires an agent socket",
            )
            .into())
        }
    };
    let verify_host = verifier(&verify_host)?;
    let on_disconnect = disconnect_listener(&on_disconnect)?;
    let abort: Flag = (**abort).clone();
    let timeout_ms = options.ready_timeout_ms;
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
        let session_shared = shared.clone();
        let (handle, auth_info) = bounded(
            &shared,
            timeout_ms,
            &abort,
            "the SSH handshake timed out",
            async move {
                let mut handle = tcp_and_handshake(&host, port, handler).await?;
                if let Some(binding) = handle.agent_session_binding() {
                    let _ = session_shared.binding.set(binding.clone());
                }
                let info = authenticate(&mut handle, &user, auth).await?;
                Ok((handle, info))
            },
        )
        .await?;
        Ok(External::new(SessionCore {
            inner: Arc::new(SessionInner {
                handle,
                shared,
                agent_forward,
            }),
            auth: auth_info,
        }))
    }))
}

#[napi(object, object_from_js = false)]
pub struct ChannelStats {
    /// Types of server-opened channels this client rejected.
    pub rejected: Vec<String>,
    /// Server-opened agent channels that were accepted and bridged.
    pub agent_channels_bridged: u32,
}

#[napi(js_name = "sessionAuthInfo", skip_typescript, catch_unwind)]
pub fn session_auth_info(session: &NativeSession) -> AuthInfo {
    session.auth.clone()
}

#[napi(js_name = "sessionClosed", skip_typescript, catch_unwind)]
pub fn session_closed(session: &NativeSession) -> bool {
    session.inner.shared.is_ended()
}

#[napi(js_name = "sessionChannelStats", skip_typescript, catch_unwind)]
pub fn session_channel_stats(session: &NativeSession) -> ChannelStats {
    let shared = &session.inner.shared;
    ChannelStats {
        rejected: shared
            .rejected
            .lock()
            .map(|l| l.clone())
            .unwrap_or_default(),
        agent_channels_bridged: shared
            .agent_channels_bridged
            .load(std::sync::atomic::Ordering::SeqCst),
    }
}

#[napi(js_name = "sessionExec", skip_typescript, catch_unwind)]
pub fn session_exec<'env>(
    env: &'env Env,
    session: &NativeSession,
    command: String,
    stdin: Option<Buffer>,
    abort: &AbortHandle,
    on_event: Function<'_, sys::napi_value, ()>,
) -> napi::Result<PromiseRaw<'env, ExecChannel>> {
    // Copied synchronously into a zeroizing buffer, see `connect`.
    let request = ExecRequest {
        command,
        stdin: stdin.as_ref().map(copy_secret),
        agent_forward: session.inner.agent_forward,
    };
    drop(stdin);
    let sink = event_sink(&on_event)?;
    let abort: Flag = (**abort).clone();
    let inner = session.inner.clone();
    env.spawn_future(guarded(async move {
        if inner.shared.is_ended() || inner.shared.is_killed() {
            return Err(BindingError::disconnected());
        }
        start_exec(&inner.handle, inner.shared.clone(), request, abort, sink).await
    }))
}

/// Opens an SFTP subsystem channel.
#[napi(js_name = "sessionSftp", skip_typescript, catch_unwind)]
pub fn session_sftp<'env>(
    env: &'env Env,
    session: &NativeSession,
) -> napi::Result<PromiseRaw<'env, NativeSftp>> {
    let inner = session.inner.clone();
    env.spawn_future(guarded(async move {
        if inner.shared.is_ended() || inner.shared.is_killed() {
            return Err(BindingError::disconnected());
        }
        open_sftp(&inner.handle).await
    }))
}

/// Graceful close: SSH_MSG_DISCONNECT, wait for the session task to end
/// (bounded), then the event-loop handle is released.
#[napi(js_name = "sessionClose", skip_typescript, catch_unwind)]
pub fn session_close<'env>(
    env: &'env Env,
    session: &NativeSession,
) -> napi::Result<PromiseRaw<'env, ()>> {
    let inner = session.inner.clone();
    inner.shared.mark_local_close();
    env.spawn_future(guarded(async move {
        if !inner.shared.is_ended() {
            let _ = inner
                .handle
                .disconnect(Disconnect::ByApplication, "", "en")
                .await;
            let waited =
                tokio::time::timeout(Duration::from_secs(5), inner.shared.ended.fired()).await;
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
/// socket down, stops every exec reader and un-refs the event-loop handle
/// on the JS thread.
#[napi(js_name = "sessionDestroy", skip_typescript, catch_unwind)]
pub fn session_destroy(env: Env, session: &NativeSession) {
    session.inner.shared.mark_local_close();
    session.inner.shared.kill();
    if let Some(mut keepalive) = session.inner.shared.take_keepalive() {
        // Synchronous un-ref on the JS thread, so the event loop can exit
        // before the session task has noticed the shut-down socket.
        #[allow(deprecated)]
        let _ = keepalive.unref(&env);
        drop(keepalive);
    }
}
