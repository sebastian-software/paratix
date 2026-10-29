//! Exec channels: streamed stdout/stderr events, stdin writes, exit status.

use std::sync::Arc;

use napi::bindgen_prelude::{Buffer, PromiseRaw};
use napi::threadsafe_function::{ThreadsafeFunction, ThreadsafeFunctionCallMode};
use napi::{Env, Status};
use napi_derive::napi;
use russh::client::{Handle, Msg};
use russh::{ChannelMsg, ChannelWriteHalf, Sig};

use crate::error::{Code, SpikeError, SpikeResult};
use crate::guarded;
use crate::handler::ClientHandler;

/// One event of an exec channel, delivered in order through one threadsafe
/// function, so `exit` is always the last event after all output.
#[napi(object)]
pub struct ExecEvent {
    /// `stdout`, `stderr`, `exit` or `failure` (server refused the exec request).
    pub kind: String,
    pub data: Option<Buffer>,
    pub code: Option<u32>,
    pub signal: Option<String>,
}

/// Weak: an open connection already keeps the event loop alive.
pub type ExecEventFn = ThreadsafeFunction<ExecEvent, (), ExecEvent, Status, false, true>;

#[napi]
pub struct ExecChannel {
    write: Arc<ChannelWriteHalf<Msg>>,
}

fn signal_name(sig: &Sig) -> String {
    match sig {
        Sig::ABRT => "ABRT".into(),
        Sig::ALRM => "ALRM".into(),
        Sig::FPE => "FPE".into(),
        Sig::HUP => "HUP".into(),
        Sig::ILL => "ILL".into(),
        Sig::INT => "INT".into(),
        Sig::KILL => "KILL".into(),
        Sig::PIPE => "PIPE".into(),
        Sig::QUIT => "QUIT".into(),
        Sig::SEGV => "SEGV".into(),
        Sig::TERM => "TERM".into(),
        Sig::USR1 => "USR1".into(),
        Sig::Custom(name) => name.clone(),
    }
}

fn event(kind: &str) -> ExecEvent {
    ExecEvent {
        kind: kind.into(),
        data: None,
        code: None,
        signal: None,
    }
}

pub async fn start_exec(
    handle: &Handle<ClientHandler>,
    command: String,
    agent_forward: bool,
    on_event: ExecEventFn,
) -> SpikeResult<ExecChannel> {
    let channel = handle.channel_open_session().await?;
    if agent_forward {
        // auth-agent-req@openssh.com without want_reply, as OpenSSH does.
        channel.agent_forward(false).await?;
    }
    channel.exec(true, command).await?;
    let (mut read, write) = channel.split();
    tokio::spawn(async move {
        let mut code = None;
        let mut signal = None;
        while let Some(msg) = read.wait().await {
            match msg {
                ChannelMsg::Data { data } => {
                    let mut ev = event("stdout");
                    ev.data = Some(Buffer::from(data.to_vec()));
                    on_event.call(ev, ThreadsafeFunctionCallMode::NonBlocking);
                }
                ChannelMsg::ExtendedData { data, ext } => {
                    let mut ev = event(if ext == 1 { "stderr" } else { "extended" });
                    ev.data = Some(Buffer::from(data.to_vec()));
                    on_event.call(ev, ThreadsafeFunctionCallMode::NonBlocking);
                }
                ChannelMsg::ExitStatus { exit_status } => code = Some(exit_status),
                ChannelMsg::ExitSignal { signal_name: s, .. } => signal = Some(signal_name(&s)),
                ChannelMsg::Failure => {
                    on_event.call(event("failure"), ThreadsafeFunctionCallMode::NonBlocking);
                }
                ChannelMsg::Close => break,
                _ => {}
            }
        }
        let mut ev = event("exit");
        ev.code = code;
        ev.signal = signal;
        on_event.call(ev, ThreadsafeFunctionCallMode::NonBlocking);
    });
    Ok(ExecChannel {
        write: Arc::new(write),
    })
}

#[napi]
impl ExecChannel {
    /// Writes to the remote stdin. Resolves once russh accepted the data
    /// into the channel window (natural backpressure).
    #[napi]
    pub fn write<'env>(&self, env: &'env Env, chunk: Buffer) -> napi::Result<PromiseRaw<'env, ()>> {
        let data = chunk.to_vec();
        let write = self.write.clone();
        env.spawn_future(guarded(async move {
            write
                .data_bytes(data)
                .await
                .map_err(|_| SpikeError::new(Code::Disconnected, "the exec channel is closed"))
        }))
    }

    /// Sends EOF on stdin.
    #[napi]
    pub fn end<'env>(&self, env: &'env Env) -> napi::Result<PromiseRaw<'env, ()>> {
        let write = self.write.clone();
        env.spawn_future(guarded(async move {
            write
                .eof()
                .await
                .map_err(|_| SpikeError::new(Code::Disconnected, "the exec channel is closed"))
        }))
    }

    #[napi]
    pub fn close<'env>(&self, env: &'env Env) -> napi::Result<PromiseRaw<'env, ()>> {
        let write = self.write.clone();
        env.spawn_future(guarded(async move {
            let _ = write.close().await;
            Ok(())
        }))
    }
}
