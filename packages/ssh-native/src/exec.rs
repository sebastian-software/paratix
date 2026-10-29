//! Exec channels: streamed stdout/stderr events with stdout backpressure,
//! stdin writes, exit status.
//!
//! # Event order
//!
//! A detached reader task forwards every channel message through ONE
//! threadsafe function, so the JS wrapper sees stdout/stderr data, then
//! exactly one `exit`, in channel order. If the channel ends without
//! `CHANNEL_CLOSE` (connection loss), the reader waits for the end of the
//! session and sends the exit with the disconnect reason attached; the
//! wrapper reports the session disconnect first and the exit after it.
//!
//! # Backpressure
//!
//! The reader only reads the next channel message while fewer than
//! [`STDOUT_QUEUE_LIMIT`] bytes of stdout are unacknowledged by JS. The
//! wrapper acknowledges stdout as its `Readable` accepts the data (`push()`
//! returned `true`, or `_read()` was called). Because russh reopens the SSH
//! window on receipt and blocks its session loop once the channel buffer is
//! full, a paused stdout stalls the whole connection (documented limit).
//! stderr is not counted: it flows into a JS buffer while stdout flows.
//!
//! # Panics
//!
//! The reader runs under `catch_unwind`. A panic ends stdout and stderr with
//! an `internal` event (no exit) and closes the channel.

use std::collections::VecDeque;
use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;

use bytes::Bytes;
use futures::FutureExt;
use napi::bindgen_prelude::{Buffer, External, Function, PromiseRaw};
use napi::threadsafe_function::{ThreadsafeFunction, ThreadsafeFunctionCallMode};
use napi::{sys, Env, Status};
use napi_derive::napi;
use russh::client::{Handle, Msg};
use russh::{ChannelMsg, ChannelReadHalf, ChannelWriteHalf, Sig};
use tokio::sync::watch;

use crate::connect::MAXIMUM_PACKET_SIZE;
use crate::error::{BindingError, BindingResult, Code};
use crate::guarded;
use crate::handler::{ClientHandler, DisconnectInfo, Shared};
use crate::js::{guarded_value, JsObjectBuilder};
use crate::secret::{copy_secret, SecretBytes};
use crate::signal::Flag;

/// Maximum number of stdout bytes delivered to JS but not yet taken by the
/// JS `Readable` (1 MiB). The reader stops reading the channel at this
/// bound, which bounds memory for a slow stdout consumer.
pub const STDOUT_QUEUE_LIMIT: u64 = 1_048_576;

/// The largest data chunk one channel message can carry.
const MAX_CHUNK: u64 = MAXIMUM_PACKET_SIZE as u64;

/// One event of an exec channel, delivered in order through one threadsafe
/// function, so `exit` is always the last event after all output.
#[derive(Debug)]
pub enum ExecEvent {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    Exit {
        code: Option<u32>,
        signal: Option<String>,
        /// Set when the channel ended through the loss of the connection.
        disconnected: Option<DisconnectInfo>,
    },
    /// The reader panicked: streams end with `INTERNAL`, no exit follows.
    Internal,
    /// `__internalPanicProbe("event")`: panics while converting to JS.
    PanicProbe,
}

impl ExecEvent {
    /// `{ kind, data?, code?, signal?, disconnected?, reason?, reasonCode? }`
    #[allow(clippy::panic)]
    fn into_js(self, env: &Env) -> napi::Result<sys::napi_value> {
        let object = match self {
            ExecEvent::Stdout(data) => {
                JsObjectBuilder::new(env, "stdout")?.set("data", Some(Buffer::from(data)))?
            }
            ExecEvent::Stderr(data) => {
                JsObjectBuilder::new(env, "stderr")?.set("data", Some(Buffer::from(data)))?
            }
            ExecEvent::Exit {
                code,
                signal,
                disconnected,
            } => JsObjectBuilder::new(env, "exit")?
                .set("code", code)?
                .set("signal", signal)?
                .set("disconnected", Some(disconnected.is_some()))?
                .set("reason", disconnected.as_ref().map(|d| d.reason))?
                .set(
                    "reasonCode",
                    disconnected.as_ref().and_then(|d| d.code.map(Code::as_str)),
                )?,
            ExecEvent::Internal => JsObjectBuilder::new(env, "internal")?,
            ExecEvent::PanicProbe => panic!("event panic probe"),
        };
        Ok(object.finish())
    }
}

/// NOT weak: an open exec channel keeps the event loop alive until its final
/// event is delivered, even after the session's own handle was released on
/// connection loss. The reader drops it right after the final event.
pub type ExecEventFn = ThreadsafeFunction<ExecEvent, (), sys::napi_value, Status, false, false>;

/// Builds the event sink from the JS listener. The JS value of every event
/// is built inside `catch_unwind` (see `js.rs`).
pub fn event_sink(listener: &Function<'_, sys::napi_value, ()>) -> napi::Result<Arc<ExecEventFn>> {
    let threadsafe = listener
        .build_threadsafe_function::<ExecEvent>()
        .weak::<false>()
        .build_callback(|ctx| Ok(guarded_value(&ctx.env, |env| ctx.value.into_js(env))))?;
    Ok(Arc::new(threadsafe))
}

fn send(sink: &ExecEventFn, event: ExecEvent) {
    sink.call(event, ThreadsafeFunctionCallMode::NonBlocking);
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

/// Where the reader gets its channel messages from: the russh channel in
/// production, an internal source for the panic probe.
pub trait MessageSource: Send + 'static {
    fn next(&mut self) -> impl Future<Output = Option<ChannelMsg>> + Send;
}

impl MessageSource for ChannelReadHalf {
    async fn next(&mut self) -> Option<ChannelMsg> {
        self.wait().await
    }
}

/// Stdout credit and cancellation shared by the reader and `ExecChannel`.
pub struct Flow {
    acked: watch::Sender<u64>,
    cancel: Flag,
}

impl Flow {
    pub fn new() -> Arc<Self> {
        let (acked, _) = watch::channel(0);
        Arc::new(Self {
            acked,
            cancel: Flag::new(),
        })
    }

    fn ack(&self, bytes: u32) {
        self.acked
            .send_modify(|total| *total = total.saturating_add(u64::from(bytes)));
    }
}

/// What the reader needs to know about the session it belongs to.
#[derive(Clone)]
pub struct SessionLink {
    pub ended: Flag,
    pub killed: Flag,
    pub shared: Option<Arc<Shared>>,
}

enum ReadEnd {
    /// `CHANNEL_CLOSE` arrived.
    Closed,
    /// The channel ended without `CHANNEL_CLOSE`: the session is gone.
    Lost,
    /// JS cancelled the channel (or `destroy()` while waiting for credit).
    Cancelled,
}

struct ReadState {
    sent: u64,
    code: Option<u32>,
    signal: Option<String>,
}

/// Waits until one more full chunk fits under [`STDOUT_QUEUE_LIMIT`].
/// Returns `false` when the channel was cancelled or the session killed.
async fn wait_for_credit(state: &ReadState, flow: &Flow, link: &SessionLink) -> bool {
    let sent = state.sent;
    let fits = move |acked: &u64| sent.saturating_sub(*acked) + MAX_CHUNK <= STDOUT_QUEUE_LIMIT;
    let mut acked = flow.acked.subscribe();
    if fits(&acked.borrow()) {
        return true;
    }
    tokio::select! {
        biased;
        () = flow.cancel.fired() => false,
        () = link.killed.fired() => false,
        result = acked.wait_for(fits) => result.is_ok(),
    }
}

async fn read_loop<S: MessageSource>(
    source: &mut S,
    prefix: VecDeque<ChannelMsg>,
    sink: &ExecEventFn,
    flow: &Flow,
    link: &SessionLink,
    state: &mut ReadState,
) -> ReadEnd {
    let mut prefix = prefix;
    loop {
        if !wait_for_credit(state, flow, link).await {
            return ReadEnd::Cancelled;
        }
        let msg = if let Some(msg) = prefix.pop_front() {
            Some(msg)
        } else {
            tokio::select! {
                biased;
                () = flow.cancel.fired() => return ReadEnd::Cancelled,
                msg = source.next() => msg,
            }
        };
        match msg {
            Some(ChannelMsg::Data { data }) => {
                state.sent += data.len() as u64;
                send(sink, ExecEvent::Stdout(data.to_vec()));
            }
            Some(ChannelMsg::ExtendedData { data, ext: 1 }) => {
                send(sink, ExecEvent::Stderr(data.to_vec()));
            }
            Some(ChannelMsg::ExitStatus { exit_status }) => state.code = Some(exit_status),
            Some(ChannelMsg::ExitSignal { signal_name: s, .. }) => {
                state.signal = Some(signal_name(&s));
            }
            Some(ChannelMsg::Close) => return ReadEnd::Closed,
            Some(_) => {}
            None => return ReadEnd::Lost,
        }
    }
}

/// The exec reader. Also used by `__internalPanicProbe("execReader")` with
/// an internal message source, so the probe runs exactly this code.
pub async fn run_reader<S: MessageSource>(
    mut source: S,
    prefix: VecDeque<ChannelMsg>,
    sink: Arc<ExecEventFn>,
    flow: Arc<Flow>,
    link: SessionLink,
    closer: Option<Arc<ChannelWriteHalf<Msg>>>,
) {
    let mut state = ReadState {
        sent: 0,
        code: None,
        signal: None,
    };
    let outcome = AssertUnwindSafe(read_loop(
        &mut source,
        prefix,
        &sink,
        &flow,
        &link,
        &mut state,
    ))
    .catch_unwind()
    .await;
    // Release the channel receiver first: russh's session loop may be
    // blocked on delivering into it.
    drop(source);
    match outcome {
        Ok(ReadEnd::Closed) => send(
            &sink,
            ExecEvent::Exit {
                code: state.code,
                signal: state.signal,
                disconnected: None,
            },
        ),
        Ok(ReadEnd::Lost) => {
            link.ended.fired().await;
            let info = link
                .shared
                .as_ref()
                .map(|shared| shared.disconnect_info())
                .unwrap_or(DisconnectInfo {
                    reason: "error",
                    code: Some(Code::Disconnected),
                });
            // A channel that ended through connection loss never reports
            // an exit code.
            send(
                &sink,
                ExecEvent::Exit {
                    code: None,
                    signal: None,
                    disconnected: Some(info),
                },
            );
        }
        Ok(ReadEnd::Cancelled) => {
            if let Some(closer) = closer {
                let _ = closer.close().await;
            }
        }
        Err(_) => {
            send(&sink, ExecEvent::Internal);
            if let Some(closer) = closer {
                let _ = closer.close().await;
            }
        }
    }
}

/// Native side of one exec channel, handed to JS as an external.
pub struct ExecCore {
    write: Arc<ChannelWriteHalf<Msg>>,
    flow: Arc<Flow>,
}

pub type ExecChannel = External<ExecCore>;

fn channel_closed() -> BindingError {
    BindingError::new(Code::Disconnected, "the exec channel is closed")
}

/// Waits for the server's reply to the exec request. Data that arrives
/// before it is kept for the reader.
async fn await_exec_reply(read: &mut ChannelReadHalf) -> BindingResult<VecDeque<ChannelMsg>> {
    let mut prefix = VecDeque::new();
    loop {
        match read.wait().await {
            Some(ChannelMsg::Success) => return Ok(prefix),
            Some(ChannelMsg::Failure) => {
                return Err(BindingError::with_detail(
                    Code::ChannelOpenFailed,
                    "exec-refused",
                    "the server refused the exec request",
                ))
            }
            Some(ChannelMsg::Close) | None => return Err(channel_closed()),
            Some(other) => prefix.push_back(other),
        }
    }
}

pub struct ExecRequest {
    pub command: String,
    /// Initial stdin (Paratix passes sudo passwords this way).
    pub stdin: Option<SecretBytes>,
    pub agent_forward: bool,
}

async fn open_exec(
    handle: &Handle<ClientHandler>,
    request: &ExecRequest,
) -> BindingResult<(
    ChannelReadHalf,
    Arc<ChannelWriteHalf<Msg>>,
    VecDeque<ChannelMsg>,
)> {
    let channel = handle.channel_open_session().await?;
    if request.agent_forward {
        // auth-agent-req@openssh.com without want_reply, as OpenSSH does.
        channel.agent_forward(false).await?;
    }
    channel.exec(true, request.command.as_bytes()).await?;
    let (mut read, write) = channel.split();
    let write = Arc::new(write);
    let prefix = match await_exec_reply(&mut read).await {
        Ok(prefix) => prefix,
        Err(err) => {
            let _ = write.close().await;
            return Err(err);
        }
    };
    if let Some(stdin) = &request.stdin {
        write
            .data_bytes(Bytes::copy_from_slice(stdin))
            .await
            .map_err(|_| channel_closed())?;
    }
    Ok((read, write, prefix))
}

pub async fn start_exec(
    handle: &Handle<ClientHandler>,
    shared: Arc<Shared>,
    request: ExecRequest,
    abort: Flag,
    sink: Arc<ExecEventFn>,
) -> BindingResult<ExecChannel> {
    let opened = tokio::select! {
        biased;
        () = abort.fired() => return Err(BindingError::aborted()),
        opened = open_exec(handle, &request) => opened?,
    };
    drop(request);
    let (read, write, prefix) = opened;
    let flow = Flow::new();
    let link = SessionLink {
        ended: shared.ended.clone(),
        killed: shared.killed(),
        shared: Some(shared),
    };
    tokio::spawn(run_reader(
        read,
        prefix,
        sink,
        flow.clone(),
        link,
        Some(write.clone()),
    ));
    Ok(External::new(ExecCore { write, flow }))
}

/// Acknowledges stdout bytes the JS `Readable` has taken.
#[napi(js_name = "execAckStdout", skip_typescript, catch_unwind)]
pub fn exec_ack_stdout(channel: &ExecChannel, bytes: u32) {
    channel.flow.ack(bytes);
}

/// Writes to the remote stdin. The chunk is copied into a zeroizing buffer
/// synchronously; the promise resolves once russh accepted the data into
/// the channel window (natural backpressure).
#[napi(js_name = "execWrite", skip_typescript, catch_unwind)]
pub fn exec_write<'env>(
    env: &'env Env,
    channel: &ExecChannel,
    chunk: Buffer,
) -> napi::Result<PromiseRaw<'env, ()>> {
    let data = copy_secret(&chunk);
    drop(chunk);
    let write = channel.write.clone();
    env.spawn_future(guarded(async move {
        write
            .data_bytes(Bytes::copy_from_slice(&data))
            .await
            .map_err(|_| channel_closed())
    }))
}

/// Sends EOF on stdin.
#[napi(js_name = "execEnd", skip_typescript, catch_unwind)]
pub fn exec_end<'env>(env: &'env Env, channel: &ExecChannel) -> napi::Result<PromiseRaw<'env, ()>> {
    let write = channel.write.clone();
    env.spawn_future(guarded(async move {
        write.eof().await.map_err(|_| channel_closed())
    }))
}

/// Sends `CHANNEL_CLOSE`; the exit follows once the server confirms.
#[napi(js_name = "execClose", skip_typescript, catch_unwind)]
pub fn exec_close<'env>(
    env: &'env Env,
    channel: &ExecChannel,
) -> napi::Result<PromiseRaw<'env, ()>> {
    let write = channel.write.clone();
    env.spawn_future(guarded(async move {
        let _ = write.close().await;
        Ok(())
    }))
}

/// Stops the reader without an exit event and closes the channel.
#[napi(js_name = "execCancel", skip_typescript, catch_unwind)]
pub fn exec_cancel(channel: &ExecChannel) {
    channel.flow.cancel.fire();
}

/// Message source of `__internalPanicProbe("execReader")`.
pub struct PanicSource;

impl MessageSource for PanicSource {
    #[allow(clippy::panic)]
    async fn next(&mut self) -> Option<ChannelMsg> {
        if std::hint::black_box(true) {
            panic!("exec reader panic probe");
        }
        None
    }
}

/// Runs the production reader against [`PanicSource`].
pub fn spawn_reader_probe(sink: Arc<ExecEventFn>) {
    let ended = Flag::new();
    ended.fire();
    let link = SessionLink {
        ended,
        killed: Flag::new(),
        shared: None,
    };
    tokio::spawn(run_reader(
        PanicSource,
        VecDeque::new(),
        sink,
        Flow::new(),
        link,
        None,
    ));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::tests::assert_zeroize_on_drop;

    #[test]
    fn exec_stdin_is_zeroizing() {
        let request = ExecRequest {
            command: String::new(),
            stdin: Some(SecretBytes::default()),
            agent_forward: false,
        };
        if let Some(stdin) = &request.stdin {
            assert_zeroize_on_drop(stdin);
        }
    }

    #[test]
    fn stdout_credit_keeps_a_full_chunk_under_the_limit() {
        let fits =
            |sent: u64, acked: u64| sent.saturating_sub(acked) + MAX_CHUNK <= STDOUT_QUEUE_LIMIT;
        assert!(fits(0, 0));
        assert!(fits(STDOUT_QUEUE_LIMIT - MAX_CHUNK, 0));
        assert!(!fits(STDOUT_QUEUE_LIMIT - MAX_CHUNK + 1, 0));
        assert!(fits(STDOUT_QUEUE_LIMIT, STDOUT_QUEUE_LIMIT));
    }
}
