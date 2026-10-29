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
use russh::{Channel, ChannelMsg, ChannelReadHalf, ChannelWriteHalf, Sig};
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

impl MessageSource for Channel<Msg> {
    async fn next(&mut self) -> Option<ChannelMsg> {
        self.wait().await
    }
}

/// Stdout credit, cancellation and close requests shared by the reader and
/// `ExecChannel`.
pub struct Flow {
    acked: watch::Sender<u64>,
    cancel: Flag,
    close: Flag,
}

impl Flow {
    pub fn new() -> Arc<Self> {
        let (acked, _) = watch::channel(0);
        Arc::new(Self {
            acked,
            cancel: Flag::new(),
            close: Flag::new(),
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
    /// The channel ended without `CHANNEL_CLOSE`, or the session ended or
    /// was killed (`destroy()`, `close()` fallback) while the reader waited
    /// for stdout credit: the exit reports the lost connection.
    Lost,
    /// JS called `close()`: the reader sends `CHANNEL_CLOSE` itself.
    CloseRequested,
    /// JS cancelled the channel: no exit event.
    Cancelled,
}

/// Why the reader stopped waiting before it could read the next message.
enum Interrupt {
    Cancel,
    Close,
    Ended,
    Killed,
}

struct ReadState {
    sent: u64,
    code: Option<u32>,
    signal: Option<String>,
}

/// Waits until one more full chunk fits under [`STDOUT_QUEUE_LIMIT`], or
/// until something ends the wait.
async fn wait_for_credit(
    state: &ReadState,
    flow: &Flow,
    link: &SessionLink,
) -> Result<(), Interrupt> {
    let sent = state.sent;
    let fits = move |acked: &u64| sent.saturating_sub(*acked) + MAX_CHUNK <= STDOUT_QUEUE_LIMIT;
    let mut acked = flow.acked.subscribe();
    if fits(&acked.borrow()) {
        return Ok(());
    }
    tokio::select! {
        biased;
        () = flow.cancel.fired() => Err(Interrupt::Cancel),
        () = flow.close.fired() => Err(Interrupt::Close),
        () = link.killed.fired() => Err(Interrupt::Killed),
        // The connection dropped while stdout was paused: russh's session
        // loop was not blocked on this channel, so it could end.
        () = link.ended.fired() => Err(Interrupt::Ended),
        result = acked.wait_for(fits) => result.map(|_| ()).map_err(|_| Interrupt::Cancel),
    }
}

/// Forwards one channel message. Returns `true` for `CHANNEL_CLOSE`.
fn forward(msg: ChannelMsg, sink: &ExecEventFn, state: &mut ReadState) -> bool {
    match msg {
        ChannelMsg::Data { data } => {
            state.sent += data.len() as u64;
            send(sink, ExecEvent::Stdout(data.to_vec()));
        }
        ChannelMsg::ExtendedData { data, ext: 1 } => {
            send(sink, ExecEvent::Stderr(data.to_vec()));
        }
        ChannelMsg::ExitStatus { exit_status } => state.code = Some(exit_status),
        ChannelMsg::ExitSignal { signal_name: s, .. } => {
            state.signal = Some(signal_name(&s));
        }
        ChannelMsg::Close => return true,
        _ => {}
    }
    false
}

/// Forwards every message that is already queued, without waiting and
/// without stdout credit. Returns `true` if `CHANNEL_CLOSE` was among them.
fn drain_queued<S: MessageSource>(
    source: &mut S,
    sink: &ExecEventFn,
    state: &mut ReadState,
) -> bool {
    while let Some(Some(msg)) = source.next().now_or_never() {
        if forward(msg, sink, state) {
            return true;
        }
    }
    false
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
        match wait_for_credit(state, flow, link).await {
            Ok(()) => {}
            Err(Interrupt::Cancel) => return ReadEnd::Cancelled,
            Err(Interrupt::Close) => return ReadEnd::CloseRequested,
            Err(Interrupt::Killed) => return ReadEnd::Lost,
            Err(Interrupt::Ended) => {
                return if drain_queued(source, sink, state) {
                    ReadEnd::Closed
                } else {
                    ReadEnd::Lost
                };
            }
        }
        let msg = if let Some(msg) = prefix.pop_front() {
            Some(msg)
        } else {
            tokio::select! {
                biased;
                () = flow.cancel.fired() => return ReadEnd::Cancelled,
                () = flow.close.fired() => return ReadEnd::CloseRequested,
                msg = source.next() => msg,
            }
        };
        match msg {
            Some(msg) => {
                if forward(msg, sink, state) {
                    return ReadEnd::Closed;
                }
            }
            None => return ReadEnd::Lost,
        }
    }
}

/// Sends `CHANNEL_CLOSE` for a JS `close()`. russh forgets a channel as
/// soon as the client closes it, so the server's `CHANNEL_CLOSE` never
/// reaches the reader; the exit is therefore sent here, after the messages
/// that were already queued.
async fn close_requested<S: MessageSource>(
    source: &mut S,
    sink: &ExecEventFn,
    state: &mut ReadState,
    closer: Option<&ChannelWriteHalf<Msg>>,
) {
    if let Some(closer) = closer {
        let close = closer.close();
        tokio::pin!(close);
        // Keep taking messages while the close is queued, so russh's session
        // loop is never blocked on this channel meanwhile.
        loop {
            tokio::select! {
                biased;
                _ = &mut close => break,
                msg = source.next() => match msg {
                    Some(msg) => {
                        if forward(msg, sink, state) {
                            break;
                        }
                    }
                    None => break,
                },
            }
        }
    }
    drain_queued(source, sink, state);
}

/// Waits for the end of the session and reports the lost connection.
async fn report_lost(sink: &ExecEventFn, link: &SessionLink) {
    link.ended.fired().await;
    let info = link
        .shared
        .as_ref()
        .map(|shared| shared.disconnect_info())
        .unwrap_or(DisconnectInfo {
            reason: "error",
            code: Some(Code::Disconnected),
        });
    // A channel that ended through connection loss never reports an exit
    // code.
    send(
        sink,
        ExecEvent::Exit {
            code: None,
            signal: None,
            disconnected: Some(info),
        },
    );
}

async fn read_and_finish<S: MessageSource>(
    mut source: S,
    prefix: VecDeque<ChannelMsg>,
    sink: &ExecEventFn,
    flow: &Flow,
    link: &SessionLink,
    closer: Option<&ChannelWriteHalf<Msg>>,
) {
    let mut state = ReadState {
        sent: 0,
        code: None,
        signal: None,
    };
    let end = read_loop(&mut source, prefix, sink, flow, link, &mut state).await;
    if let ReadEnd::CloseRequested = end {
        close_requested(&mut source, sink, &mut state, closer).await;
    }
    // Release the channel receiver: russh's session loop may be blocked on
    // delivering into it.
    drop(source);
    match end {
        ReadEnd::Closed | ReadEnd::CloseRequested => send(
            sink,
            ExecEvent::Exit {
                code: state.code,
                signal: state.signal,
                disconnected: None,
            },
        ),
        ReadEnd::Lost => report_lost(sink, link).await,
        ReadEnd::Cancelled => {
            if let Some(closer) = closer {
                let _ = closer.close().await;
            }
        }
    }
}

/// The exec reader. Also used by `__internalPanicProbe("execReader")` with
/// an internal message source, so the probe runs exactly this code. The
/// event sink (a ref'd threadsafe function) is dropped right after the final
/// event, which releases the event loop.
pub async fn run_reader<S: MessageSource>(
    source: S,
    prefix: VecDeque<ChannelMsg>,
    sink: Arc<ExecEventFn>,
    flow: Arc<Flow>,
    link: SessionLink,
    closer: Option<Arc<ChannelWriteHalf<Msg>>>,
) {
    let outcome = AssertUnwindSafe(read_and_finish(
        source,
        prefix,
        &sink,
        &flow,
        &link,
        closer.as_deref(),
    ))
    .catch_unwind()
    .await;
    if outcome.is_err() {
        send(&sink, ExecEvent::Internal);
        if let Some(closer) = closer {
            let _ = closer.close().await;
        }
    }
}

/// Native side of one exec channel, handed to JS as an external.
pub struct ExecCore {
    flow: Arc<Flow>,
    write: Arc<ChannelWriteHalf<Msg>>,
}

pub type ExecChannel = External<ExecCore>;

fn channel_closed() -> BindingError {
    BindingError::new(Code::Disconnected, "the exec channel is closed")
}

/// Waits for the server's reply to a channel request (`want_reply`). Data
/// that arrives before it is kept for the reader.
pub async fn await_request_reply<S: MessageSource>(
    read: &mut S,
    refused: BindingError,
) -> BindingResult<VecDeque<ChannelMsg>> {
    let mut prefix = VecDeque::new();
    loop {
        match read.next().await {
            Some(ChannelMsg::Success) => return Ok(prefix),
            Some(ChannelMsg::Failure) => return Err(refused),
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

/// Requests exec on an open channel and writes the initial stdin.
async fn request_exec(
    read: &mut ChannelReadHalf,
    write: &ChannelWriteHalf<Msg>,
    request: &ExecRequest,
) -> BindingResult<VecDeque<ChannelMsg>> {
    if request.agent_forward {
        // auth-agent-req@openssh.com without want_reply, as OpenSSH does.
        write.agent_forward(false).await?;
    }
    write.exec(true, request.command.as_bytes()).await?;
    let refused = BindingError::with_detail(
        Code::ChannelOpenFailed,
        "exec-refused",
        "the server refused the exec request",
    );
    let prefix = await_request_reply(read, refused).await?;
    if let Some(stdin) = &request.stdin {
        write
            .data_bytes(Bytes::copy_from_slice(stdin))
            .await
            .map_err(|_| channel_closed())?;
    }
    Ok(prefix)
}

pub async fn start_exec(
    handle: &Handle<ClientHandler>,
    shared: Arc<Shared>,
    request: ExecRequest,
    abort: Flag,
    sink: Arc<ExecEventFn>,
) -> BindingResult<ExecChannel> {
    let channel = tokio::select! {
        biased;
        () = abort.fired() => return Err(BindingError::aborted()),
        channel = handle.channel_open_session() => channel?,
    };
    let (mut read, write) = channel.split();
    let write = Arc::new(write);
    // From here on the channel is open: an abort or a failed request closes
    // it again.
    let prefix = tokio::select! {
        biased;
        () = abort.fired() => Err(BindingError::aborted()),
        prefix = request_exec(&mut read, &write, &request) => prefix,
    };
    drop(request);
    let prefix = match prefix {
        Ok(prefix) => prefix,
        Err(err) => {
            drop(read);
            let _ = write.close().await;
            return Err(err);
        }
    };
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
    Ok(External::new(ExecCore { flow, write }))
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

/// Closes the channel through the reader, which sends `CHANNEL_CLOSE` and
/// then the exit (`disconnected: false`, with the exit status if one
/// arrived before). The promise resolves once the request is registered.
#[napi(js_name = "execClose", skip_typescript, catch_unwind)]
pub fn exec_close<'env>(
    env: &'env Env,
    channel: &ExecChannel,
) -> napi::Result<PromiseRaw<'env, ()>> {
    channel.flow.close.fire();
    env.spawn_future(async { Ok(()) })
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
