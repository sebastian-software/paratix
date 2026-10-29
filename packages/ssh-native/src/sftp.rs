//! SFTP read and write streams over `russh_sftp::client::RawSftpSession`.
//!
//! The binding talks to the raw request/response session instead of
//! russh-sftp's `File`, because `File` flattens the status replies of WRITE,
//! READ and CLOSE into `io::Error::other(message)` and loses the numeric
//! status code. With the raw session every error status reaches JS as
//! `SFTP_STATUS` with its code.
//!
//! Writes: JS `write(chunk)` resolves once the chunk sits in a bounded queue
//! (`QUEUE_CHUNKS` entries). A task drains the queue into pipelined WRITE
//! requests of at most `WRITE_CHUNK` bytes, at most `MAX_IN_FLIGHT` at a
//! time. When the server is slower, `write()` stays pending, the JS
//! `Writable` buffer fills up, `write()` returns false and `drain` follows.
//!
//! Reads: a task keeps up to `MAX_IN_FLIGHT` READ requests of `READ_CHUNK`
//! bytes in flight and hands the data in order to a bounded queue that JS
//! pulls from in `_read()`.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use futures::stream::{FuturesOrdered, FuturesUnordered};
use futures::StreamExt;
use napi::bindgen_prelude::{Buffer, External, PromiseRaw};
use napi::Env;
use napi_derive::napi;
use russh::client::Handle;
use russh_sftp::client::error::Error as SftpError;
use russh_sftp::client::{Config, RawSftpSession};
use russh_sftp::protocol::{FileAttributes, OpenFlags, StatusCode};
use tokio::sync::{mpsc, oneshot};

use crate::error::{from_sftp, BindingError, BindingResult};
use crate::guarded;
use crate::handler::ClientHandler;
use crate::signal::Flag;

const QUEUE_CHUNKS: usize = 4;
const MAX_IN_FLIGHT: usize = 16;
const WRITE_CHUNK: usize = 32 * 1024;
const READ_CHUNK: u32 = 32 * 1024;

fn attrs_with_mode(mode: Option<u32>) -> FileAttributes {
    let mut attrs = FileAttributes::empty();
    attrs.permissions = mode;
    attrs
}

fn sftp_err(err: &SftpError) -> BindingError {
    from_sftp(err)
}

/// One SFTP subsystem channel. Streams share it; `end()` closes it.
pub struct SftpCore {
    raw: Arc<RawSftpSession>,
}

pub type NativeSftp = External<SftpCore>;

pub async fn open_sftp(handle: &Handle<ClientHandler>) -> BindingResult<NativeSftp> {
    let channel = handle.channel_open_session().await?;
    channel.request_subsystem(true, "sftp").await?;
    // No per-request timeout: like ssh2, a slow server is waited for. The
    // connection-level controls (destroy, close) still end pending requests.
    let config = Config {
        request_timeout_secs: u64::MAX,
        ..Config::default()
    };
    let raw = RawSftpSession::new_with_config(channel.into_stream(), config);
    raw.init().await.map_err(|e| sftp_err(&e))?;
    Ok(External::new(SftpCore { raw: Arc::new(raw) }))
}

/// Opens `path` for writing (create, truncate). With `mode`, the file gets
/// that mode on create and, like ssh2's `WriteStream`, through an fchmod
/// after open, so an existing file ends up with it too.
#[napi(js_name = "sftpOpenWrite", skip_typescript, catch_unwind)]
pub fn sftp_open_write<'env>(
    env: &'env Env,
    sftp: &NativeSftp,
    path: String,
    mode: Option<u32>,
) -> napi::Result<PromiseRaw<'env, External<SftpWriter>>> {
    let raw = sftp.raw.clone();
    env.spawn_future(guarded(async move {
        open_writer(raw, path, mode).await.map(External::new)
    }))
}

/// Opens `path` for reading.
#[napi(js_name = "sftpOpenRead", skip_typescript, catch_unwind)]
pub fn sftp_open_read<'env>(
    env: &'env Env,
    sftp: &NativeSftp,
    path: String,
) -> napi::Result<PromiseRaw<'env, External<SftpReader>>> {
    let raw = sftp.raw.clone();
    env.spawn_future(guarded(async move {
        open_reader(raw, path).await.map(External::new)
    }))
}

/// Closes the SFTP channel. Pending requests fail with `DISCONNECTED`.
#[napi(js_name = "sftpEnd", skip_typescript, catch_unwind)]
pub fn sftp_end(sftp: &NativeSftp) {
    let _ = sftp.raw.close_session();
}

pub struct SftpWriter {
    tx: Mutex<Option<mpsc::Sender<Vec<u8>>>>,
    done: Mutex<Option<oneshot::Receiver<BindingResult<f64>>>>,
    failure: Arc<Mutex<Option<BindingError>>>,
}

async fn open_writer(
    raw: Arc<RawSftpSession>,
    path: String,
    mode: Option<u32>,
) -> BindingResult<SftpWriter> {
    let handle = raw
        .open(
            path,
            OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE,
            attrs_with_mode(mode),
        )
        .await
        .map_err(|e| sftp_err(&e))?
        .handle;
    if mode.is_some() {
        if let Err(err) = raw.fsetstat(handle.as_str(), attrs_with_mode(mode)).await {
            let _ = raw.close(handle.as_str()).await;
            return Err(sftp_err(&err));
        }
    }

    let (tx, rx) = mpsc::channel::<Vec<u8>>(QUEUE_CHUNKS);
    let (done_tx, done_rx) = oneshot::channel();
    let failure = Arc::new(Mutex::new(None));
    let failure_task = failure.clone();
    tokio::spawn(async move {
        let result = write_all(&raw, &handle, rx).await;
        let result = match result {
            Ok(total) => raw
                .close(handle.as_str())
                .await
                .map(|_| total)
                .map_err(|e| sftp_err(&e)),
            Err(err) => {
                let _ = raw.close(handle.as_str()).await;
                Err(err)
            }
        };
        if let Err(err) = &result {
            if let Ok(mut slot) = failure_task.lock() {
                *slot = Some(err.clone());
            }
        }
        let _ = done_tx.send(result);
    });

    Ok(SftpWriter {
        tx: Mutex::new(Some(tx)),
        done: Mutex::new(Some(done_rx)),
        failure,
    })
}

/// Pipelines WRITE requests until the queue closes; returns the byte count.
async fn write_all(
    raw: &RawSftpSession,
    handle: &str,
    mut rx: mpsc::Receiver<Vec<u8>>,
) -> BindingResult<f64> {
    let mut offset: u64 = 0;
    let mut pending: VecDeque<(u64, Vec<u8>)> = VecDeque::new();
    let mut in_flight = FuturesUnordered::new();
    let mut input_open = true;
    loop {
        while in_flight.len() < MAX_IN_FLIGHT {
            let Some((at, piece)) = pending.pop_front() else {
                break;
            };
            in_flight.push(raw.write(handle, at, piece));
        }
        if !input_open && pending.is_empty() && in_flight.is_empty() {
            return Ok(offset as f64);
        }
        tokio::select! {
            Some(reply) = in_flight.next(), if !in_flight.is_empty() => {
                reply.map_err(|e| sftp_err(&e))?;
            }
            chunk = rx.recv(), if input_open && pending.is_empty() => match chunk {
                Some(chunk) => {
                    for piece in chunk.chunks(WRITE_CHUNK) {
                        pending.push_back((offset, piece.to_vec()));
                        offset += piece.len() as u64;
                    }
                }
                None => input_open = false,
            },
        }
    }
}

/// Copies the chunk and waits for a free slot in the bounded queue.
#[napi(js_name = "sftpWriterWrite", skip_typescript, catch_unwind)]
pub fn sftp_writer_write<'env>(
    env: &'env Env,
    writer: &External<SftpWriter>,
    chunk: Buffer,
) -> napi::Result<PromiseRaw<'env, ()>> {
    let data = chunk.to_vec();
    let tx = writer.tx.lock().ok().and_then(|t| t.clone());
    let failure = writer.failure.clone();
    env.spawn_future(guarded(async move {
        let stored = || {
            failure
                .lock()
                .ok()
                .and_then(|f| f.clone())
                .unwrap_or_else(BindingError::disconnected)
        };
        let Some(tx) = tx else {
            return Err(stored());
        };
        tx.send(data).await.map_err(|_| stored())
    }))
}

/// Closes the queue, waits until all data is acknowledged and the remote
/// handle is closed. Resolves with the number of bytes written.
#[napi(js_name = "sftpWriterEnd", skip_typescript, catch_unwind)]
pub fn sftp_writer_end<'env>(
    env: &'env Env,
    writer: &External<SftpWriter>,
) -> napi::Result<PromiseRaw<'env, f64>> {
    if let Ok(mut tx) = writer.tx.lock() {
        tx.take();
    }
    let done = writer.done.lock().ok().and_then(|mut d| d.take());
    env.spawn_future(guarded(async move {
        match done {
            Some(done) => done
                .await
                .unwrap_or_else(|_| Err(BindingError::disconnected())),
            None => Err(BindingError::disconnected()),
        }
    }))
}

type ReadItem = BindingResult<Option<Vec<u8>>>;

pub struct SftpReader {
    rx: Arc<tokio::sync::Mutex<Option<mpsc::Receiver<ReadItem>>>>,
    closed: Flag,
}

async fn open_reader(raw: Arc<RawSftpSession>, path: String) -> BindingResult<SftpReader> {
    let handle = raw
        .open(path, OpenFlags::READ, FileAttributes::empty())
        .await
        .map_err(|e| sftp_err(&e))?
        .handle;
    let (tx, rx) = mpsc::channel::<ReadItem>(QUEUE_CHUNKS);
    tokio::spawn(async move {
        read_all(&raw, &handle, &tx).await;
        let _ = raw.close(handle.as_str()).await;
    });
    Ok(SftpReader {
        rx: Arc::new(tokio::sync::Mutex::new(Some(rx))),
        closed: Flag::new(),
    })
}

enum ReadReply {
    Data(Vec<u8>),
    Eof,
}

fn read_reply(result: Result<russh_sftp::protocol::Data, SftpError>) -> BindingResult<ReadReply> {
    match result {
        Ok(data) if data.data.is_empty() => Ok(ReadReply::Eof),
        Ok(data) => Ok(ReadReply::Data(data.data)),
        Err(SftpError::Status(status)) if status.status_code == StatusCode::Eof => {
            Ok(ReadReply::Eof)
        }
        Err(err) => Err(sftp_err(&err)),
    }
}

/// Pipelines READ requests and forwards the data in order. Stops at EOF, on
/// the first error, or when JS dropped the reader.
async fn read_all(raw: &RawSftpSession, handle: &str, tx: &mpsc::Sender<ReadItem>) {
    let mut next_offset: u64 = 0;
    let mut in_flight = FuturesOrdered::new();
    loop {
        while in_flight.len() < MAX_IN_FLIGHT {
            let at = next_offset;
            in_flight.push_back(async move { (at, raw.read(handle, at, READ_CHUNK).await) });
            next_offset += u64::from(READ_CHUNK);
        }
        let Some((at, result)) = in_flight.next().await else {
            return;
        };
        match read_reply(result) {
            Ok(ReadReply::Data(data)) => {
                let len = data.len() as u64;
                if tx.send(Ok(Some(data))).await.is_err() {
                    return;
                }
                if len < u64::from(READ_CHUNK) {
                    // Short read: discard the requests beyond it and
                    // continue right after the data we got.
                    in_flight = FuturesOrdered::new();
                    next_offset = at + len;
                }
            }
            Ok(ReadReply::Eof) => {
                let _ = tx.send(Ok(None)).await;
                return;
            }
            Err(err) => {
                let _ = tx.send(Err(err)).await;
                return;
            }
        }
    }
}

/// Resolves with the next chunk, or `null` at the end of the file.
#[napi(js_name = "sftpReaderRead", skip_typescript, catch_unwind)]
pub fn sftp_reader_read<'env>(
    env: &'env Env,
    reader: &External<SftpReader>,
) -> napi::Result<PromiseRaw<'env, Option<Buffer>>> {
    let rx = reader.rx.clone();
    let closed = reader.closed.clone();
    env.spawn_future(guarded(async move {
        let mut guard = rx.lock().await;
        let Some(receiver) = guard.as_mut() else {
            return Ok(None);
        };
        let item = tokio::select! {
            biased;
            () = closed.fired() => None,
            item = receiver.recv() => item,
        };
        match item {
            Some(Ok(Some(data))) => Ok(Some(Buffer::from(data))),
            Some(Ok(None)) | None => {
                guard.take();
                Ok(None)
            }
            Some(Err(err)) => {
                guard.take();
                Err(err)
            }
        }
    }))
}

/// Stops reading; the remote handle is closed in the background.
#[napi(js_name = "sftpReaderClose", skip_typescript, catch_unwind)]
pub fn sftp_reader_close(reader: &External<SftpReader>) {
    reader.closed.fire();
    if let Ok(mut guard) = reader.rx.try_lock() {
        guard.take();
    }
}
