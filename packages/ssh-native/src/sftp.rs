//! SFTP write stream with bounded in-flight data.
//!
//! JS `write(chunk)` resolves once the chunk sits in a bounded queue
//! (`QUEUE_CHUNKS` entries). A background task drains the queue into
//! russh-sftp's `File` (which itself pipelines at most 16 WRITE requests of
//! 32 KiB). When the remote side is slower, `write()` stays pending, the JS
//! `Writable` buffer fills up, `write()` returns false and `drain` follows.

use std::sync::{Arc, Mutex};

use napi::bindgen_prelude::{Buffer, PromiseRaw};
use napi::Env;
use napi_derive::napi;
use russh::client::Handle;
use russh_sftp::client::SftpSession;
use russh_sftp::protocol::{FileAttributes, OpenFlags};
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, oneshot};

use crate::error::{from_sftp, from_sftp_io, SpikeError, SpikeResult};
use crate::guarded;
use crate::handler::ClientHandler;

const QUEUE_CHUNKS: usize = 4;

#[napi]
pub struct SftpWriter {
    tx: Mutex<Option<mpsc::Sender<Vec<u8>>>>,
    done: Mutex<Option<oneshot::Receiver<SpikeResult<f64>>>>,
    failure: Arc<Mutex<Option<SpikeError>>>,
}

fn attrs_with_mode(mode: Option<u32>) -> FileAttributes {
    let mut attrs = FileAttributes::empty();
    attrs.permissions = mode;
    attrs
}

pub async fn open_writer(
    handle: &Handle<ClientHandler>,
    remote_path: String,
    mode: Option<u32>,
) -> SpikeResult<SftpWriter> {
    let channel = handle.channel_open_session().await?;
    channel.request_subsystem(true, "sftp").await?;
    let sftp = SftpSession::new(channel.into_stream())
        .await
        .map_err(|e| from_sftp(&e))?;
    let mut file = sftp
        .open_with_flags_and_attributes(
            remote_path,
            OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE,
            attrs_with_mode(mode),
        )
        .await
        .map_err(|e| from_sftp(&e))?;
    if mode.is_some() {
        // Like ssh2's WriteStream: fchmod after open, so an existing file
        // also ends up with the requested mode (open attrs only apply on create).
        file.set_metadata(attrs_with_mode(mode))
            .await
            .map_err(|e| from_sftp(&e))?;
    }

    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(QUEUE_CHUNKS);
    let (done_tx, done_rx) = oneshot::channel();
    let failure = Arc::new(Mutex::new(None));
    let failure_task = failure.clone();
    tokio::spawn(async move {
        let result: SpikeResult<f64> = async {
            let mut total = 0f64;
            while let Some(chunk) = rx.recv().await {
                file.write_all(&chunk).await.map_err(|e| from_sftp_io(&e))?;
                total += chunk.len() as f64;
            }
            file.shutdown().await.map_err(|e| from_sftp_io(&e))?;
            let _ = sftp.close().await;
            Ok(total)
        }
        .await;
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

#[napi]
impl SftpWriter {
    /// Copies the chunk and waits for a free slot in the bounded queue.
    #[napi]
    pub fn write<'env>(&self, env: &'env Env, chunk: Buffer) -> napi::Result<PromiseRaw<'env, ()>> {
        let data = chunk.to_vec();
        let tx = self.tx.lock().ok().and_then(|t| t.clone());
        let failure = self.failure.clone();
        env.spawn_future(guarded(async move {
            let stored = || {
                failure
                    .lock()
                    .ok()
                    .and_then(|f| f.clone())
                    .unwrap_or_else(SpikeError::disconnected)
            };
            let Some(tx) = tx else {
                return Err(stored());
            };
            tx.send(data).await.map_err(|_| stored())
        }))
    }

    /// Closes the queue, waits until all data is acknowledged and the remote
    /// handle is closed. Resolves with the number of bytes written.
    #[napi]
    pub fn end<'env>(&self, env: &'env Env) -> napi::Result<PromiseRaw<'env, f64>> {
        if let Ok(mut tx) = self.tx.lock() {
            tx.take();
        }
        let done = self.done.lock().ok().and_then(|mut d| d.take());
        env.spawn_future(guarded(async move {
            match done {
                Some(done) => done
                    .await
                    .unwrap_or_else(|_| Err(SpikeError::disconnected())),
                None => Err(SpikeError::disconnected()),
            }
        }))
    }
}
