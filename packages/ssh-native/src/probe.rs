//! Internal panic probe, shipped in the binary (undocumented API).
//!
//! `__internalPanicProbe(kind)` in the JS wrapper calls one of these to prove
//! that a panic at each kind of entry point ends as `INTERNAL` with the fixed
//! message, prints nothing, and does not abort the process:
//!
//! - `sync`: a synchronous `#[napi]` function
//! - `convert`: the argument conversion of a synchronous function
//! - `async`: a spawned future
//! - `event`: the JS-value conversion of a threadsafe-function event
//! - `execReader`: the production exec reader, fed by a panicking source
//! - `handler`: the protected russh handler path (`check_server_key`)
//!
//! None of them touches the network.

#![allow(clippy::panic)]

use napi::bindgen_prelude::{FromNapiValue, Function, PromiseRaw, TypeName, ValidateNapiValue};
use napi::{sys, Env, ValueType};
use napi_derive::napi;

use crate::exec::{event_sink, spawn_reader_probe, ExecEvent};
use crate::guarded;
use crate::handler::run_handler_probe;

fn boom(what: &str) -> ! {
    panic!("{what} panic probe")
}

#[napi(js_name = "panicProbeSync", skip_typescript, catch_unwind)]
pub fn panic_probe_sync() {
    if std::hint::black_box(true) {
        boom("sync");
    }
}

/// An argument type whose conversion from JS panics.
pub struct PanicOnConvert;

impl TypeName for PanicOnConvert {
    fn type_name() -> &'static str {
        "PanicOnConvert"
    }

    fn value_type() -> ValueType {
        ValueType::Unknown
    }
}

impl ValidateNapiValue for PanicOnConvert {}

impl FromNapiValue for PanicOnConvert {
    unsafe fn from_napi_value(_env: sys::napi_env, _value: sys::napi_value) -> napi::Result<Self> {
        if std::hint::black_box(true) {
            boom("convert");
        }
        Ok(PanicOnConvert)
    }
}

#[napi(js_name = "panicProbeConvert", skip_typescript, catch_unwind)]
pub fn panic_probe_convert(_value: PanicOnConvert) {}

#[napi(js_name = "panicProbeAsync", skip_typescript, catch_unwind)]
pub fn panic_probe_async(env: &Env) -> napi::Result<PromiseRaw<'_, ()>> {
    env.spawn_future(guarded(async {
        if std::hint::black_box(true) {
            boom("async");
        }
        Ok(())
    }))
}

/// Sends one event whose conversion panics; JS receives `{ kind: "internal" }`.
#[napi(js_name = "panicProbeEvent", skip_typescript, catch_unwind)]
pub fn panic_probe_event(on_event: Function<'_, sys::napi_value, ()>) -> napi::Result<()> {
    let sink = event_sink(&on_event)?;
    sink.call(
        ExecEvent::PanicProbe,
        napi::threadsafe_function::ThreadsafeFunctionCallMode::NonBlocking,
    );
    Ok(())
}

/// Runs the exec reader against a panicking message source.
#[napi(js_name = "panicProbeExecReader", skip_typescript, catch_unwind)]
pub fn panic_probe_exec_reader<'env>(
    env: &'env Env,
    on_event: Function<'_, sys::napi_value, ()>,
) -> napi::Result<PromiseRaw<'env, ()>> {
    let sink = event_sink(&on_event)?;
    env.spawn_future(async move {
        spawn_reader_probe(sink);
        Ok(())
    })
}

/// Runs the protected handler path with a panicking host check.
#[napi(js_name = "panicProbeHandler", skip_typescript, catch_unwind)]
pub fn panic_probe_handler(env: &Env) -> napi::Result<PromiseRaw<'_, ()>> {
    env.spawn_future(guarded(async { Err(run_handler_probe().await) }))
}
