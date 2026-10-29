//! Building JS values for threadsafe-function calls.
//!
//! The conversion of a threadsafe-function payload runs on the JS thread,
//! outside the `catch_unwind` that `#[napi(catch_unwind)]` places around
//! synchronous entry points. Every callback of the binding therefore builds
//! its JS value through [`guarded_value`], which converts inside
//! `catch_unwind` and falls back to an `{ kind: "internal" }` event instead
//! of unwinding into Node.

use std::panic::{catch_unwind, AssertUnwindSafe};

use napi::bindgen_prelude::{Object, ToNapiValue};
use napi::{sys, Env, JsValue};

/// A JS object under construction.
pub struct JsObjectBuilder<'env> {
    env: &'env Env,
    object: Object<'env>,
}

impl<'env> JsObjectBuilder<'env> {
    pub fn new(env: &'env Env, kind: &str) -> napi::Result<Self> {
        let mut object = Object::new(env)?;
        object.set("kind", kind)?;
        Ok(Self { env, object })
    }

    /// Sets `key` unless `value` is `None` (absent keys read as `undefined`).
    pub fn set<V: ToNapiValue>(mut self, key: &str, value: Option<V>) -> napi::Result<Self> {
        if let Some(value) = value {
            self.object.set(key, value)?;
        }
        Ok(self)
    }

    pub fn finish(self) -> sys::napi_value {
        let _ = self.env;
        self.object.raw()
    }
}

/// Converts a `#[napi(object)]` value.
pub fn to_js<V: ToNapiValue>(env: &Env, value: V) -> napi::Result<sys::napi_value> {
    // SAFETY: `env` is the live env of the current JS-thread callback.
    unsafe { V::to_napi_value(env.raw(), value) }
}

fn convert(
    env: &Env,
    build: impl FnOnce(&Env) -> napi::Result<sys::napi_value>,
) -> Option<sys::napi_value> {
    catch_unwind(AssertUnwindSafe(|| build(env).ok()))
        .ok()
        .flatten()
}

fn undefined(env: &Env) -> sys::napi_value {
    let mut value = std::ptr::null_mut();
    // SAFETY: valid env of the current callback; on failure `value` stays
    // null, which napi passes on as `undefined`.
    unsafe {
        sys::napi_get_undefined(env.raw(), &mut value);
    }
    value
}

/// Builds a value inside `catch_unwind`. A panic or a failed conversion
/// yields `{ kind: "internal" }` (or `undefined` if even that fails); the
/// wrapper treats both as an `INTERNAL` error.
pub fn guarded_value(
    env: &Env,
    build: impl FnOnce(&Env) -> napi::Result<sys::napi_value>,
) -> sys::napi_value {
    convert(env, build)
        .or_else(|| {
            convert(env, |env| {
                Ok(JsObjectBuilder::new(env, "internal")?.finish())
            })
        })
        .unwrap_or_else(|| undefined(env))
}
