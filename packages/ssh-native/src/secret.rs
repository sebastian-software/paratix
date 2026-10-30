//! Secret buffers of the binding.
//!
//! Private keys, passwords, exec stdin (including the `stdin` option that
//! Paratix uses for sudo passwords) and keyboard-interactive answers are
//! copied out of the JS buffers synchronously and live in `Zeroizing`
//! containers here; the JS wrapper zero-fills its own buffers right after the
//! native call returns. russh keeps its own, non-zeroized copies (see the
//! README, "Known limitations").

use napi::bindgen_prelude::Buffer;
use zeroize::Zeroizing;

/// Bytes that are wiped when dropped.
pub type SecretBytes = Zeroizing<Vec<u8>>;

/// Keyboard-interactive answers, wiped when dropped.
pub type SecretAnswers = Zeroizing<Vec<String>>;

/// Copies a JS buffer into a zeroizing Rust buffer.
pub fn copy_secret(buffer: &Buffer) -> SecretBytes {
    Zeroizing::new(buffer.to_vec())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Compile-time proof: only types that wipe themselves on drop pass.
    pub(crate) fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>(_: &T) {}

    #[test]
    fn secret_types_zeroize_on_drop() {
        assert_zeroize_on_drop(&SecretBytes::default());
        assert_zeroize_on_drop(&SecretAnswers::default());
    }
}
