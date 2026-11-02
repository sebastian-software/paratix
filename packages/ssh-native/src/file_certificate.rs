//! File certificates are checked before TCP; the server decides CA trust and
//! principal authorization. Signing stays in-process for this connection only.

use std::time::{SystemTime, UNIX_EPOCH};

use russh::keys::agent::AgentIdentity;
use russh::keys::signature::Signer as _;
use russh::keys::ssh_encoding::Encode;
use russh::keys::ssh_key::{certificate::CertType, Certificate, Signature};
use russh::keys::{HashAlg, PrivateKey};

use crate::auth::decode_key_bytes;
use crate::error::{BindingError, BindingResult, Code};
use crate::secret::SecretBytes;

pub struct FileCertificate {
    pub certificate: Certificate,
    pub signer: FileSigner,
}

fn certificate_error(detail: &str) -> BindingError {
    BindingError::with_detail(
        Code::AuthFailed,
        detail,
        "the user certificate failed local validation",
    )
}

impl FileCertificate {
    pub fn prepare(key: SecretBytes, bytes: SecretBytes) -> BindingResult<Self> {
        // Keep encrypted/unsupported key diagnostics unchanged, even when a
        // certificate is supplied alongside the key.
        let key = decode_key_bytes(key)?;
        let text =
            std::str::from_utf8(&bytes).map_err(|_| certificate_error("certificate-invalid"))?;
        let certificate = Certificate::from_openssh(text)
            .map_err(|_| certificate_error("certificate-invalid"))?;
        drop(bytes);
        if certificate.cert_type() != CertType::User || certificate.verify_signature().is_err() {
            return Err(certificate_error("certificate-invalid"));
        }
        if certificate.public_key() != key.public_key().key_data() {
            return Err(certificate_error("certificate-key-mismatch"));
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| certificate_error("certificate-invalid"))?
            .as_secs();
        if now < certificate.valid_after() {
            return Err(certificate_error("certificate-not-yet-valid"));
        }
        if now >= certificate.valid_before() {
            return Err(certificate_error("certificate-expired"));
        }
        Ok(Self {
            certificate,
            signer: FileSigner { key },
        })
    }
}

/// Owned by one authentication future; ssh-key zeroizes the key on drop.
pub struct FileSigner {
    key: PrivateKey,
}

impl From<russh::SendError> for BindingError {
    fn from(_: russh::SendError) -> Self {
        Self::disconnected()
    }
}

impl russh::Signer for FileSigner {
    type Error = BindingError;

    async fn auth_sign(
        &mut self,
        _identity: &AgentIdentity,
        hash_alg: Option<HashAlg>,
        mut to_sign: Vec<u8>,
    ) -> BindingResult<Vec<u8>> {
        let failed = || BindingError::new(Code::AuthFailed, "certificate signing failed");
        // PrivateKey's generic Signer defaults RSA to SHA-512. Select the
        // exact hash negotiated by russh instead, as its ordinary key path does.
        let signature: Signature = match self.key.key_data() {
            russh::keys::ssh_key::private::KeypairData::Rsa(key) => {
                (key, hash_alg).try_sign(&to_sign).map_err(|_| failed())?
            }
            key => key.try_sign(&to_sign).map_err(|_| failed())?,
        };
        let mut encoded = Vec::new();
        signature.encode(&mut encoded).map_err(|_| failed())?;
        // russh expects the original userauth payload followed by one SSH
        // string containing the signature algorithm and signature bytes.
        encoded.encode(&mut to_sign).map_err(|_| failed())?;
        Ok(to_sign)
    }
}
