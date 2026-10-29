//! Host key description handed to JS (`verifyHost(info)` and `scan()`).
//!
//! Rust only describes the presented key or certificate; the trust decision
//! stays in TypeScript (plan decision 4). For certificates the spike also
//! reports whether the CA signature is cryptographically valid, to show that
//! Rust can own that check later (work package E) via `russh::keys`.

use napi_derive::napi;
use russh::keys::ssh_key::certificate::CertType;
use russh::keys::ssh_key::public::KeyData;
use russh::keys::PublicKeyOrCertificate;
use russh::keys::{HashAlg, PublicKey};

#[napi(object)]
#[derive(Clone, Debug)]
pub struct HostKeyInfo {
    /// `key` or `certificate`.
    pub kind: String,
    /// Key algorithm of the plain key (`ssh-ed25519`, `ssh-rsa`, ...) or the
    /// certificate algorithm (`ssh-ed25519-cert-v01@openssh.com`).
    pub algorithm: String,
    /// Base64 of the plain public key blob (for certificates: the certified key).
    pub key_base64: String,
    /// `SHA256:...` fingerprint of the plain key, as OpenSSH prints it.
    pub fingerprint_sha256: String,
    pub ca_key_base64: Option<String>,
    pub ca_fingerprint_sha256: Option<String>,
    pub cert_type: Option<String>,
    pub principals: Option<Vec<String>>,
    pub valid_after: Option<f64>,
    pub valid_before: Option<f64>,
    pub key_id: Option<String>,
    pub ca_signature_valid: Option<bool>,
}

fn openssh_base64(key: &PublicKey) -> String {
    key.to_openssh()
        .ok()
        .and_then(|line| line.split_whitespace().nth(1).map(str::to_owned))
        .unwrap_or_default()
}

fn plain(key_data: &KeyData) -> PublicKey {
    PublicKey::new(key_data.clone(), "")
}

pub fn describe(presented: &PublicKeyOrCertificate) -> HostKeyInfo {
    match presented {
        PublicKeyOrCertificate::PublicKey { key, .. } => HostKeyInfo {
            kind: "key".into(),
            algorithm: key.algorithm().as_str().to_owned(),
            key_base64: openssh_base64(key),
            fingerprint_sha256: key.fingerprint(HashAlg::Sha256).to_string(),
            ca_key_base64: None,
            ca_fingerprint_sha256: None,
            cert_type: None,
            principals: None,
            valid_after: None,
            valid_before: None,
            key_id: None,
            ca_signature_valid: None,
        },
        PublicKeyOrCertificate::Certificate(cert) => {
            let key = plain(cert.public_key());
            let ca = plain(cert.signature_key());
            HostKeyInfo {
                kind: "certificate".into(),
                algorithm: cert.algorithm().to_certificate_type(),
                key_base64: openssh_base64(&key),
                fingerprint_sha256: key.fingerprint(HashAlg::Sha256).to_string(),
                ca_key_base64: Some(openssh_base64(&ca)),
                ca_fingerprint_sha256: Some(ca.fingerprint(HashAlg::Sha256).to_string()),
                cert_type: Some(
                    match cert.cert_type() {
                        CertType::Host => "host",
                        CertType::User => "user",
                    }
                    .into(),
                ),
                principals: Some(cert.valid_principals().to_vec()),
                valid_after: Some(cert.valid_after() as f64),
                valid_before: Some(cert.valid_before() as f64),
                key_id: Some(cert.key_id().to_owned()),
                ca_signature_valid: Some(cert.verify_signature().is_ok()),
            }
        }
    }
}
