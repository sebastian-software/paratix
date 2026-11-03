//! Host key description handed to JS (`verifyHost(info)` and `scan()`).
//!
//! Rust validates certificate cryptography, type, time and critical options;
//! TypeScript authorizes the CA, principal, revocations and additional pins.
//! Plain key material always describes the leaf, never the certificate or CA.

use std::time::{SystemTime, UNIX_EPOCH};

use napi_derive::napi;
use russh::keys::ssh_key::certificate::CertType;
use russh::keys::ssh_key::public::KeyData;
use russh::keys::PublicKeyOrCertificate;
use russh::keys::{HashAlg, PublicKey};

use crate::host_certificate::{validate, HostCertificateValidation};

#[napi(object, object_from_js = false)]
#[derive(Clone, Debug)]
pub struct HostKeyInfo {
    /// `key` or `certificate`.
    #[napi(ts_type = "'key' | 'certificate'")]
    pub kind: String,
    /// Key algorithm of the plain key (`ssh-ed25519`, `ssh-rsa`, ...) or the
    /// certificate algorithm (`ssh-ed25519-cert-v01@openssh.com`).
    pub algorithm: String,
    /// Algorithm encoded in the certified/plain leaf blob (never a cert alias).
    pub key_algorithm: String,
    /// Base64 of the plain public key blob (for certificates: the certified key).
    pub key_base64: String,
    /// `SHA256:...` fingerprint of the plain key, as OpenSSH prints it.
    pub fingerprint_sha256: String,
    /// Base64 of the CA key blob (certificates only).
    pub ca_key_base64: Option<String>,
    /// Algorithm encoded in the CA public key blob (certificates only).
    pub ca_algorithm: Option<String>,
    /// `SHA256:...` fingerprint of the CA key (certificates only).
    pub ca_fingerprint_sha256: Option<String>,
    /// `host` or `user` (certificates only).
    #[napi(ts_type = "'host' | 'user'")]
    pub cert_type: Option<String>,
    /// Valid principals (certificates only).
    pub principals: Option<Vec<String>>,
    /// Start of validity, seconds since the epoch (certificates only).
    pub valid_after: Option<f64>,
    /// End of validity, seconds since the epoch (certificates only).
    pub valid_before: Option<f64>,
    /// Key ID (certificates only).
    pub key_id: Option<String>,
    /// Whether the CA signature verifies (certificates only).
    pub ca_signature_valid: Option<bool>,
    /// Native validation result. Mandatory for a certificate trust decision;
    /// its absence never grants certificate trust. No CA authorization implied.
    pub certificate_validation: Option<HostCertificateValidation>,
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
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|time| time.as_secs());
    describe_at(presented, now)
}

fn describe_at(presented: &PublicKeyOrCertificate, now: Option<u64>) -> HostKeyInfo {
    match presented {
        PublicKeyOrCertificate::PublicKey { key, .. } => HostKeyInfo {
            kind: "key".into(),
            algorithm: key.algorithm().as_str().to_owned(),
            key_algorithm: key.algorithm().as_str().to_owned(),
            key_base64: openssh_base64(key),
            fingerprint_sha256: key.fingerprint(HashAlg::Sha256).to_string(),
            ca_key_base64: None,
            ca_algorithm: None,
            ca_fingerprint_sha256: None,
            cert_type: None,
            principals: None,
            valid_after: None,
            valid_before: None,
            key_id: None,
            ca_signature_valid: None,
            certificate_validation: None,
        },
        PublicKeyOrCertificate::Certificate(cert) => {
            let key = plain(cert.public_key());
            let ca = plain(cert.signature_key());
            let signature_valid = cert.verify_signature().is_ok();
            HostKeyInfo {
                kind: "certificate".into(),
                algorithm: cert.algorithm().to_certificate_type(),
                key_algorithm: key.algorithm().as_str().to_owned(),
                key_base64: openssh_base64(&key),
                fingerprint_sha256: key.fingerprint(HashAlg::Sha256).to_string(),
                ca_key_base64: Some(openssh_base64(&ca)),
                ca_algorithm: Some(ca.algorithm().as_str().to_owned()),
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
                ca_signature_valid: Some(signature_valid),
                certificate_validation: Some(validate(cert, now, signature_valid)),
            }
        }
    }
}

#[cfg(test)]
#[path = "hostkey_tests.rs"]
mod tests;
