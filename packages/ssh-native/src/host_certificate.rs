//! Certificate checks that require native crypto and exact integer time.
//! Trust in the signer and host principal belongs to the controller.

use napi_derive::napi;
use russh::keys::ssh_key::{certificate::CertType, Certificate};

#[napi(object, object_from_js = false)]
#[derive(Clone, Debug)]
pub struct HostCertificateValidation {
    /// Signature, host type, validity interval and empty critical options passed.
    pub valid: bool,
    /// Stable reason only; no certificate-supplied text is included.
    #[napi(
        ts_type = "'certificate-signature-invalid' | 'certificate-type-invalid' | 'certificate-critical-options' | 'certificate-time-unavailable' | 'certificate-not-yet-valid' | 'certificate-expired'"
    )]
    pub reason: Option<String>,
}

pub fn validate(
    certificate: &Certificate,
    now: Option<u64>,
    signature_valid: bool,
) -> HostCertificateValidation {
    let reason = if !signature_valid {
        Some("certificate-signature-invalid")
    } else if certificate.cert_type() != CertType::Host {
        Some("certificate-type-invalid")
    } else if !certificate.critical_options().is_empty() {
        Some("certificate-critical-options")
    } else {
        match now {
            None => Some("certificate-time-unavailable"),
            Some(now) if now < certificate.valid_after() => Some("certificate-not-yet-valid"),
            Some(now) if now >= certificate.valid_before() => Some("certificate-expired"),
            Some(_) => None,
        }
    };
    HostCertificateValidation {
        valid: reason.is_none(),
        reason: reason.map(str::to_owned),
    }
}
