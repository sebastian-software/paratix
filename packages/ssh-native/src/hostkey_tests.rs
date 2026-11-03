use super::*;
use russh::keys::ssh_key::{certificate::Builder, private::Ed25519Keypair, Certificate};
use russh::keys::PrivateKey;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn key(seed: u8) -> PrivateKey {
    PrivateKey::from(Ed25519Keypair::from_seed(&[seed; 32]))
}

fn builder(after: u64, before: u64) -> Result<Builder, russh::keys::ssh_key::Error> {
    let mut builder = Builder::new(vec![0; 32], key(1).public_key(), after, before)?;
    builder
        .cert_type(CertType::Host)?
        .valid_principal("example.test")?;
    Ok(builder)
}

fn certificate(after: u64, before: u64) -> Result<Certificate, russh::keys::ssh_key::Error> {
    builder(after, before)?.sign(&key(2))
}

fn validation(certificate: Certificate, now: Option<u64>) -> HostCertificateValidation {
    let info = describe_at(&PublicKeyOrCertificate::Certificate(certificate), now);
    // A missing validation object must fail this assertion too.
    match info.certificate_validation {
        Some(validation) => validation,
        None => panic!("a certificate requires native validation evidence"),
    }
}

#[test]
fn certificate_time_uses_exact_inclusive_start_and_exclusive_end() -> TestResult {
    for (now, reason) in [
        (99, Some("certificate-not-yet-valid")),
        (100, None),
        (199, None),
        (200, Some("certificate-expired")),
    ] {
        let checked = validation(certificate(100, 200)?, Some(now));
        assert_eq!(checked.valid, reason.is_none());
        assert_eq!(checked.reason.as_deref(), reason);
    }
    // Adjacent u64 values above JS's exact integer range must remain distinct.
    let start = (1_u64 << 53) + 1;
    assert!(validation(certificate(start, start + 1)?, Some(start)).valid);
    assert!(!validation(certificate(start, start + 1)?, Some(start - 1)).valid);
    assert!(!validation(certificate(start, start + 1)?, Some(start + 1)).valid);
    assert!(validation(certificate(0, u64::MAX)?, Some(u64::MAX - 1)).valid);
    assert!(!validation(certificate(0, u64::MAX)?, Some(u64::MAX)).valid);
    Ok(())
}

#[test]
fn user_type_critical_options_and_unavailable_time_fail_closed() -> TestResult {
    let mut user = Builder::new(vec![0; 32], key(1).public_key(), 0, u64::MAX)?;
    user.cert_type(CertType::User)?
        .valid_principal("example.test")?;
    let checked = validation(user.sign(&key(2))?, Some(100));
    assert_eq!(checked.reason.as_deref(), Some("certificate-type-invalid"));

    let mut critical = builder(0, u64::MAX)?;
    critical.critical_option("force-command", "private-value")?;
    let checked = validation(critical.sign(&key(2))?, Some(100));
    assert_eq!(
        checked.reason.as_deref(),
        Some("certificate-critical-options")
    );

    let checked = validation(certificate(0, u64::MAX)?, None);
    assert_eq!(
        checked.reason.as_deref(),
        Some("certificate-time-unavailable")
    );
    let mut extended = builder(0, u64::MAX)?;
    extended.extension("unrecognized-extension", "private-value")?;
    assert!(validation(extended.sign(&key(2))?, Some(100)).valid);
    Ok(())
}

#[test]
fn invalid_signature_never_becomes_valid_metadata() -> TestResult {
    let mut bytes = certificate(0, u64::MAX)?.to_bytes()?;
    *bytes.last_mut().ok_or("missing signature")? ^= 1;
    let corrupted = Certificate::from_bytes(&bytes)?;
    let info = describe_at(&PublicKeyOrCertificate::Certificate(corrupted), Some(100));
    assert_eq!(info.ca_signature_valid, Some(false));
    let checked = info.certificate_validation.ok_or("missing validation")?;
    assert!(!checked.valid);
    assert_eq!(
        checked.reason.as_deref(),
        Some("certificate-signature-invalid")
    );
    Ok(())
}

#[test]
fn certificate_metadata_keeps_leaf_and_ca_separate() -> TestResult {
    let info = describe_at(
        &PublicKeyOrCertificate::Certificate(certificate(0, u64::MAX)?),
        Some(100),
    );
    let leaf = key(1);
    let ca = key(2);
    assert_eq!(info.kind, "certificate");
    assert_eq!(info.algorithm, "ssh-ed25519-cert-v01@openssh.com");
    assert_eq!(info.key_algorithm, "ssh-ed25519");
    assert_eq!(info.key_base64, openssh_base64(leaf.public_key()));
    assert_eq!(
        info.fingerprint_sha256,
        leaf.public_key().fingerprint(HashAlg::Sha256).to_string()
    );
    assert_eq!(info.ca_key_base64, Some(openssh_base64(ca.public_key())));
    assert_eq!(info.ca_algorithm.as_deref(), Some("ssh-ed25519"));
    assert_ne!(Some(info.key_base64), info.ca_key_base64);
    assert_eq!(info.principals, Some(vec!["example.test".to_owned()]));
    assert!(
        info.certificate_validation
            .ok_or("missing validation")?
            .valid
    );
    Ok(())
}

#[test]
fn raw_key_has_no_certificate_validation_or_authority() {
    let presented = PublicKeyOrCertificate::from(key(1).public_key().clone());
    let info = describe_at(&presented, Some(100));
    assert_eq!(info.kind, "key");
    assert_eq!(info.algorithm, info.key_algorithm);
    assert!(info.certificate_validation.is_none());
    assert!(info.ca_key_base64.is_none());
    assert!(info.ca_algorithm.is_none());
    assert!(info.ca_signature_valid.is_none());
}
