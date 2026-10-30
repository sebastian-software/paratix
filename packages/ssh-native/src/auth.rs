//! Authentication flows: agent (keys and certificates), key file, password
//! with keyboard-interactive fallback.

use std::sync::Arc;

use napi_derive::napi;
use russh::client::{AuthResult, Handle, KeyboardInteractiveAuthResponse};
use russh::keys::agent::client::AgentClient;
use russh::keys::agent::AgentIdentity;
use russh::keys::{decode_secret_key, HashAlg, PrivateKeyWithHashAlg};
use zeroize::Zeroizing;

use crate::error::{from_key_error, BindingError, BindingResult, Code};
use crate::handler::ClientHandler;
use crate::secret::{SecretAnswers, SecretBytes};

pub enum AuthInput {
    Agent(String),
    /// Copied out of the JS buffer synchronously; zeroized on drop.
    PrivateKey(SecretBytes),
    /// Copied out of the JS buffer synchronously; zeroized on drop.
    Password(SecretBytes),
}

#[napi(object, object_from_js = false)]
#[derive(Clone, Debug, Default)]
pub struct AuthInfo {
    /// `agent`, `publickey`, `password` or `keyboard-interactive`.
    #[napi(ts_type = "'agent' | 'publickey' | 'password' | 'keyboard-interactive'")]
    pub method: String,
    /// For agent/publickey: `key` or `certificate`.
    #[napi(ts_type = "'key' | 'certificate'")]
    pub identity_kind: Option<String>,
    /// Signature algorithm of the accepted key, e.g. `ssh-ed25519`.
    pub algorithm: Option<String>,
    /// Number of agent identities that were offered before success.
    pub attempts: u32,
}

fn auth_failed() -> BindingError {
    BindingError::new(Code::AuthFailed, "authentication failed")
}

async fn rsa_hash(handle: &Handle<ClientHandler>) -> Option<HashAlg> {
    // Some(Some(h)): server-sig-algs lists rsa-sha2-*; Some(None): only ssh-rsa;
    // None: no server-sig-algs extension, try rsa-sha2-256 like OpenSSH does.
    match handle.best_supported_rsa_hash().await {
        Ok(Some(hash)) => hash,
        _ => Some(HashAlg::Sha256),
    }
}

pub async fn authenticate(
    handle: &mut Handle<ClientHandler>,
    user: &str,
    input: AuthInput,
) -> BindingResult<AuthInfo> {
    match input {
        AuthInput::Agent(socket) => agent_auth(handle, user, &socket).await,
        AuthInput::PrivateKey(bytes) => key_auth(handle, user, bytes).await,
        AuthInput::Password(bytes) => password_auth(handle, user, bytes).await,
    }
}

async fn agent_auth(
    handle: &mut Handle<ClientHandler>,
    user: &str,
    socket: &str,
) -> BindingResult<AuthInfo> {
    let mut agent = AgentClient::connect_uds(socket).await.map_err(|_| {
        BindingError::with_detail(
            Code::AuthFailed,
            "agent-unavailable",
            "could not connect to the SSH agent socket",
        )
    })?;
    if let Some(binding) = handle.agent_session_binding().cloned() {
        // session-bind@openssh.com; agents without the extension answer FAILURE.
        let _ = agent.bind_session(&binding, false).await;
    }
    let identities = agent.request_identities().await.map_err(|_| {
        BindingError::with_detail(
            Code::AuthFailed,
            "agent-protocol",
            "the SSH agent did not list identities",
        )
    })?;
    if identities.is_empty() {
        return Err(BindingError::with_detail(
            Code::AuthFailed,
            "agent-empty",
            "the SSH agent holds no identities",
        ));
    }
    let rsa = rsa_hash(handle).await;
    for (index, identity) in identities.into_iter().enumerate() {
        let attempts = u32::try_from(index + 1).unwrap_or(u32::MAX);
        let (kind, algorithm, result) = match identity {
            AgentIdentity::Certificate { certificate, .. } => {
                let algorithm = certificate.algorithm();
                let hash = if algorithm.clone().is_rsa() {
                    rsa
                } else {
                    None
                };
                let name = algorithm.to_certificate_type();
                let r = handle
                    .authenticate_certificate_with(user, certificate, hash, &mut agent)
                    .await;
                ("certificate", name, r.map_err(|_| ()))
            }
            AgentIdentity::PublicKey { key, .. } => {
                let algorithm = key.algorithm();
                let is_rsa = algorithm.clone().is_rsa();
                let hash = if is_rsa { rsa } else { None };
                let name = if is_rsa {
                    russh::keys::Algorithm::Rsa { hash }.as_str().to_owned()
                } else {
                    algorithm.as_str().to_owned()
                };
                let r = handle
                    .authenticate_publickey_with(user, key, hash, &mut agent)
                    .await;
                ("key", name, r.map_err(|_| ()))
            }
        };
        if let Ok(AuthResult::Success) = result {
            return Ok(AuthInfo {
                method: "agent".into(),
                identity_kind: Some(kind.into()),
                algorithm: Some(algorithm),
                attempts,
            });
        }
        if handle.is_closed() {
            return Err(BindingError::disconnected());
        }
    }
    Err(auth_failed())
}

async fn key_auth(
    handle: &mut Handle<ClientHandler>,
    user: &str,
    bytes: SecretBytes,
) -> BindingResult<AuthInfo> {
    let text = std::str::from_utf8(&bytes).map_err(|_| {
        BindingError::new(
            Code::UnsupportedKey,
            "the private key is not a text (PEM/OpenSSH) key",
        )
    })?;
    // russh keeps internal, non-zeroized copies while decoding (base64 String
    // and DER Vec in keys/format/mod.rs); the parsed ssh-key PrivateKey
    // zeroizes its key material on drop.
    let key = decode_secret_key(text, None).map_err(|e| from_key_error(&e))?;
    drop(bytes);
    let algorithm = key.algorithm();
    let hash = if algorithm.clone().is_rsa() {
        rsa_hash(handle).await
    } else {
        None
    };
    let key = PrivateKeyWithHashAlg::new(Arc::new(key), hash);
    let name = key.algorithm().as_str().to_owned();
    match handle.authenticate_publickey(user, key).await? {
        AuthResult::Success => Ok(AuthInfo {
            method: "publickey".into(),
            identity_kind: Some("key".into()),
            algorithm: Some(name),
            attempts: 1,
        }),
        AuthResult::Failure { .. } => Err(auth_failed()),
    }
}

async fn password_auth(
    handle: &mut Handle<ClientHandler>,
    user: &str,
    bytes: SecretBytes,
) -> BindingResult<AuthInfo> {
    let password = Zeroizing::new(
        std::str::from_utf8(&bytes)
            .map_err(|_| BindingError::new(Code::AuthFailed, "the password is not valid UTF-8"))?
            .to_owned(),
    );
    drop(bytes);
    // russh copies the password into `auth::Method::Password { password: String }`;
    // that copy is zeroized on drop (russh auth.rs `impl Drop for Method`). The
    // keyboard-interactive answers below live in a zeroizing `SecretAnswers`
    // here, but russh receives its own plain `Vec<String>` copy
    // (`Msg::AuthInfoResponse`) that is not zeroized: a documented limit.
    if let AuthResult::Success = handle
        .authenticate_password(user, password.as_str())
        .await?
    {
        return Ok(AuthInfo {
            method: "password".into(),
            attempts: 1,
            ..AuthInfo::default()
        });
    }
    if handle.is_closed() {
        return Err(BindingError::disconnected());
    }
    let mut response = handle
        .authenticate_keyboard_interactive_start(user, None::<String>)
        .await?;
    for _ in 0..8 {
        match response {
            KeyboardInteractiveAuthResponse::Success => {
                return Ok(AuthInfo {
                    method: "keyboard-interactive".into(),
                    attempts: 2,
                    ..AuthInfo::default()
                });
            }
            KeyboardInteractiveAuthResponse::Failure { .. } => return Err(auth_failed()),
            KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. } => {
                // Every prompt (usually exactly one "Password:") gets the password;
                // empty info requests get an empty answer list.
                let answers = keyboard_interactive_answers(prompts.len(), &password);
                response = handle
                    .authenticate_keyboard_interactive_respond(answers.to_vec())
                    .await?;
            }
        }
    }
    Err(auth_failed())
}

/// One copy of the password per keyboard-interactive prompt, held in a
/// zeroizing container until russh has taken its own copy.
pub fn keyboard_interactive_answers(prompts: usize, password: &Zeroizing<String>) -> SecretAnswers {
    Zeroizing::new((0..prompts).map(|_| password.to_string()).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::tests::assert_zeroize_on_drop;

    #[test]
    fn secrets_of_every_auth_input_are_zeroizing() {
        for input in [
            AuthInput::PrivateKey(SecretBytes::default()),
            AuthInput::Password(SecretBytes::default()),
        ] {
            match &input {
                AuthInput::PrivateKey(bytes) | AuthInput::Password(bytes) => {
                    assert_zeroize_on_drop(bytes);
                }
                AuthInput::Agent(_) => {}
            }
        }
    }

    #[test]
    fn keyboard_interactive_answers_are_zeroizing() {
        let password = Zeroizing::new("secret".to_owned());
        let answers = keyboard_interactive_answers(2, &password);
        assert_zeroize_on_drop(&answers);
        assert_eq!(answers.len(), 2);
    }
}
