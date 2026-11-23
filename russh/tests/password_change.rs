//! A server can ask for a new password (`SSH_MSG_USERAUTH_PASSWD_CHANGEREQ`,
//! RFC 4252 §8), and the client can answer it.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use russh::keys::{PrivateKey, PublicKeyOrCertificate, ssh_key};
use russh::{MethodKind, MethodSet, client, server};

struct AcceptServerKey;

impl client::Handler for AcceptServerKey {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// The password `old` has expired; `new` is the only new password it
/// takes. Every request is recorded.
struct Server {
    log: Arc<Mutex<Vec<String>>>,
}

const PROMPT: &str = "Your password has expired.";

impl server::Handler for Server {
    type Error = russh::Error;

    async fn auth_password(
        &mut self,
        user: &str,
        password: &str,
    ) -> Result<server::Auth, Self::Error> {
        self.log
            .lock()
            .unwrap()
            .push(format!("password {user} {password}"));
        Ok(if password == "old" {
            server::Auth::PasswordChangeRequired {
                prompt: PROMPT.into(),
            }
        } else {
            server::Auth::reject()
        })
    }

    async fn auth_password_change(
        &mut self,
        user: &str,
        old_password: &str,
        new_password: &str,
    ) -> Result<server::Auth, Self::Error> {
        self.log
            .lock()
            .unwrap()
            .push(format!("change {user} {old_password} {new_password}"));
        Ok(match (old_password, new_password) {
            ("old", "new") => server::Auth::Accept,
            ("old", _) => server::Auth::PasswordChangeRequired {
                prompt: "Too simple.".into(),
            },
            _ => server::Auth::reject(),
        })
    }
}

async fn connect() -> (client::Handle<AcceptServerKey>, Arc<Mutex<Vec<String>>>) {
    let mut server_config = server::Config {
        auth_rejection_time: Duration::from_millis(1),
        auth_rejection_time_initial: Some(Duration::from_millis(1)),
        methods: MethodSet::from(&[MethodKind::Password][..]),
        ..Default::default()
    };
    server_config
        .keys
        .push(PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap());
    let server_config = Arc::new(server_config);
    let log = Arc::new(Mutex::new(Vec::new()));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_log = Arc::clone(&log);
    tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let _ = server::run_stream(server_config, socket, Server { log: server_log }).await;
    });

    let session = client::connect(Arc::new(client::Config::default()), addr, AcceptServerKey)
        .await
        .unwrap();
    (session, log)
}

#[tokio::test]
async fn change_after_request() {
    let (mut session, log) = connect().await;
    let reply = session
        .authenticate_password_or_change("user", "old")
        .await
        .unwrap();
    assert_eq!(
        reply,
        client::PasswordAuthResponse::ChangeRequest {
            prompt: PROMPT.into(),
            language_tag: String::new(),
        }
    );
    // A refused new password gets another request.
    let reply = session
        .authenticate_password_change("user", "old", "weak")
        .await
        .unwrap();
    let client::PasswordAuthResponse::ChangeRequest { prompt, .. } = reply else {
        panic!("expected another request: {reply:?}");
    };
    assert_eq!(prompt, "Too simple.");
    let reply = session
        .authenticate_password_change("user", "old", "new")
        .await
        .unwrap();
    assert_eq!(reply, client::PasswordAuthResponse::Success);
    assert_eq!(
        *log.lock().unwrap(),
        [
            "password user old",
            "change user old weak",
            "change user old new"
        ]
    );
}

#[tokio::test]
async fn plain_password_requests() {
    let (mut session, _log) = connect().await;
    // A wrong password is an ordinary failure.
    let reply = session
        .authenticate_password_or_change("user", "wrong")
        .await
        .unwrap();
    assert!(
        matches!(reply, client::PasswordAuthResponse::Failure { .. }),
        "{reply:?}"
    );
    // authenticate_password can't answer a change request: it fails
    // instead of waiting, and the session goes on.
    let error = session
        .authenticate_password("user", "old")
        .await
        .unwrap_err();
    assert!(
        matches!(error, russh::Error::PasswordChangeRequired),
        "{error:?}"
    );
    let reply = session
        .authenticate_password_change("user", "old", "new")
        .await
        .unwrap();
    assert_eq!(reply, client::PasswordAuthResponse::Success);
}
