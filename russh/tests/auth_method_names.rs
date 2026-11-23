//! The server's list of authentication methods reaches the client as sent,
//! and a list without anything the client knows doesn't end the session.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::sync::Arc;
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

/// Rejects `none` with `methods` as the list to continue with, and accepts
/// any password.
struct Server {
    methods: MethodSet,
}

impl server::Handler for Server {
    type Error = russh::Error;

    async fn auth_none(&mut self, _user: &str) -> Result<server::Auth, Self::Error> {
        Ok(server::Auth::Reject {
            proceed_with_methods: Some(self.methods.clone()),
            partial_success: false,
        })
    }

    async fn auth_password(
        &mut self,
        _user: &str,
        _password: &str,
    ) -> Result<server::Auth, Self::Error> {
        Ok(server::Auth::Accept)
    }
}

async fn connect(methods: &[MethodKind]) -> client::Handle<AcceptServerKey> {
    let mut server_config = server::Config {
        auth_rejection_time: Duration::from_millis(1),
        auth_rejection_time_initial: Some(Duration::from_millis(1)),
        ..Default::default()
    };
    server_config
        .keys
        .push(PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap());
    let server_config = Arc::new(server_config);
    let methods = MethodSet::from(methods);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let _ = server::run_stream(server_config, socket, Server { methods }).await;
    });

    client::connect(Arc::new(client::Config::default()), addr, AcceptServerKey)
        .await
        .unwrap()
}

#[tokio::test]
async fn names_as_sent() {
    let mut session = connect(&[MethodKind::Password, MethodKind::PublicKey]).await;
    let result = session.authenticate_none("user").await.unwrap();
    let client::AuthResult::Failure { method_names, .. } = result else {
        panic!("none should fail: {result:?}");
    };
    assert_eq!(method_names, ["password", "publickey"]);
}

#[tokio::test]
async fn empty_list_keeps_the_session() {
    let mut session = connect(&[]).await;
    let result = session.authenticate_none("user").await.unwrap();
    let client::AuthResult::Failure {
        method_names,
        remaining_methods,
        ..
    } = result
    else {
        panic!("none should fail: {result:?}");
    };
    assert!(method_names.is_empty());
    assert!(remaining_methods.is_empty());
    assert!(!session.is_closed());
    let result = session
        .authenticate_password("user", "secret")
        .await
        .unwrap();
    assert!(result.success(), "{result:?}");
}
