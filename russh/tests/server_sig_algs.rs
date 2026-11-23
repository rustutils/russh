//! A client can read the server's `server-sig-algs` without waiting.
#![allow(clippy::unwrap_used)]

use std::sync::Arc;
use std::time::Duration;

use russh::keys::{Algorithm, HashAlg, PrivateKey, PublicKeyOrCertificate, ssh_key};
use russh::{client, server};

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

struct Server;

impl server::Handler for Server {
    type Error = russh::Error;
}

#[tokio::test]
async fn announced_algorithms() {
    let mut server_config = server::Config {
        auth_rejection_time: Duration::from_millis(1),
        auth_rejection_time_initial: Some(Duration::from_millis(1)),
        ..Default::default()
    };
    server_config
        .keys
        .push(PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap());
    let server_config = Arc::new(server_config);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let _ = server::run_stream(server_config, socket, Server).await;
    });

    let mut session = client::connect(Arc::new(client::Config::default()), addr, AcceptServerKey)
        .await
        .unwrap();
    // The extension arrives before the first reply to an authentication
    // request.
    let _ = session.authenticate_none("user").await.unwrap();
    let algorithms = session.server_sig_algs().await.unwrap().unwrap();
    assert!(algorithms.contains(&Algorithm::Ed25519), "{algorithms:?}");
    assert!(
        algorithms.contains(&Algorithm::Rsa {
            hash: Some(HashAlg::Sha512)
        }),
        "{algorithms:?}"
    );
}
