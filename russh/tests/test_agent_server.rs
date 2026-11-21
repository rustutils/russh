//! The in-memory agent server (`agent::server::serve`), driven by russh's
//! client and by OpenSSH's `ssh-add`.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Output;
use std::time::Duration;

use russh::keys::agent::client::AgentClient;
use russh::keys::agent::{AgentIdentity, Constraint};
use russh::keys::signature::Verifier;
use russh::keys::ssh_key::{self, Algorithm, Certificate, LineEnding, PrivateKey};
use russh::keys::{Error, HashAlg};
use tokio::io::AsyncWriteExt;
use tokio::net::{UnixListener, UnixStream};

struct Agent {
    dir: tempfile::TempDir,
}

impl Agent {
    async fn start() -> Agent {
        let dir = tempfile::tempdir().unwrap();
        let listener = UnixListener::bind(dir.path().join("agent")).unwrap();
        let incoming = futures::stream::unfold(listener, |listener| async move {
            let accepted = listener.accept().await.map(|(stream, _)| stream);
            Some((accepted, listener))
        });
        tokio::spawn(russh::keys::agent::server::serve(Box::pin(incoming), ()));
        Agent { dir }
    }

    fn socket(&self) -> PathBuf {
        self.dir.path().join("agent")
    }

    async fn client(&self) -> AgentClient<UnixStream> {
        AgentClient::connect(UnixStream::connect(self.socket()).await.unwrap())
    }

    /// Run OpenSSH's ssh-add against this agent.
    async fn ssh_add(&self, args: &[&str], stdin: &str) -> Output {
        let mut child = tokio::process::Command::new("ssh-add")
            .args(args)
            .current_dir(self.dir.path())
            .env("SSH_AUTH_SOCK", self.socket())
            .env_remove("DISPLAY")
            .env_remove("SSH_ASKPASS")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("ssh-add is installed");
        let mut input = child.stdin.take().unwrap();
        input.write_all(stdin.as_bytes()).await.unwrap();
        drop(input);
        child.wait_with_output().await.unwrap()
    }

    fn write_key(&self, name: &str, key: &PrivateKey) {
        let path = self.dir.path().join(name);
        std::fs::write(&path, key.to_openssh(LineEnding::LF).unwrap().as_bytes()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(
            self.dir.path().join(format!("{name}.pub")),
            key.public_key().to_openssh().unwrap(),
        )
        .unwrap();
    }
}

fn key(comment: &str) -> PrivateKey {
    let mut key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    key.set_comment(comment);
    key
}

fn certificate(ca: &PrivateKey, key: &PrivateKey) -> Certificate {
    let mut builder = ssh_key::certificate::Builder::new_with_random_nonce(
        &mut rand::rng(),
        key.public_key(),
        0,
        u64::MAX,
    )
    .unwrap();
    builder.serial(1).unwrap();
    builder.key_id("cert-id").unwrap();
    builder
        .cert_type(ssh_key::certificate::CertType::User)
        .unwrap();
    builder.valid_principal("alice").unwrap();
    builder.sign(ca).unwrap()
}

fn comments(identities: &[AgentIdentity]) -> Vec<&str> {
    identities.iter().map(|i| i.comment()).collect()
}

#[tokio::test]
async fn keeps_order_and_comments() {
    let agent = Agent::start().await;
    let mut client = agent.client().await;
    let (one, two, three) = (key("one"), key("two"), key("three"));
    for key in [&one, &two, &three] {
        client.add_identity(key, &[]).await.unwrap();
    }
    let identities = client.request_identities().await.unwrap();
    assert_eq!(comments(&identities), ["one", "two", "three"]);

    // Re-adding a key updates it in place.
    let mut renamed = one.clone();
    renamed.set_comment("one again");
    client.add_identity(&renamed, &[]).await.unwrap();
    let identities = client.request_identities().await.unwrap();
    assert_eq!(comments(&identities), ["one again", "two", "three"]);

    client.remove_identity(two.public_key()).await.unwrap();
    let identities = client.request_identities().await.unwrap();
    assert_eq!(comments(&identities), ["one again", "three"]);
}

#[tokio::test]
async fn holds_certificates() {
    let agent = Agent::start().await;
    let mut client = agent.client().await;
    let ca = key("ca");
    let user = key("user");
    let cert = certificate(&ca, &user);
    client.add_identity(&user, &[]).await.unwrap();
    client
        .add_identity_with_certificate(&user, &cert, &[])
        .await
        .unwrap();

    let identities = client.request_identities().await.unwrap();
    assert_eq!(identities.len(), 2);
    match &identities[1] {
        AgentIdentity::Certificate {
            certificate,
            comment,
        } => {
            assert_eq!(certificate, &cert);
            assert_eq!(comment, "user");
        }
        other => panic!("expected a certificate, got {other:?}"),
    }

    // Signing through the certificate uses the key.
    let data = b"data".to_vec();
    let signed = client
        .sign_request(&AgentIdentity::from(cert.clone()), None, data.clone())
        .await
        .unwrap();
    let mut rest = &signed[data.len()..];
    let blob: Vec<u8> = ssh_key::encoding::Decode::decode(&mut rest).unwrap();
    let signature: ssh_key::Signature = ssh_key::encoding::Decode::decode(&mut &blob[..]).unwrap();
    user.public_key()
        .key_data()
        .verify(&data, &signature)
        .unwrap();

    client.remove_certificate(&cert).await.unwrap();
    assert_eq!(client.request_identities().await.unwrap().len(), 1);
}

#[tokio::test]
async fn signs_with_requested_rsa_hash() {
    use ssh_key::private::{KeypairData, RsaKeypair};

    let agent = Agent::start().await;
    let mut client = agent.client().await;
    let rsa = PrivateKey::new(
        KeypairData::Rsa(RsaKeypair::random(&mut rand::rng(), 2048).unwrap()),
        "rsa",
    )
    .unwrap();
    client.add_identity(&rsa, &[]).await.unwrap();
    for (hash, name) in [
        (Some(HashAlg::Sha256), "rsa-sha2-256"),
        (Some(HashAlg::Sha512), "rsa-sha2-512"),
    ] {
        let signature = client
            .sign_request_signature(rsa.public_key(), hash, b"data")
            .await
            .unwrap();
        assert_eq!(signature.algorithm().as_str(), name);
        Verifier::verify(rsa.public_key(), b"data", &signature).unwrap();
    }
}

#[tokio::test]
async fn locking() {
    let agent = Agent::start().await;
    let mut client = agent.client().await;
    let one = key("one");
    client.add_identity(&one, &[]).await.unwrap();

    client.lock(b"secret").await.unwrap();
    assert!(client.lock(b"again").await.is_err(), "already locked");
    // Locked: nothing listed, nothing signed or added.
    assert!(client.request_identities().await.unwrap().is_empty());
    assert!(
        client
            .sign_request_signature(one.public_key(), None, b"data")
            .await
            .is_err()
    );
    assert!(client.add_identity(&key("two"), &[]).await.is_err());

    assert!(client.unlock(b"wrong").await.is_err());
    client.unlock(b"secret").await.unwrap();
    assert!(client.unlock(b"secret").await.is_err(), "not locked");
    assert_eq!(client.request_identities().await.unwrap().len(), 1);
}

#[tokio::test]
async fn lifetime_expires_keys() {
    let agent = Agent::start().await;
    let mut client = agent.client().await;
    client
        .add_identity(&key("short"), &[Constraint::KeyLifetime { seconds: 1 }])
        .await
        .unwrap();
    client.add_identity(&key("long"), &[]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let identities = client.request_identities().await.unwrap();
    assert_eq!(comments(&identities), ["long"]);
}

#[tokio::test]
async fn refuses_constraints_it_cannot_enforce() {
    let agent = Agent::start().await;
    let mut client = agent.client().await;
    let constraint = Constraint::Extensions {
        name: b"restrict-destination-v00@openssh.com".to_vec(),
        details: vec![],
    };
    assert!(matches!(
        client.add_identity(&key("k"), &[constraint]).await,
        Err(Error::AgentFailure)
    ));
    assert!(client.request_identities().await.unwrap().is_empty());
}

#[tokio::test]
async fn answers_query() {
    let agent = Agent::start().await;
    let mut client = agent.client().await;
    assert_eq!(client.query_extensions().await.unwrap(), ["query"]);
}

#[tokio::test]
async fn works_with_openssh_ssh_add() {
    let agent = Agent::start().await;
    let ca = key("ca");
    let user = key("my user key");
    agent.write_key("user", &user);
    std::fs::write(
        agent.dir.path().join("user-cert.pub"),
        certificate(&ca, &user).to_openssh().unwrap(),
    )
    .unwrap();

    let output = agent.ssh_add(&["user"], "").await;
    assert!(output.status.success(), "{output:?}");

    let output = agent.ssh_add(&["-l"], "").await;
    assert!(output.status.success(), "{output:?}");
    let listing = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<_> = listing.lines().collect();
    assert_eq!(lines.len(), 2, "{listing}");
    assert!(lines[0].ends_with("my user key (ED25519)"), "{listing}");
    assert!(
        lines[1].ends_with("my user key (ED25519-CERT)"),
        "{listing}"
    );

    let output = agent.ssh_add(&["-T", "user.pub"], "").await;
    assert!(output.status.success(), "{output:?}");

    // Locked agents list nothing; ssh-add reports that as an empty agent.
    assert!(agent.ssh_add(&["-x"], "pw\npw\n").await.status.success());
    let output = agent.ssh_add(&["-l"], "").await;
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "The agent has no identities.\n"
    );
    assert!(agent.ssh_add(&["-X"], "pw\n").await.status.success());

    let output = agent.ssh_add(&["-d", "user"], "").await;
    assert!(output.status.success(), "{output:?}");
    let output = agent.ssh_add(&["-l"], "").await;
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "The agent has no identities.\n"
    );
}
