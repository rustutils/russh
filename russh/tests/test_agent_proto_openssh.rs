//! Decode what OpenSSH's `ssh-add` sends, and check that it understands
//! what we answer, using a minimal agent built on `agent::proto`.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::process::Output;
use std::sync::{Arc, Mutex};

use russh::keys::agent::Constraint;
use russh::keys::agent::proto::{ExtensionRequest, Identity, Request, Response};
use russh::keys::signature::Signer;
use russh::keys::ssh_key::{self, Algorithm, Certificate, LineEnding, PrivateKey};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

/// A minimal in-memory agent: records every request and answers it.
#[derive(Default)]
struct Recorder {
    requests: Vec<Request>,
    keys: Vec<(Vec<u8>, PrivateKey)>,
}

impl Recorder {
    fn answer(&mut self, request: Request) -> Response {
        let response = match &request {
            Request::RequestIdentities => Response::Identities(
                self.keys
                    .iter()
                    .map(|(blob, key)| Identity {
                        key_blob: blob.clone(),
                        comment: key.comment().as_str_lossy().to_string(),
                    })
                    .collect(),
            ),
            Request::AddIdentity(add) => {
                let blob = match &add.certificate {
                    Some(certificate) => certificate.to_bytes().unwrap(),
                    None => add.key.public_key().to_bytes().unwrap(),
                };
                self.keys.push((blob, add.key.clone()));
                Response::Success
            }
            Request::RemoveIdentity { key_blob } => {
                let before = self.keys.len();
                self.keys.retain(|(blob, _)| blob != key_blob);
                if self.keys.len() < before {
                    Response::Success
                } else {
                    Response::Failure
                }
            }
            Request::RemoveAllIdentities => {
                self.keys.clear();
                Response::Success
            }
            Request::Sign(sign) => {
                match self.keys.iter().find(|(blob, _)| *blob == sign.key_blob) {
                    Some((_, key)) => {
                        let signature: ssh_key::Signature = key.try_sign(&sign.data).unwrap();
                        let mut encoded = Vec::new();
                        ssh_key::encoding::Encode::encode(&signature, &mut encoded).unwrap();
                        Response::Signature(encoded)
                    }
                    None => Response::Failure,
                }
            }
            Request::Lock { .. } | Request::Unlock { .. } => Response::Success,
            Request::Extension(ExtensionRequest::Query) => {
                Response::query_response(&["query", "session-bind@openssh.com"]).unwrap()
            }
            _ => Response::Failure,
        };
        self.requests.push(request);
        response
    }
}

async fn serve(listener: UnixListener, recorder: Arc<Mutex<Recorder>>) {
    while let Ok((stream, _)) = listener.accept().await {
        let recorder = recorder.clone();
        tokio::spawn(async move {
            let _ = handle(stream, recorder).await;
        });
    }
}

async fn handle(mut stream: UnixStream, recorder: Arc<Mutex<Recorder>>) -> std::io::Result<()> {
    loop {
        let len = stream.read_u32().await? as usize;
        let mut payload = vec![0; len];
        stream.read_exact(&mut payload).await?;
        let response = match Request::decode(&payload) {
            Ok(request) => recorder.lock().unwrap().answer(request),
            Err(_) => Response::Failure,
        };
        let message = russh::keys::agent::proto::frame(&response.encode().unwrap()).unwrap();
        stream.write_all(&message).await?;
    }
}

struct Setup {
    dir: tempfile::TempDir,
    recorder: Arc<Mutex<Recorder>>,
}

impl Setup {
    async fn new() -> Setup {
        let dir = tempfile::tempdir().unwrap();
        let listener = UnixListener::bind(dir.path().join("agent")).unwrap();
        let recorder = Arc::new(Mutex::new(Recorder::default()));
        tokio::spawn(serve(listener, recorder.clone()));
        Setup { dir, recorder }
    }

    /// Run OpenSSH's ssh-add against our agent.
    async fn ssh_add(&self, args: &[&str], stdin: &str) -> Output {
        use tokio::process::Command;

        let mut child = Command::new("ssh-add")
            .args(args)
            .current_dir(self.dir.path())
            .env("SSH_AUTH_SOCK", self.dir.path().join("agent"))
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

    fn take_requests(&self) -> Vec<Request> {
        std::mem::take(&mut self.recorder.lock().unwrap().requests)
    }
}

fn key(algorithm: Algorithm, comment: &str) -> PrivateKey {
    let mut key = PrivateKey::random(&mut rand::rng(), algorithm).unwrap();
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

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "ssh-add failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
async fn decodes_openssh_add_requests() {
    let setup = Setup::new().await;
    let ca = key(Algorithm::Ed25519, "ca");
    let plain = key(Algorithm::Ed25519, "plain key");
    let ecdsa = key(
        Algorithm::Ecdsa {
            curve: ssh_key::EcdsaCurve::NistP384,
        },
        "ecdsa key",
    );
    let certified = key(Algorithm::Ed25519, "certified key");
    let cert = certificate(&ca, &certified);
    setup.write_key("plain", &plain);
    setup.write_key("ecdsa", &ecdsa);
    setup.write_key("certified", &certified);
    std::fs::write(
        setup.dir.path().join("certified-cert.pub"),
        cert.to_openssh().unwrap(),
    )
    .unwrap();

    assert_success(
        &setup
            .ssh_add(&["-c", "-t", "60", "plain", "ecdsa", "certified"], "")
            .await,
    );

    let added: Vec<_> = setup
        .take_requests()
        .into_iter()
        .map(|request| match request {
            Request::AddIdentity(add) => add,
            other => panic!("unexpected request {other:?}"),
        })
        .collect();
    // Each key, then the certificate after its key.
    assert_eq!(added.len(), 4);
    let expected = [
        (&plain, None),
        (&ecdsa, None),
        (&certified, None),
        (&certified, Some(&cert)),
    ];
    for (add, (key, certificate)) in added.iter().zip(expected) {
        assert_eq!(&add.key, key);
        assert_eq!(add.key.comment(), key.comment());
        assert_eq!(add.certificate.as_ref(), certificate);
        assert_eq!(
            add.constraints,
            [Constraint::KeyLifetime { seconds: 60 }, Constraint::Confirm]
        );
    }
}

#[tokio::test]
async fn openssh_understands_our_responses() {
    let setup = Setup::new().await;
    let one = key(Algorithm::Ed25519, "first key");
    let two = key(Algorithm::Ed25519, "second key");
    setup.write_key("one", &one);
    setup.write_key("two", &two);
    assert_success(&setup.ssh_add(&["one", "two"], "").await);

    // Identities answer: listed in order, with comments.
    let output = setup.ssh_add(&["-l"], "").await;
    assert_success(&output);
    let listing = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<_> = listing.lines().collect();
    assert_eq!(lines.len(), 2, "{listing}");
    assert!(lines[0].ends_with("first key (ED25519)"), "{listing}");
    assert!(lines[1].ends_with("second key (ED25519)"), "{listing}");

    // Signature: ssh-add -T verifies it.
    assert_success(&setup.ssh_add(&["-T", "one.pub"], "").await);

    // Query extension response.
    let output = setup.ssh_add(&["-Q"], "").await;
    assert_success(&output);
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "query\nsession-bind@openssh.com\n"
    );

    // Removal, locking and removing everything.
    assert_success(&setup.ssh_add(&["-d", "one"], "").await);
    assert_success(&setup.ssh_add(&["-x"], "secret\nsecret\n").await);
    assert_success(&setup.ssh_add(&["-X"], "secret\n").await);
    assert_success(&setup.ssh_add(&["-D"], "").await);

    let requests = setup.take_requests();
    let one_blob = one.public_key().to_bytes().unwrap();
    assert!(
        requests
            .iter()
            .any(|r| matches!(r, Request::RemoveIdentity { key_blob } if *key_blob == one_blob))
    );
    assert!(
        requests.iter().any(
            |r| matches!(r, Request::Lock { passphrase } if passphrase.as_slice() == b"secret")
        )
    );
    assert!(requests.iter().any(
        |r| matches!(r, Request::Unlock { passphrase } if passphrase.as_slice() == b"secret")
    ));
    assert!(
        requests
            .iter()
            .any(|r| matches!(r, Request::RemoveAllIdentities))
    );
    assert!(
        requests
            .iter()
            .any(|r| matches!(r, Request::Sign(sign) if sign.key_blob == one_blob))
    );
}
