use std::marker::Sync;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::future::Future;
use futures::stream::{Stream, StreamExt};
use ssh_key::{HashAlg, PrivateKey};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::sleep;
use zeroize::Zeroizing;
use {std, tokio};

use super::proto::{self, AddIdentity, ExtensionRequest, Identity, Request, Response, SignRequest};
use super::{Constraint, msg};
use crate::helpers::sign_with_hash_alg;
use crate::keys::Error;
use crate::keys::key::PrivateKeyWithHashAlg;

/// A key held by the agent.
struct Entry {
    /// Public key blob, or certificate blob for certificate identities.
    blob: Vec<u8>,
    key: Arc<PrivateKey>,
    comment: String,
    confirm: bool,
    /// Distinguishes this addition from earlier ones of the same key, so a
    /// lifetime timer only removes the addition it belongs to.
    generation: u64,
}

/// State shared by all connections to one agent.
#[derive(Default)]
struct State {
    /// Keys in the order they were added; re-adding a key keeps its place.
    entries: Vec<Entry>,
    /// Lock passphrase while the agent is locked.
    lock: Option<Zeroizing<Vec<u8>>>,
    next_generation: u64,
}

#[derive(Clone, Default)]
struct Shared(Arc<Mutex<State>>);

impl Shared {
    fn with<T>(&self, f: impl FnOnce(&mut State) -> T) -> T {
        // A panic while holding the lock can't leave the state inconsistent
        // in a way that matters more than refusing service, so recover.
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        f(&mut state)
    }
}

#[allow(missing_docs)]
#[derive(Debug)]
pub enum ServerError<E> {
    E(E),
    Error(Error),
}

pub enum MessageType {
    RequestKeys,
    AddKeys,
    RemoveKeys,
    RemoveAllKeys,
    Sign,
    Lock,
    Unlock,
}

pub trait Agent: Clone + Send + 'static {
    fn confirm(
        self,
        _pk: Arc<PrivateKey>,
    ) -> Box<dyn Future<Output = (Self, bool)> + Unpin + Send> {
        Box::new(futures::future::ready((self, true)))
    }

    fn confirm_request(&self, _msg: MessageType) -> impl Future<Output = bool> + Send {
        async { true }
    }
}

/// Serve the agent protocol on every connection from `listener`, with keys
/// kept in memory and shared between connections.
///
/// Identities are listed in the order they were added, with their comments;
/// keys may be added together with a certificate. The lifetime and confirm
/// constraints are supported (confirmation is delegated to
/// [`Agent::confirm`]); keys with other constraints are refused. While
/// locked, the agent lists no identities and refuses everything but
/// unlocking. The only extension supported is `query`.
pub async fn serve<S, L, A>(mut listener: L, agent: A) -> Result<(), Error>
where
    S: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
    L: Stream<Item = tokio::io::Result<S>> + Unpin,
    A: Agent + Send + Sync + 'static,
{
    let shared = Shared::default();
    while let Some(Ok(stream)) = listener.next().await {
        russh_util::runtime::spawn(
            (Connection {
                shared: shared.clone(),
                agent: Some(agent.clone()),
                s: stream,
                buf: Vec::new(),
            })
            .run(),
        );
    }
    Ok(())
}

impl Agent for () {
    fn confirm(self, _: Arc<PrivateKey>) -> Box<dyn Future<Output = (Self, bool)> + Unpin + Send> {
        Box::new(futures::future::ready((self, true)))
    }
}

struct Connection<S: AsyncRead + AsyncWrite + Send + 'static, A: Agent> {
    shared: Shared,
    agent: Option<A>,
    s: S,
    buf: Vec<u8>,
}

impl<S: AsyncRead + AsyncWrite + Send + Unpin + 'static, A: Agent + Send + Sync + 'static>
    Connection<S, A>
{
    async fn read_frame(&mut self) -> Result<(), Error> {
        let len = self.s.read_u32().await? as usize;
        if len > proto::MAX_MESSAGE_LEN {
            return Err(Error::AgentProtocolError);
        }
        self.buf.clear();
        self.buf.resize(len, 0);
        self.s.read_exact(&mut self.buf).await?;
        Ok(())
    }

    async fn run(mut self) -> Result<(), Error> {
        loop {
            self.read_frame().await?;
            let response = match Request::decode(&self.buf) {
                Ok(request) => self.respond(request).await,
                // Like OpenSSH, answer malformed messages with a failure
                // rather than dropping the connection.
                Err(_) => Response::Failure,
            };
            let message = proto::frame(&response.encode()?)?;
            self.s.write_all(&message).await?;
            self.s.flush().await?
        }
    }

    fn is_locked(&self) -> bool {
        self.shared.with(|state| state.lock.is_some())
    }

    async fn allowed(&self, message: MessageType) -> bool {
        match &self.agent {
            Some(agent) => agent.confirm_request(message).await,
            None => false,
        }
    }

    async fn respond(&mut self, request: Request) -> Response {
        let locked = self.is_locked();
        match request {
            Request::RequestIdentities if self.allowed(MessageType::RequestKeys).await => {
                if locked {
                    // OpenSSH lists nothing rather than failing.
                    return Response::Identities(Vec::new());
                }
                Response::Identities(self.shared.with(|state| {
                    state
                        .entries
                        .iter()
                        .map(|entry| Identity {
                            key_blob: entry.blob.clone(),
                            comment: entry.comment.clone(),
                        })
                        .collect()
                }))
            }
            Request::Sign(sign) if !locked && self.allowed(MessageType::Sign).await => {
                self.sign(sign).await
            }
            Request::AddIdentity(add) if !locked && self.allowed(MessageType::AddKeys).await => {
                self.add(*add)
            }
            Request::RemoveIdentity { key_blob }
                if !locked && self.allowed(MessageType::RemoveKeys).await =>
            {
                let removed = self.shared.with(|state| {
                    let before = state.entries.len();
                    state.entries.retain(|entry| entry.blob != key_blob);
                    state.entries.len() < before
                });
                if removed {
                    Response::Success
                } else {
                    Response::Failure
                }
            }
            Request::RemoveAllIdentities
                if !locked && self.allowed(MessageType::RemoveAllKeys).await =>
            {
                self.shared.with(|state| state.entries.clear());
                Response::Success
            }
            Request::Lock { passphrase } if !locked && self.allowed(MessageType::Lock).await => {
                self.shared.with(|state| state.lock = Some(passphrase));
                Response::Success
            }
            Request::Unlock { passphrase } if locked && self.allowed(MessageType::Unlock).await => {
                let unlocked = self.shared.with(|state| {
                    let matches = state
                        .lock
                        .as_ref()
                        .is_some_and(|lock| bool::from(lock.as_slice().ct_eq(&passphrase)));
                    if matches {
                        state.lock = None;
                    }
                    matches
                });
                if unlocked {
                    Response::Success
                } else {
                    Response::Failure
                }
            }
            Request::Extension(ExtensionRequest::Query) => {
                Response::query_response(&["query"]).unwrap_or(Response::Failure)
            }
            _ => Response::Failure,
        }
    }

    fn add(&self, add: AddIdentity) -> Response {
        let mut lifetime = None;
        let mut confirm = false;
        for constraint in &add.constraints {
            match constraint {
                Constraint::KeyLifetime { seconds } => {
                    if lifetime.replace(*seconds).is_some() {
                        return Response::Failure;
                    }
                }
                Constraint::Confirm => confirm = true,
                // Constraints we can't enforce must not be silently ignored.
                Constraint::Extensions { .. } => return Response::Failure,
            }
        }
        let blob = match &add.certificate {
            Some(certificate) => certificate.to_bytes(),
            None => add.key.public_key().to_bytes(),
        };
        let Ok(blob) = blob else {
            return Response::Failure;
        };
        let comment = add.key.comment().as_str_lossy().to_string();
        let key = Arc::new(add.key);

        let generation = self.shared.with(|state| {
            state.next_generation += 1;
            let generation = state.next_generation;
            let entry = Entry {
                blob: blob.clone(),
                key,
                comment,
                confirm,
                generation,
            };
            match state.entries.iter_mut().find(|e| e.blob == blob) {
                Some(existing) => *existing = entry,
                None => state.entries.push(entry),
            }
            generation
        });

        if let Some(seconds) = lifetime {
            let shared = self.shared.clone();
            russh_util::runtime::spawn(async move {
                sleep(Duration::from_secs(u64::from(seconds))).await;
                shared.with(|state| {
                    state
                        .entries
                        .retain(|e| !(e.blob == blob && e.generation == generation))
                });
            });
        }
        Response::Success
    }

    async fn sign(&mut self, sign: SignRequest) -> Response {
        let found = self.shared.with(|state| {
            state
                .entries
                .iter()
                .find(|e| e.blob == sign.key_blob)
                .map(|e| (e.key.clone(), e.confirm, e.generation))
        });
        let Some((key, confirm, generation)) = found else {
            return Response::Failure;
        };

        if confirm {
            let Some(agent) = self.agent.take() else {
                return Response::Failure;
            };
            let (agent, ok) = agent.confirm(key.clone()).await;
            self.agent = Some(agent);
            if !ok {
                return Response::Failure;
            }
            // The agent may have been locked, or the key removed or
            // replaced, while confirmation was pending.
            let still_valid = self.shared.with(|state| {
                state.lock.is_none()
                    && state
                        .entries
                        .iter()
                        .any(|e| e.blob == sign.key_blob && e.generation == generation)
            });
            if !still_valid {
                return Response::Failure;
            }
        }

        let hash_alg = if sign.flags & msg::SSH_AGENT_RSA_SHA2_256 != 0 {
            Some(HashAlg::Sha256)
        } else if sign.flags & msg::SSH_AGENT_RSA_SHA2_512 != 0 {
            Some(HashAlg::Sha512)
        } else {
            None
        };
        match sign_with_hash_alg(&PrivateKeyWithHashAlg::new(key, hash_alg), &sign.data) {
            Ok(signature) => Response::Signature(signature),
            Err(_) => Response::Failure,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::io::AsyncWriteExt;

    use super::{Agent, Connection, Shared};
    use crate::keys::Error;
    use crate::keys::agent::Constraint;
    use crate::keys::agent::proto::{self, AddIdentity, Request, Response, SignRequest};
    use crate::keys::{Algorithm, PrivateKey};

    fn connection<A: Agent + Sync>(agent: A) -> Connection<tokio::io::DuplexStream, A> {
        let (server, _client) = tokio::io::duplex(64);
        Connection {
            shared: Shared::default(),
            agent: Some(agent),
            s: server,
            buf: Vec::new(),
        }
    }

    fn add(key: &PrivateKey, constraints: Vec<Constraint>) -> Request {
        Request::AddIdentity(Box::new(AddIdentity {
            key: key.clone(),
            certificate: None,
            constraints,
        }))
    }

    #[test]
    fn oversized_agent_request_is_rejected_before_allocation() -> std::io::Result<()> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;

        runtime.block_on(async {
            let (server, mut client) = tokio::io::duplex(64);
            let connection = Connection {
                shared: Shared::default(),
                agent: Some(()),
                s: server,
                buf: Vec::new(),
            };
            let server = tokio::spawn(async move { connection.run().await });

            let len = u32::try_from(proto::MAX_MESSAGE_LEN + 1).unwrap_or(u32::MAX);
            client.write_all(&len.to_be_bytes()).await?;
            drop(client);

            let err = server.await.expect("server task").unwrap_err();
            assert!(matches!(err, Error::AgentProtocolError));
            Ok::<(), std::io::Error>(())
        })?;

        Ok(())
    }

    #[tokio::test]
    async fn duplicate_confirm_constraints_are_accepted() {
        let mut connection = connection(());
        let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        let constraints = vec![Constraint::Confirm; 100];
        assert_eq!(
            connection.respond(add(&key, constraints)).await,
            Response::Success
        );
        assert!(connection.shared.with(|state| state.entries[0].confirm));
    }

    #[tokio::test]
    async fn duplicate_lifetime_constraints_are_refused() {
        let mut connection = connection(());
        let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        let lifetime = Constraint::KeyLifetime { seconds: 60 };
        assert_eq!(
            connection
                .respond(add(&key, vec![lifetime.clone(), lifetime]))
                .await,
            Response::Failure
        );
    }

    #[tokio::test]
    async fn sign_is_rejected_when_locked_during_confirm() {
        use std::future::Future;

        use tokio::sync::Notify;
        use zeroize::Zeroizing;

        #[derive(Clone)]
        struct Delayed(Arc<Notify>, Arc<Notify>);
        impl Agent for Delayed {
            fn confirm(
                self,
                _: Arc<PrivateKey>,
            ) -> Box<dyn Future<Output = (Self, bool)> + Unpin + Send> {
                Box::new(Box::pin(async move {
                    self.0.notify_one();
                    self.1.notified().await;
                    (self, true)
                }))
            }
        }

        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let mut connection = connection(Delayed(entered.clone(), release.clone()));
        let shared = connection.shared.clone();

        let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        assert_eq!(
            connection
                .respond(add(&key, vec![Constraint::Confirm]))
                .await,
            Response::Success
        );
        let sign = Request::Sign(SignRequest {
            key_blob: key.public_key().to_bytes().unwrap(),
            data: b"data".to_vec(),
            flags: 0,
        });

        let signer = connection.respond(sign);
        let locker = async {
            entered.notified().await;
            shared.with(|state| state.lock = Some(Zeroizing::new(b"pw".to_vec())));
            release.notify_one();
        };
        let (response, ()) = tokio::join!(signer, locker);
        assert_eq!(response, Response::Failure);
    }
}
