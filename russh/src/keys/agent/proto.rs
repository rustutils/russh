//! Typed messages of the SSH agent protocol.
//!
//! This module encodes and decodes the messages exchanged between agent
//! clients and agents, as specified in [draft-miller-ssh-agent] and
//! OpenSSH's `PROTOCOL.agent`, without implementing either side's
//! behaviour. Agents decode a [`Request`] from each message they receive
//! and answer with an encoded [`Response`]; clients do the reverse.
//!
//! Every message on the wire is a `uint32` length followed by that many
//! bytes of payload, whose first byte is the message type. [`frame`] adds
//! the length; the `decode` and `encode` functions work on payloads.
//!
//! [draft-miller-ssh-agent]: https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent

use ssh_encoding::{Decode, Encode};
use ssh_key::private::{EcdsaKeypair, Ed25519Keypair, KeypairData, RsaKeypair, RsaPrivateKey};
use ssh_key::public::{EcdsaPublicKey, KeyData};
use ssh_key::{Algorithm, Certificate, PrivateKey};
use zeroize::Zeroizing;

use super::{Constraint, msg};
use crate::keys::Error;

/// The largest message agents accept, as in OpenSSH.
pub const MAX_MESSAGE_LEN: usize = 256 * 1024;

/// Constraint extensions whose data is a single string, which we represent
/// as [`Constraint::Extensions`] with that string as `details`.
const STRING_CONSTRAINT_EXTENSIONS: &[&str] = &[
    "sk-provider@openssh.com",
    "restrict-destination-v00@openssh.com",
];

/// A message from a client to an agent.
#[derive(Debug)]
pub enum Request {
    /// `SSH_AGENTC_REQUEST_IDENTITIES`: list the agent's keys.
    RequestIdentities,
    /// `SSH_AGENTC_SIGN_REQUEST`.
    Sign(SignRequest),
    /// `SSH_AGENTC_ADD_IDENTITY` or, with constraints,
    /// `SSH_AGENTC_ADD_ID_CONSTRAINED`. Boxed, as it holds a private key.
    AddIdentity(Box<AddIdentity>),
    /// `SSH_AGENTC_REMOVE_IDENTITY`: remove the key or certificate with this
    /// public key blob.
    RemoveIdentity { key_blob: Vec<u8> },
    /// `SSH_AGENTC_REMOVE_ALL_IDENTITIES`.
    RemoveAllIdentities,
    /// `SSH_AGENTC_ADD_SMARTCARD_KEY` or, with constraints,
    /// `SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED`.
    AddSmartcardKey {
        id: String,
        pin: Zeroizing<Vec<u8>>,
        constraints: Vec<Constraint>,
    },
    /// `SSH_AGENTC_REMOVE_SMARTCARD_KEY`.
    RemoveSmartcardKey { id: String, pin: Zeroizing<Vec<u8>> },
    /// `SSH_AGENTC_LOCK`.
    Lock { passphrase: Zeroizing<Vec<u8>> },
    /// `SSH_AGENTC_UNLOCK`.
    Unlock { passphrase: Zeroizing<Vec<u8>> },
    /// `SSH_AGENTC_EXTENSION`.
    Extension(ExtensionRequest),
    /// A message type this module doesn't know. Agents should answer with
    /// [`Response::Failure`].
    Unknown { message_type: u8 },
}

/// A request to sign data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignRequest {
    /// Public key or certificate blob of the key to sign with.
    pub key_blob: Vec<u8>,
    pub data: Vec<u8>,
    /// `SSH_AGENT_RSA_SHA2_256` (2) or `SSH_AGENT_RSA_SHA2_512` (4) for RSA
    /// keys.
    pub flags: u32,
}

/// A key to add, optionally with a certificate for it. The key's comment
/// is the one sent with it.
#[derive(Debug)]
pub struct AddIdentity {
    pub key: PrivateKey,
    pub certificate: Option<Certificate>,
    pub constraints: Vec<Constraint>,
}

/// An `SSH_AGENTC_EXTENSION` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtensionRequest {
    /// `query`: list the supported extensions.
    Query,
    /// `session-bind@openssh.com`: bind the connection to an SSH session.
    SessionBind(SessionBind),
    /// Any other extension, with its undecoded contents.
    Other { name: String, contents: Vec<u8> },
}

/// Contents of a `session-bind@openssh.com` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionBind {
    /// The server's host key blob.
    pub host_key: Vec<u8>,
    pub session_id: Vec<u8>,
    /// The server's signature over the session identifier.
    pub signature: Vec<u8>,
    /// Whether the connection is a forwarded agent.
    pub forwarding: bool,
}

/// A message from an agent to a client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    /// `SSH_AGENT_SUCCESS`.
    Success,
    /// `SSH_AGENT_FAILURE`.
    Failure,
    /// `SSH_AGENT_IDENTITIES_ANSWER`.
    Identities(Vec<Identity>),
    /// `SSH_AGENT_SIGN_RESPONSE`, with the encoded signature.
    Signature(Vec<u8>),
    /// `SSH_AGENT_EXTENSION_RESPONSE`, with the extension's name and its
    /// extension-specific contents.
    ExtensionResponse { name: String, contents: Vec<u8> },
    /// `SSH_AGENT_EXTENSION_FAILURE`.
    ExtensionFailure,
}

/// One entry of an identities answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// Public key or certificate blob.
    pub key_blob: Vec<u8>,
    pub comment: String,
}

impl Response {
    /// The answer to a [`ExtensionRequest::Query`]: the extension names.
    pub fn query_response<S: AsRef<str>>(extensions: &[S]) -> Result<Response, Error> {
        let mut contents = Vec::new();
        for extension in extensions {
            extension.as_ref().encode(&mut contents)?;
        }
        Ok(Response::ExtensionResponse {
            name: "query".into(),
            contents,
        })
    }
}

/// Prefix a payload with its length, giving a message ready to send.
pub fn frame(payload: &[u8]) -> Result<Vec<u8>, Error> {
    let len = u32::try_from(payload.len()).map_err(|_| Error::AgentProtocolError)?;
    let mut message = Vec::with_capacity(payload.len() + 4);
    len.encode(&mut message)?;
    message.extend_from_slice(payload);
    Ok(message)
}

impl Request {
    /// Decode a request payload. Unknown message types decode to
    /// [`Request::Unknown`]; malformed known messages are errors.
    pub fn decode(payload: &[u8]) -> Result<Request, Error> {
        let (&message_type, mut r) = payload.split_first().ok_or(Error::AgentProtocolError)?;
        let request = match message_type {
            msg::REQUEST_IDENTITIES => Request::RequestIdentities,
            msg::SIGN_REQUEST => Request::Sign(SignRequest {
                key_blob: Vec::decode(&mut r)?,
                data: Vec::decode(&mut r)?,
                flags: u32::decode(&mut r)?,
            }),
            msg::ADD_IDENTITY | msg::ADD_ID_CONSTRAINED => {
                let (key, certificate) = decode_private_key(&mut r)?;
                let constraints = if message_type == msg::ADD_ID_CONSTRAINED {
                    decode_constraints(&mut r)?
                } else {
                    Vec::new()
                };
                Request::AddIdentity(Box::new(AddIdentity {
                    key,
                    certificate,
                    constraints,
                }))
            }
            msg::REMOVE_IDENTITY => Request::RemoveIdentity {
                key_blob: Vec::decode(&mut r)?,
            },
            msg::REMOVE_ALL_IDENTITIES => Request::RemoveAllIdentities,
            msg::ADD_SMARTCARD_KEY | msg::ADD_SMARTCARD_KEY_CONSTRAINED => {
                let id = String::decode(&mut r)?;
                let pin = Zeroizing::new(Vec::decode(&mut r)?);
                let constraints = if message_type == msg::ADD_SMARTCARD_KEY_CONSTRAINED {
                    decode_constraints(&mut r)?
                } else {
                    Vec::new()
                };
                Request::AddSmartcardKey {
                    id,
                    pin,
                    constraints,
                }
            }
            msg::REMOVE_SMARTCARD_KEY => Request::RemoveSmartcardKey {
                id: String::decode(&mut r)?,
                pin: Zeroizing::new(Vec::decode(&mut r)?),
            },
            msg::LOCK => Request::Lock {
                passphrase: Zeroizing::new(Vec::decode(&mut r)?),
            },
            msg::UNLOCK => Request::Unlock {
                passphrase: Zeroizing::new(Vec::decode(&mut r)?),
            },
            msg::EXTENSION => {
                let name = String::decode(&mut r)?;
                let contents = r;
                r = &[];
                Request::Extension(decode_extension(name, contents)?)
            }
            message_type => return Ok(Request::Unknown { message_type }),
        };
        if !r.is_empty() {
            return Err(Error::AgentProtocolError);
        }
        Ok(request)
    }

    /// Encode this request as a payload.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut buf = Vec::new();
        match self {
            Request::RequestIdentities => msg::REQUEST_IDENTITIES.encode(&mut buf)?,
            Request::Sign(sign) => {
                msg::SIGN_REQUEST.encode(&mut buf)?;
                sign.key_blob.encode(&mut buf)?;
                sign.data.encode(&mut buf)?;
                sign.flags.encode(&mut buf)?;
            }
            Request::AddIdentity(add) => encode_add_identity(
                &mut buf,
                &add.key,
                add.certificate.as_ref(),
                &add.constraints,
            )?,
            Request::RemoveIdentity { key_blob } => {
                msg::REMOVE_IDENTITY.encode(&mut buf)?;
                key_blob.encode(&mut buf)?;
            }
            Request::RemoveAllIdentities => msg::REMOVE_ALL_IDENTITIES.encode(&mut buf)?,
            Request::AddSmartcardKey {
                id,
                pin,
                constraints,
            } => {
                if constraints.is_empty() {
                    msg::ADD_SMARTCARD_KEY.encode(&mut buf)?;
                } else {
                    msg::ADD_SMARTCARD_KEY_CONSTRAINED.encode(&mut buf)?;
                }
                id.encode(&mut buf)?;
                pin.as_slice().encode(&mut buf)?;
                encode_constraints(&mut buf, constraints)?;
            }
            Request::RemoveSmartcardKey { id, pin } => {
                msg::REMOVE_SMARTCARD_KEY.encode(&mut buf)?;
                id.encode(&mut buf)?;
                pin.as_slice().encode(&mut buf)?;
            }
            Request::Lock { passphrase } => {
                msg::LOCK.encode(&mut buf)?;
                passphrase.as_slice().encode(&mut buf)?;
            }
            Request::Unlock { passphrase } => {
                msg::UNLOCK.encode(&mut buf)?;
                passphrase.as_slice().encode(&mut buf)?;
            }
            Request::Extension(extension) => {
                msg::EXTENSION.encode(&mut buf)?;
                match extension {
                    ExtensionRequest::Query => "query".encode(&mut buf)?,
                    ExtensionRequest::SessionBind(bind) => {
                        "session-bind@openssh.com".encode(&mut buf)?;
                        bind.host_key.encode(&mut buf)?;
                        bind.session_id.encode(&mut buf)?;
                        bind.signature.encode(&mut buf)?;
                        u8::from(bind.forwarding).encode(&mut buf)?;
                    }
                    ExtensionRequest::Other { name, contents } => {
                        name.encode(&mut buf)?;
                        buf.extend_from_slice(contents);
                    }
                }
            }
            Request::Unknown { message_type } => message_type.encode(&mut buf)?,
        }
        Ok(buf)
    }
}

impl Response {
    /// Decode a response payload.
    pub fn decode(payload: &[u8]) -> Result<Response, Error> {
        let (&message_type, mut r) = payload.split_first().ok_or(Error::AgentProtocolError)?;
        let response = match message_type {
            msg::SUCCESS => Response::Success,
            msg::FAILURE => Response::Failure,
            msg::IDENTITIES_ANSWER => {
                let count = u32::decode(&mut r)?;
                let mut identities = Vec::new();
                for _ in 0..count {
                    identities.push(Identity {
                        key_blob: Vec::decode(&mut r)?,
                        comment: String::decode(&mut r)?,
                    });
                }
                Response::Identities(identities)
            }
            msg::SIGN_RESPONSE => Response::Signature(Vec::decode(&mut r)?),
            msg::EXTENSION_RESPONSE => {
                let name = String::decode(&mut r)?;
                let contents = r.to_vec();
                r = &[];
                Response::ExtensionResponse { name, contents }
            }
            msg::EXTENSION_FAILURE => Response::ExtensionFailure,
            _ => return Err(Error::AgentProtocolError),
        };
        if !r.is_empty() {
            return Err(Error::AgentProtocolError);
        }
        Ok(response)
    }

    /// Encode this response as a payload.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut buf = Vec::new();
        match self {
            Response::Success => msg::SUCCESS.encode(&mut buf)?,
            Response::Failure => msg::FAILURE.encode(&mut buf)?,
            Response::Identities(identities) => {
                msg::IDENTITIES_ANSWER.encode(&mut buf)?;
                u32::try_from(identities.len())
                    .map_err(|_| Error::AgentProtocolError)?
                    .encode(&mut buf)?;
                for identity in identities {
                    identity.key_blob.encode(&mut buf)?;
                    identity.comment.encode(&mut buf)?;
                }
            }
            Response::Signature(signature) => {
                msg::SIGN_RESPONSE.encode(&mut buf)?;
                signature.encode(&mut buf)?;
            }
            Response::ExtensionResponse { name, contents } => {
                msg::EXTENSION_RESPONSE.encode(&mut buf)?;
                name.encode(&mut buf)?;
                buf.extend_from_slice(contents);
            }
            Response::ExtensionFailure => msg::EXTENSION_FAILURE.encode(&mut buf)?,
        }
        Ok(buf)
    }
}

fn decode_extension(name: String, mut r: &[u8]) -> Result<ExtensionRequest, Error> {
    let extension = match name.as_str() {
        "query" => ExtensionRequest::Query,
        "session-bind@openssh.com" => ExtensionRequest::SessionBind(SessionBind {
            host_key: Vec::decode(&mut r)?,
            session_id: Vec::decode(&mut r)?,
            signature: Vec::decode(&mut r)?,
            forwarding: u8::decode(&mut r)? != 0,
        }),
        _ => {
            return Ok(ExtensionRequest::Other {
                name,
                contents: r.to_vec(),
            });
        }
    };
    if !r.is_empty() {
        return Err(Error::AgentProtocolError);
    }
    Ok(extension)
}

/// Decode a sequence of key constraints, which runs to the end of the
/// message. Extensions whose data format we don't know can't be skipped,
/// so they are errors, as in OpenSSH.
fn decode_constraints(r: &mut &[u8]) -> Result<Vec<Constraint>, Error> {
    let mut constraints = Vec::new();
    while !r.is_empty() {
        match u8::decode(r)? {
            msg::CONSTRAIN_LIFETIME => constraints.push(Constraint::KeyLifetime {
                seconds: u32::decode(r)?,
            }),
            msg::CONSTRAIN_CONFIRM => constraints.push(Constraint::Confirm),
            msg::CONSTRAIN_EXTENSION => {
                let name = String::decode(r)?;
                if !STRING_CONSTRAINT_EXTENSIONS.contains(&name.as_str()) {
                    return Err(Error::AgentProtocolError);
                }
                constraints.push(Constraint::Extensions {
                    name: name.into_bytes(),
                    details: Vec::decode(r)?,
                });
            }
            _ => return Err(Error::AgentProtocolError),
        }
    }
    Ok(constraints)
}

/// Append key constraints in the agent protocol's format: each one is a
/// type byte followed by its data, with no count in front.
pub(crate) fn encode_constraints(
    buf: &mut Vec<u8>,
    constraints: &[Constraint],
) -> Result<(), Error> {
    for constraint in constraints {
        match constraint {
            Constraint::KeyLifetime { seconds } => {
                msg::CONSTRAIN_LIFETIME.encode(buf)?;
                seconds.encode(buf)?;
            }
            Constraint::Confirm => msg::CONSTRAIN_CONFIRM.encode(buf)?,
            Constraint::Extensions { name, details } => {
                msg::CONSTRAIN_EXTENSION.encode(buf)?;
                name.encode(buf)?;
                details.encode(buf)?;
            }
        }
    }
    Ok(())
}

/// Append an add-identity message for `key` (with `certificate`, if any),
/// using `key`'s comment.
pub(crate) fn encode_add_identity(
    buf: &mut Vec<u8>,
    key: &PrivateKey,
    certificate: Option<&Certificate>,
    constraints: &[Constraint],
) -> Result<(), Error> {
    if constraints.is_empty() {
        msg::ADD_IDENTITY.encode(buf)?;
    } else {
        msg::ADD_ID_CONSTRAINED.encode(buf)?;
    }
    match certificate {
        None => key.key_data().encode(buf)?,
        Some(certificate) => {
            // OpenSSH's private key serialization for certificates: the
            // certificate type and blob, then only the private parts of the
            // key (the public parts are in the certificate).
            certificate.algorithm().to_certificate_type().encode(buf)?;
            certificate.to_bytes()?.encode(buf)?;
            match key.key_data() {
                KeypairData::Rsa(rsa) => rsa.private().encode(buf)?,
                KeypairData::Ecdsa(EcdsaKeypair::NistP256 { private, .. }) => {
                    private.encode(buf)?
                }
                KeypairData::Ecdsa(EcdsaKeypair::NistP384 { private, .. }) => {
                    private.encode(buf)?
                }
                KeypairData::Ecdsa(EcdsaKeypair::NistP521 { private, .. }) => {
                    private.encode(buf)?
                }
                KeypairData::Ed25519(ed25519) => ed25519.encode(buf)?,
                _ => return Err(unsupported(key.algorithm())),
            }
        }
    }
    key.comment().as_bytes().encode(buf)?;
    encode_constraints(buf, constraints)
}

fn unsupported(algorithm: Algorithm) -> Error {
    Error::UnsupportedKeyType {
        key_type_string: algorithm.to_string(),
        key_type_raw: algorithm.as_str().as_bytes().to_vec(),
    }
}

/// Decode the key of an add-identity message, followed by its comment.
fn decode_private_key(r: &mut &[u8]) -> Result<(PrivateKey, Option<Certificate>), Error> {
    let type_name = String::decode(r)?;
    let (keypair, certificate) = match Algorithm::new_certificate(&type_name) {
        Ok(algorithm) => {
            let blob = Vec::decode(r)?;
            let certificate = Certificate::from_bytes(&blob)?;
            if certificate.algorithm() != algorithm {
                return Err(Error::AgentProtocolError);
            }
            let keypair = decode_certified_keypair(r, &certificate)?;
            (keypair, Some(certificate))
        }
        Err(_) => {
            let algorithm = Algorithm::new(&type_name)?;
            (KeypairData::decode_as(r, algorithm)?, None)
        }
    };
    let comment = String::decode(r)?;
    let key = PrivateKey::new(keypair, comment)?;
    if let Some(certificate) = &certificate {
        check_certificate_matches(&key, certificate)?;
    }
    Ok((key, certificate))
}

/// The private parts that follow a certificate, combined with the public
/// key from the certificate.
fn decode_certified_keypair(
    r: &mut &[u8],
    certificate: &Certificate,
) -> Result<KeypairData, Error> {
    Ok(match certificate.public_key() {
        KeyData::Rsa(public) => {
            KeypairData::Rsa(RsaKeypair::new(public.clone(), RsaPrivateKey::decode(r)?)?)
        }
        KeyData::Ecdsa(EcdsaPublicKey::NistP256(public)) => {
            KeypairData::Ecdsa(EcdsaKeypair::NistP256 {
                public: *public,
                private: Decode::decode(r)?,
            })
        }
        KeyData::Ecdsa(EcdsaPublicKey::NistP384(public)) => {
            KeypairData::Ecdsa(EcdsaKeypair::NistP384 {
                public: *public,
                private: Decode::decode(r)?,
            })
        }
        KeyData::Ecdsa(EcdsaPublicKey::NistP521(public)) => {
            KeypairData::Ecdsa(EcdsaKeypair::NistP521 {
                public: *public,
                private: Decode::decode(r)?,
            })
        }
        KeyData::Ed25519(_) => KeypairData::Ed25519(Ed25519Keypair::decode(r)?),
        _ => return Err(unsupported(certificate.algorithm())),
    })
}

/// Make sure the private key belongs to the certificate, by signing with
/// it and verifying with the certificate's key. (RSA and ECDSA keypairs
/// built from a certificate aren't checked when constructed.)
fn check_certificate_matches(key: &PrivateKey, certificate: &Certificate) -> Result<(), Error> {
    use signature::{Signer, Verifier};

    const PROBE: &[u8] = b"russh agent certificate key check";
    let signature: ssh_key::Signature = key.try_sign(PROBE)?;
    certificate
        .public_key()
        .verify(PROBE, &signature)
        .map_err(|_| Error::KeyIsCorrupt)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> Vec<PrivateKey> {
        let mut rng = rand::rng();
        let mut keys = vec![
            PrivateKey::random(&mut rng, Algorithm::Ed25519).unwrap(),
            PrivateKey::new(
                KeypairData::Rsa(RsaKeypair::random(&mut rng, 2048).unwrap()),
                "",
            )
            .unwrap(),
        ];
        for curve in [
            ssh_key::EcdsaCurve::NistP256,
            ssh_key::EcdsaCurve::NistP384,
            ssh_key::EcdsaCurve::NistP521,
        ] {
            let keypair = EcdsaKeypair::random(&mut rng, curve).unwrap();
            keys.push(PrivateKey::new(KeypairData::Ecdsa(keypair), "").unwrap());
        }
        for key in &mut keys {
            key.set_comment(format!("comment for {}", key.algorithm()));
        }
        keys
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
        builder.key_id("id").unwrap();
        builder
            .cert_type(ssh_key::certificate::CertType::User)
            .unwrap();
        builder.all_principals_valid().unwrap();
        builder.sign(ca).unwrap()
    }

    fn roundtrip(request: &Request) -> Request {
        Request::decode(&request.encode().unwrap()).unwrap()
    }

    #[test]
    fn add_identity_roundtrips() {
        let ca = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        let constraints = vec![
            Constraint::KeyLifetime { seconds: 60 },
            Constraint::Confirm,
            Constraint::Extensions {
                name: b"sk-provider@openssh.com".to_vec(),
                details: b"/usr/lib/provider.so".to_vec(),
            },
        ];
        for key in keys() {
            for certificate in [None, Some(certificate(&ca, &key))] {
                for constraints in [vec![], constraints.clone()] {
                    let request = Request::AddIdentity(Box::new(AddIdentity {
                        key: key.clone(),
                        certificate: certificate.clone(),
                        constraints: constraints.clone(),
                    }));
                    let Request::AddIdentity(decoded) = roundtrip(&request) else {
                        panic!("not an add-identity request");
                    };
                    assert_eq!(decoded.key, key);
                    assert_eq!(decoded.key.comment(), key.comment());
                    assert_eq!(decoded.certificate, certificate);
                    assert_eq!(decoded.constraints, constraints);
                }
            }
        }
    }

    #[test]
    fn mismatched_certificate_is_rejected() {
        let ca = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        for (key, other) in keys().into_iter().zip(keys()) {
            let mut buf = Vec::new();
            encode_add_identity(&mut buf, &key, Some(&certificate(&ca, &other)), &[]).unwrap();
            assert!(
                Request::decode(&buf).is_err(),
                "{} key accepted with another key's certificate",
                key.algorithm()
            );
        }
    }

    #[test]
    fn other_requests_roundtrip() {
        let requests = [
            Request::RequestIdentities,
            Request::Sign(SignRequest {
                key_blob: vec![1, 2, 3],
                data: vec![4, 5],
                flags: 4,
            }),
            Request::RemoveIdentity {
                key_blob: vec![1, 2, 3],
            },
            Request::RemoveAllIdentities,
            Request::AddSmartcardKey {
                id: "/usr/lib/pkcs11.so".into(),
                pin: Zeroizing::new(b"1234".to_vec()),
                constraints: vec![Constraint::KeyLifetime { seconds: 5 }],
            },
            Request::RemoveSmartcardKey {
                id: "/usr/lib/pkcs11.so".into(),
                pin: Zeroizing::new(Vec::new()),
            },
            Request::Lock {
                passphrase: Zeroizing::new(b"secret".to_vec()),
            },
            Request::Unlock {
                passphrase: Zeroizing::new(b"secret".to_vec()),
            },
            Request::Extension(ExtensionRequest::Query),
            Request::Extension(ExtensionRequest::SessionBind(SessionBind {
                host_key: vec![1],
                session_id: vec![2],
                signature: vec![3],
                forwarding: true,
            })),
            Request::Extension(ExtensionRequest::Other {
                name: "x@example.com".into(),
                contents: vec![9, 9],
            }),
            Request::Unknown { message_type: 200 },
        ];
        for request in &requests {
            let encoded = request.encode().unwrap();
            let decoded = Request::decode(&encoded).unwrap();
            assert_eq!(decoded.encode().unwrap(), encoded, "{request:?}");
        }
    }

    #[test]
    fn responses_roundtrip() {
        let responses = [
            Response::Success,
            Response::Failure,
            Response::Identities(vec![]),
            Response::Identities(vec![
                Identity {
                    key_blob: vec![1, 2],
                    comment: "one".into(),
                },
                Identity {
                    key_blob: vec![3],
                    comment: String::new(),
                },
            ]),
            Response::Signature(vec![7, 7, 7]),
            Response::query_response(&["query", "session-bind@openssh.com"]).unwrap(),
            Response::ExtensionFailure,
        ];
        for response in responses {
            let decoded = Response::decode(&response.encode().unwrap()).unwrap();
            assert_eq!(decoded, response);
        }
    }

    #[test]
    fn malformed_requests_are_errors() {
        let cases: &[&[u8]] = &[
            &[],
            // Sign request missing its flags.
            &[msg::SIGN_REQUEST, 0, 0, 0, 1, 9, 0, 0, 0, 0],
            // Trailing garbage after a request without contents.
            &[msg::REQUEST_IDENTITIES, 0],
            // Trailing data after a lock passphrase.
            &[msg::LOCK, 0, 0, 0, 0, 7],
        ];
        for payload in cases {
            assert!(Request::decode(payload).is_err(), "{payload:?}");
        }
    }

    #[test]
    fn unknown_constraint_extension_is_an_error() {
        let key = &keys()[0];
        let mut buf = Vec::new();
        encode_add_identity(
            &mut buf,
            key,
            None,
            &[Constraint::Extensions {
                name: b"unknown@example.com".to_vec(),
                details: vec![],
            }],
        )
        .unwrap();
        assert!(Request::decode(&buf).is_err());
    }
}
