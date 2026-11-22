use ssh_key::{Certificate, HashAlg, PublicKey};
#[cfg(not(target_arch = "wasm32"))]
use {
    crate::helpers::AlgorithmExt, ssh_encoding::Decode, ssh_key::Algorithm,
    ssh_key::public::KeyData,
};

use crate::keys::key::PrivateKeyWithHashAlg;

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum PublicKeyOrCertificate {
    PublicKey {
        key: PublicKey,
        hash_alg: Option<HashAlg>,
    },
    Certificate(Certificate),
}

impl From<&PrivateKeyWithHashAlg> for PublicKeyOrCertificate {
    fn from(key: &PrivateKeyWithHashAlg) -> Self {
        PublicKeyOrCertificate::PublicKey {
            key: key.public_key().clone(),
            hash_alg: key.hash_alg(),
        }
    }
}

impl From<Certificate> for PublicKeyOrCertificate {
    fn from(cert: Certificate) -> Self {
        PublicKeyOrCertificate::Certificate(cert)
    }
}

impl From<PublicKey> for PublicKeyOrCertificate {
    fn from(key: PublicKey) -> Self {
        PublicKeyOrCertificate::PublicKey {
            key,
            hash_alg: None,
        }
    }
}

impl PublicKeyOrCertificate {
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn decode(pubkey_algo: &str, buf: &[u8]) -> Result<Self, ssh_key::Error> {
        crate::keys::key::check_cert_nesting(buf)?;
        let mut reader = buf;
        match Algorithm::new_certificate_ext(pubkey_algo) {
            Ok(Algorithm::Other(_)) | Err(ssh_key::Error::Encoding(_)) => {
                // Did not match a known cert algorithm
                Ok(PublicKeyOrCertificate::PublicKey {
                    key: KeyData::decode(&mut reader)?.into(),
                    hash_alg: Algorithm::new(pubkey_algo)?.hash_alg(),
                })
            }
            _ => Ok(PublicKeyOrCertificate::Certificate(Certificate::decode(
                &mut reader,
            )?)),
        }
    }

    pub fn public_key(&self) -> PublicKey {
        match self {
            PublicKeyOrCertificate::PublicKey { key, .. } => key.clone(),
            PublicKeyOrCertificate::Certificate(cert) => {
                PublicKey::new(cert.public_key().clone(), "")
            }
        }
    }

    /// Whether both are the same host key: the same key (whatever signature
    /// hash an RSA key was negotiated with), or the same certificate.
    pub(crate) fn same_host_key(&self, other: &PublicKeyOrCertificate) -> bool {
        match (self, other) {
            (
                PublicKeyOrCertificate::PublicKey { key: a, .. },
                PublicKeyOrCertificate::PublicKey { key: b, .. },
            ) => a.key_data() == b.key_data(),
            (PublicKeyOrCertificate::Certificate(a), PublicKeyOrCertificate::Certificate(b)) => {
                matches!((a.to_bytes(), b.to_bytes()), (Ok(a), Ok(b)) if a == b)
            }
            _ => false,
        }
    }

    pub fn certificate(&self) -> Option<&Certificate> {
        match self {
            PublicKeyOrCertificate::PublicKey { .. } => None,
            PublicKeyOrCertificate::Certificate(cert) => Some(cert),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use ssh_key::{HashAlg, PrivateKey};

    use super::*;

    fn key() -> PublicKey {
        PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519)
            .unwrap()
            .public_key()
            .clone()
    }

    #[test]
    fn same_host_key() {
        let a = key();
        let b = key();
        let plain = |key: &PublicKey, hash_alg| PublicKeyOrCertificate::PublicKey {
            key: key.clone(),
            hash_alg,
        };
        assert!(plain(&a, None).same_host_key(&plain(&a, None)));
        // The negotiated signature hash doesn't make it another key.
        assert!(plain(&a, None).same_host_key(&plain(&a, Some(HashAlg::Sha512))));
        assert!(!plain(&a, None).same_host_key(&plain(&b, None)));
    }
}
