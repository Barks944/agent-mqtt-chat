//! Post-quantum payload encryption: ML-KEM-768 (FIPS 203) key encapsulation
//! plus AES-256-GCM authenticated encryption (REQ: ML-KEM payload encryption).
//!
//! The sender encapsulates a fresh 32-byte shared secret to the recipient's
//! ML-KEM-768 encapsulation key, then uses that secret as the AES-256-GCM key
//! to seal the plaintext body. The recipient decapsulates with its private
//! decapsulation key and opens the ciphertext. The inner routing fields are
//! bound in as AEAD associated data so a ciphertext cannot be replayed against
//! a different envelope.
//!
//! Key derivation note: the ML-KEM-768 keypair is derived **deterministically
//! from the agent's 32-byte signing seed** (see [`derive_from_seed`]), exactly
//! like the ML-DSA signing key. This keeps the advertised KEM public key stable
//! across every load and process, and gives migrated v0.1 identities (which
//! persist only the signing seed) a stable KEM key with no new on-disk storage.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{Ciphertext, Encoded, EncodedSizeUser, KemCore, MlKem768, B32};
use sha2::{Digest, Sha256};

use crate::wire::fingerprint;

/// Decapsulation key type for ML-KEM-768.
type Dk = <MlKem768 as KemCore>::DecapsulationKey;
/// Encapsulation key type for ML-KEM-768.
type Ek = <MlKem768 as KemCore>::EncapsulationKey;

/// Encoded ML-KEM-768 encapsulation-key (public) length in bytes.
pub const KEM_PK_LEN: usize = 1184;

/// A getrandom-backed CSPRNG implementing the `rand_core` 0.6 traits that
/// `ml-kem` requires for key generation and encapsulation.
struct OsRng;

impl rand_core::RngCore for OsRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }

    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        getrandom::getrandom(dest).expect("OS RNG must be available");
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl rand_core::CryptoRng for OsRng {}

/// Deterministically derive the ML-KEM-768 keypair from a 32-byte identity
/// `seed`, returning `(encoded decapsulation key, encoded encapsulation key)`.
///
/// The two 32-byte inputs ML-KEM keygen requires (`d`, `z`) are taken from
/// domain-separated SHA-256 of the seed, so the keypair is a pure function of
/// the seed: every load and every process derives the **same** KEM key (and the
/// public half advertised in the token always matches the private half the
/// daemon decrypts with). The decapsulation key is PRIVATE; the encapsulation
/// key is shared publicly.
pub fn derive_from_seed(seed: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let d = B32::from(kdf(b"agentmsg-kem-d-v1", seed));
    let z = B32::from(kdf(b"agentmsg-kem-z-v1", seed));
    let (dk, ek) = MlKem768::generate_deterministic(&d, &z);
    (dk.as_bytes().to_vec(), ek.as_bytes().to_vec())
}

/// Reconstruct the encoded encapsulation (public) key from an encoded
/// decapsulation key (used to verify a derived keypair is self-consistent).
pub fn ek_from_dk(dk: &[u8]) -> Vec<u8> {
    match Encoded::<Dk>::try_from(dk) {
        Ok(enc) => Dk::from_bytes(&enc).encapsulation_key().as_bytes().to_vec(),
        Err(_) => Vec::new(),
    }
}

/// Domain-separated SHA-256 of `seed` into a 32-byte value.
fn kdf(domain: &[u8], seed: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(domain);
    h.update(seed);
    h.finalize().into()
}

/// Short fingerprint of an encapsulation key (reuses the wrapper fingerprint so
/// `recipient_kid` matches the agent's KEM identity everywhere).
pub fn kem_fingerprint(ek: &[u8]) -> String {
    fingerprint(ek)
}

/// Encapsulate a fresh shared secret to the recipient's encapsulation key.
/// Returns `(kem_ciphertext, shared_secret)` or `None` if `ek` is malformed.
pub fn encapsulate(ek: &[u8]) -> Option<(Vec<u8>, [u8; 32])> {
    let enc = Encoded::<Ek>::try_from(ek).ok()?;
    let ek = Ek::from_bytes(&enc);
    let mut rng = OsRng;
    let (ct, ss) = ek.encapsulate(&mut rng).ok()?;
    let ss_arr: [u8; 32] = ss.as_slice().try_into().ok()?;
    Some((ct.as_slice().to_vec(), ss_arr))
}

/// Decapsulate the shared secret from `kem_ct` using the encoded decapsulation
/// key `dk`. Returns `None` on malformed input.
pub fn decapsulate(dk: &[u8], kem_ct: &[u8]) -> Option<[u8; 32]> {
    let enc = Encoded::<Dk>::try_from(dk).ok()?;
    let dk = Dk::from_bytes(&enc);
    let ct = Ciphertext::<MlKem768>::try_from(kem_ct).ok()?;
    let ss = dk.decapsulate(&ct).ok()?;
    let ss_arr: [u8; 32] = ss.as_slice().try_into().ok()?;
    Some(ss_arr)
}

/// AES-256-GCM seal: encrypt `pt` under `key`/`nonce` binding `aad`, returning
/// the ciphertext (with the 16-byte authentication tag appended).
pub fn seal(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], pt: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(nonce);
    cipher
        .encrypt(nonce, Payload { msg: pt, aad })
        .expect("AES-256-GCM seal is infallible for valid key/nonce")
}

/// AES-256-GCM open: decrypt+verify `ct` under `key`/`nonce`/`aad`. Returns
/// `None` if authentication fails (REQ: decrypt failures are rejected).
pub fn open(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], ct: &[u8]) -> Option<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(nonce);
    cipher.decrypt(nonce, Payload { msg: ct, aad }).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kem_roundtrip() {
        let seed = [3u8; 32];
        let (dk, ek) = derive_from_seed(&seed);
        assert_eq!(ek.len(), KEM_PK_LEN);
        assert_eq!(ek_from_dk(&dk), ek);
        let (ct, ss_send) = encapsulate(&ek).unwrap();
        let ss_recv = decapsulate(&dk, &ct).unwrap();
        assert_eq!(ss_send, ss_recv);
    }

    #[test]
    fn derivation_is_deterministic() {
        // The whole fix: the same seed must always yield the same KEM keypair,
        // and different seeds must differ.
        let (dk1, ek1) = derive_from_seed(&[9u8; 32]);
        let (dk2, ek2) = derive_from_seed(&[9u8; 32]);
        assert_eq!(dk1, dk2);
        assert_eq!(ek1, ek2);
        let (_dk3, ek3) = derive_from_seed(&[10u8; 32]);
        assert_ne!(ek1, ek3);
    }

    #[test]
    fn aead_roundtrip() {
        let key = [7u8; 32];
        let nonce = [9u8; 12];
        let aad = b"id|from|to|ts";
        let ct = seal(&key, &nonce, aad, b"secret");
        assert_eq!(
            open(&key, &nonce, aad, &ct).as_deref(),
            Some(&b"secret"[..])
        );
        // Wrong AAD fails authentication.
        assert!(open(&key, &nonce, b"other", &ct).is_none());
    }
}
