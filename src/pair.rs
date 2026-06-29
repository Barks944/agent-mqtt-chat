//! TOFU + Short-Authentication-String (SAS) pairing (REQ: bootstrap/pairing
//! mode). Two agents establish mutual trust over the broker channel without
//! hand-copying tokens: each broadcasts a self-signed [`crate::wire::CTYPE_PAIR`]
//! "hello" that proves possession of the advertised key, and the operators
//! compare a human-readable [`sas`] code to rule out a man-in-the-middle before
//! confirming the peer into the trust store.
//!
//! The hello is self-signed (signed by the very key it advertises), so it does
//! NOT require the sender to already be trusted; trust is conferred only by the
//! out-of-band SAS comparison + `pair confirm`.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The JSON body of a pairing hello (carried in [`crate::wire::Inner::body`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairBody {
    /// Advertised sender name.
    pub name: String,
    /// base64url ML-DSA-65 public key.
    pub pk: String,
    /// base64url ML-KEM-768 encapsulation key, or null.
    #[serde(default)]
    pub kem_pk: Option<String>,
}

/// A verified pairing hello (proof-of-possession already checked).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairHello {
    pub name: String,
    pub public_key: Vec<u8>,
    pub kem_public_key: Option<Vec<u8>>,
}

/// Compute the Short Authentication String for a pair of public keys.
///
/// SHA-256 is taken over the two keys concatenated in SORTED byte order, so both
/// peers derive the identical value regardless of who initiated. The first three
/// digest bytes are reduced to a 6-digit decimal code rendered as `"NNN NNN"`.
/// Symmetric (`sas(a, b) == sas(b, a)`) and deterministic.
pub fn sas(pk_a: &[u8], pk_b: &[u8]) -> String {
    let (first, second) = if pk_a <= pk_b {
        (pk_a, pk_b)
    } else {
        (pk_b, pk_a)
    };
    let mut hasher = Sha256::new();
    hasher.update(first);
    hasher.update(second);
    let digest = hasher.finalize();
    let n = ((digest[0] as u32) << 16) | ((digest[1] as u32) << 8) | (digest[2] as u32);
    let code = n % 1_000_000;
    format!("{:03} {:03}", code / 1000, code % 1000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sas_is_symmetric() {
        let a = b"alice-public-key-bytes";
        let b = b"bob-public-key-bytes";
        assert_eq!(sas(a, b), sas(b, a));
    }

    #[test]
    fn sas_differs_for_different_keys() {
        let a = b"alice-public-key-bytes";
        let b = b"bob-public-key-bytes";
        let c = b"carol-public-key-bytes";
        assert_ne!(sas(a, b), sas(a, c));
    }

    #[test]
    fn sas_is_six_digits_grouped() {
        let s = sas(b"x", b"y");
        // Format "NNN NNN": 7 chars, a single space in the middle, all digits.
        assert_eq!(s.len(), 7);
        assert_eq!(&s[3..4], " ");
        assert!(s.chars().filter(|c| c.is_ascii_digit()).count() == 6);
    }
}
