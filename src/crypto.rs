//! Post-quantum signature verification (FIPS 204 ML-DSA-65).
//!
//! REQ-0005/0026: ML-DSA-65 signatures. Signing lives in [`crate::identity`]
//! (it needs the private key); verification is stateless over public bytes.

use ml_dsa::{EncodedSignature, EncodedVerifyingKey, MlDsa65, Signature, Verifier, VerifyingKey};

/// Encoded public (verifying) key length for ML-DSA-65.
pub const PUBLIC_KEY_LEN: usize = 1952;
/// Encoded signature length for ML-DSA-65.
pub const SIGNATURE_LEN: usize = 3309;

/// Verify `sig` over `msg` using the encoded `public_key`. Returns false for
/// any malformed input or signature mismatch (REQ-0056: invalid signatures are
/// rejected, never trusted).
pub fn verify(public_key: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let Ok(vk_enc) = EncodedVerifyingKey::<MlDsa65>::try_from(public_key) else {
        return false;
    };
    let vk = VerifyingKey::<MlDsa65>::decode(&vk_enc);

    let Ok(sig_enc) = EncodedSignature::<MlDsa65>::try_from(sig) else {
        return false;
    };
    let Some(signature) = Signature::<MlDsa65>::decode(&sig_enc) else {
        return false;
    };

    vk.verify(msg, &signature).is_ok()
}
