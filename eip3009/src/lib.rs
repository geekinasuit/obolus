//! EIP-3009 `transferWithAuthorization` verification: EIP-712 digest construction and secp256k1
//! signer recovery.
//!
//! This crate holds no key material and signs nothing. It answers one question — *does this
//! signature, over this authorization, recover to this address?* — which is the question an x402
//! facilitator answers on the `/verify` path.
//!
//! It is deliberately **not** a dependency of the `obolus` binary. That gateway delegates
//! verification to a facilitator and never inspects a signature itself, so pulling secp256k1 into its
//! graph would widen the shipped artifact's attack surface for something it does not do.
//!
//! The rule is scoped to that binary, not to this crate's consumers in general — it is about what the
//! gateway's graph contains, not about who may verify. A binary whose job *is* to inspect signatures
//! links this crate by design: a development seller that checks payments offline, so an x402 client
//! can be tested against a counterparty that fails on command, is the intended second consumer.

use sha3::{Digest, Keccak256};

pub mod eip3009;
pub mod eip712;

#[cfg(test)]
mod kat;

pub use eip3009::Authorization;
pub use eip712::Eip712Domain;

/// Ethereum's keccak256 — the original Keccak padding, not NIST SHA-3.
///
/// Named separately from `sha3::Keccak256` because the distinction is the single most common way
/// to get an EIP-712 digest silently wrong: `sha3::Sha3_256` and `sha3::Keccak256` have identical
/// signatures and different outputs, so a mix-up compiles, runs, and produces a digest that
/// recovers to a plausible-looking wrong address.
pub fn keccak256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

/// Recovers the signing address from a 65-byte `r || s || v` signature over `digest`.
///
/// `v` is accepted in both the 27/28 and 0/1 conventions. Both are in circulation — the JSON-RPC
/// family emits 27/28, raw `ecdsa` recovery ids are 0/1 — and normalising costs one match arm,
/// where guessing wrong costs a rejected-but-valid payment. No claim is made here about which
/// convention any particular producer emits; that would need a survey nobody has run.
pub fn recover_address(digest: &[u8; 32], signature: &[u8]) -> Result<[u8; 20], Eip3009Error> {
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

    if signature.len() != 65 {
        return Err(Eip3009Error::SignatureLength(signature.len()));
    }

    let v = match signature[64] {
        0 | 1 => signature[64],
        27 | 28 => signature[64] - 27,
        other => return Err(Eip3009Error::RecoveryId(other)),
    };

    let sig = Signature::from_slice(&signature[..64]).map_err(|_| Eip3009Error::Malformed)?;
    let recid = RecoveryId::from_byte(v).ok_or(Eip3009Error::RecoveryId(v))?;
    let key = VerifyingKey::recover_from_prehash(digest, &sig, recid)
        .map_err(|_| Eip3009Error::Unrecoverable)?;

    // An Ethereum address is the low 20 bytes of the keccak256 of the 64-byte uncompressed public
    // key with its 0x04 SEC1 tag removed.
    let point = key.to_encoded_point(false);
    let hash = keccak256(&point.as_bytes()[1..]);
    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[12..]);
    Ok(address)
}

/// Decodes a hex string, with or without a `0x` prefix.
///
/// x402 payloads carry every byte string as prefixed hex, so callers parsing one need this before
/// they can call anything else here.
pub fn decode_hex(value: &str) -> Result<Vec<u8>, Eip3009Error> {
    let trimmed = value.strip_prefix("0x").unwrap_or(value);
    hex::decode(trimmed).map_err(|_| Eip3009Error::Hex(value.to_string()))
}

/// Decodes a hex string into a fixed-size array, failing if the length does not match exactly.
pub fn decode_hex_array<const N: usize>(value: &str) -> Result<[u8; N], Eip3009Error> {
    let bytes = decode_hex(value)?;
    bytes
        .try_into()
        .map_err(|_| Eip3009Error::Hex(value.to_string()))
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Eip3009Error {
    #[error("signature must be 65 bytes (r || s || v), got {0}")]
    SignatureLength(usize),
    #[error("recovery id {0} is not one of 0, 1, 27, 28")]
    RecoveryId(u8),
    #[error("signature is not a well-formed secp256k1 (r, s) pair")]
    Malformed,
    #[error("no public key recovers from this signature and digest")]
    Unrecoverable,
    #[error("not valid hex of the expected length: {0}")]
    Hex(String),
}
