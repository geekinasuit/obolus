//! EIP-3009 `transferWithAuthorization` struct hashing and signature verification.

use crate::eip712::{digest, encode_address, encode_u256, Eip712Domain};
use crate::{keccak256, recover_address, Eip3009Error};

/// Canonical EIP-3009 type signatures. The typehash is the keccak256 of these exact strings —
/// whitespace and field order are part of the hash, so these are transcribed verbatim from the
/// spec rather than reformatted to fit a line width.
pub const TRANSFER_WITH_AUTHORIZATION_TYPE: &str = "TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)";

pub const RECEIVE_WITH_AUTHORIZATION_TYPE: &str = "ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)";

pub const CANCEL_AUTHORIZATION_TYPE: &str =
    "CancelAuthorization(address authorizer,bytes32 nonce)";

/// A signed transfer authorization — the `authorization` object of an x402 `exact`-scheme payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authorization {
    pub from: [u8; 20],
    pub to: [u8; 20],
    /// The transfer amount in atomic units.
    ///
    /// Declared `uint256` on-chain but held here as a `u128`, which covers every amount any real
    /// token supply can express. The constraint that buys is on whoever parses the wire format: an
    /// x402 payload carries this as a **decimal string**, and a parser that narrows an out-of-range
    /// string with `as u128` rather than rejecting it would wrap the value — producing a signature
    /// that verifies correctly over an amount nobody authorized. Parse fallibly and reject; do not
    /// truncate.
    pub value: u128,
    pub valid_after: u64,
    pub valid_before: u64,
    pub nonce: [u8; 32],
}

impl Authorization {
    /// `keccak256(typehash || encodeData)` for `TransferWithAuthorization`.
    pub fn transfer_struct_hash(&self) -> [u8; 32] {
        let mut buf = Vec::with_capacity(224);
        buf.extend_from_slice(&keccak256(TRANSFER_WITH_AUTHORIZATION_TYPE.as_bytes()));
        buf.extend_from_slice(&encode_address(&self.from));
        buf.extend_from_slice(&encode_address(&self.to));
        buf.extend_from_slice(&encode_u256(self.value));
        buf.extend_from_slice(&encode_u256(self.valid_after as u128));
        buf.extend_from_slice(&encode_u256(self.valid_before as u128));
        // `nonce` is a bytes32, already a full word — encoded as-is, not hashed. Hashing it here
        // would be the same class of error as hashing an address: it produces a valid-looking
        // digest that no signer ever signed.
        buf.extend_from_slice(&self.nonce);
        keccak256(&buf)
    }

    /// The digest a wallet signs to authorize this transfer under `domain`.
    pub fn transfer_digest(&self, domain: &Eip712Domain) -> [u8; 32] {
        digest(&domain.separator(), &self.transfer_struct_hash())
    }

    /// Whether `signature` over this authorization recovers to the authorizing party (`from`).
    ///
    /// EIP-3009 requires the recovered signer to be `from` specifically — a signature that is
    /// cryptographically valid but recovers to anyone else authorizes nothing.
    pub fn verify_transfer(
        &self,
        domain: &Eip712Domain,
        signature: &[u8],
    ) -> Result<bool, Eip3009Error> {
        let recovered = recover_address(&self.transfer_digest(domain), signature)?;
        Ok(recovered == self.from)
    }
}
