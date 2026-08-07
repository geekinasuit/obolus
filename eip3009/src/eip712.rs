//! EIP-712 encoding primitives — only the pieces EIP-3009 actually needs.
//!
//! Deliberately absent: a general typed-data encoder. `encodeType`'s recursive rule for
//! referenced struct types (sorting referenced types alphabetically and appending them to the
//! primary type's signature) is real machinery, and EIP-3009 never exercises it — every field of
//! every EIP-3009 struct is an atomic type. Carrying a general encoder here to satisfy one test
//! vector would put untested code paths in the library to make a test pass.

use crate::keccak256;

/// The four-field `EIP712Domain` as EIP-3009 uses it. All fields are present; the spec permits
/// omitting them, but the EIP-3009 contracts do not, and a domain with a different field set
/// hashes to a different separator, so modelling the optional cases would be modelling something
/// this crate cannot encounter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Eip712Domain {
    pub name: String,
    pub version: String,
    pub chain_id: u64,
    pub verifying_contract: [u8; 20],
}

/// The canonical `EIP712Domain` type signature, hashed to produce the domain typehash.
pub const EIP712_DOMAIN_TYPE: &str =
    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";

/// Left-pads a 20-byte address into an ABI 32-byte word.
pub fn encode_address(address: &[u8; 20]) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(address);
    word
}

/// Big-endian ABI encoding of a `uint256` whose value fits in a `u128`.
///
/// Every `uint256` this crate encodes is a token amount or a Unix timestamp. A `u128` covers both
/// with room to spare, and taking `u128` rather than a byte array keeps callers from having to
/// hand-pad. A true 256-bit value would need a wider type; none appears in EIP-3009.
pub fn encode_u256(value: u128) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[16..].copy_from_slice(&value.to_be_bytes());
    word
}

/// EIP-712 encodes a dynamic `string` as the keccak256 of its UTF-8 bytes.
pub fn encode_string(value: &str) -> [u8; 32] {
    keccak256(value.as_bytes())
}

impl Eip712Domain {
    /// `keccak256(encodeType || encodeData)` for the domain struct — the `domainSeparator`.
    pub fn separator(&self) -> [u8; 32] {
        let mut buf = Vec::with_capacity(160);
        buf.extend_from_slice(&keccak256(EIP712_DOMAIN_TYPE.as_bytes()));
        buf.extend_from_slice(&encode_string(&self.name));
        buf.extend_from_slice(&encode_string(&self.version));
        buf.extend_from_slice(&encode_u256(self.chain_id as u128));
        buf.extend_from_slice(&encode_address(&self.verifying_contract));
        keccak256(&buf)
    }
}

/// Composes the final signing digest: `keccak256(0x19 || 0x01 || domainSeparator || structHash)`.
///
/// The `0x19` prefix is EIP-191's "this is not an RLP-encoded transaction" marker and `0x01` is
/// EIP-712's version byte. Omitting them yields a digest that still recovers to *some* address,
/// which is why this composition is worth its own named function rather than being inlined at
/// each call site.
pub fn digest(domain_separator: &[u8; 32], struct_hash: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 66];
    buf[0] = 0x19;
    buf[1] = 0x01;
    buf[2..34].copy_from_slice(domain_separator);
    buf[34..].copy_from_slice(struct_hash);
    keccak256(&buf)
}
