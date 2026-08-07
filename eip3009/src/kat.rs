//! Known-answer tests against third-party published vectors.
//!
//! Every expected value here comes from a specification this project does not control, and each
//! fixture records which document and which retrieval date it came from. That matters more than
//! usual for this crate: the thing being tested is a verifier, and a verifier checked only against
//! outputs produced by its own author will accept that author's bugs as readily as their correct
//! answers.

use serde_json::Value;

use crate::eip712::{encode_address, encode_string, Eip712Domain};
use crate::{decode_hex, decode_hex_array, eip712, keccak256, recover_address};

const TYPEHASHES: &str = include_str!("../fixtures/typehashes.json");
const EIP712_MAIL: &str = include_str!("../fixtures/eip712-mail.json");
const X402_AUTHORIZATION: &str = include_str!("../fixtures/x402-authorization.json");

fn fixture(raw: &str) -> Value {
    serde_json::from_str(raw).expect("fixture is valid JSON")
}

/// Every published typehash must equal the keccak256 of its published type string.
///
/// Four constants from two documents, each sensitive to a single byte of whitespace or a single
/// transposed field, all agreeing at once.
#[test]
fn typehashes_match_published_constants() {
    let doc = fixture(TYPEHASHES);
    let vectors = doc["vectors"].as_array().expect("vectors is an array");

    // A fixture that silently parsed to zero vectors would let this test pass having checked
    // nothing — the same vacuous-pass shape as a glob that matches no files.
    assert_eq!(vectors.len(), 4, "expected 4 published typehash vectors");

    for vector in vectors {
        let name = vector["name"].as_str().expect("name");
        let type_string = vector["type_string"].as_str().expect("type_string");
        let expected: [u8; 32] =
            decode_hex_array(vector["typehash"].as_str().expect("typehash")).expect("typehash hex");

        assert_eq!(
            keccak256(type_string.as_bytes()),
            expected,
            "{name} typehash does not match the published constant"
        );
    }
}

/// The type strings the library hardcodes must be the ones the fixtures pin.
///
/// Without this, the test above would verify only that the *fixture's* strings hash correctly,
/// leaving the library free to carry a typo that no test ever reaches.
#[test]
fn library_type_strings_match_fixtures() {
    let doc = fixture(TYPEHASHES);
    let vectors = doc["vectors"].as_array().expect("vectors is an array");

    let published = |name: &str| -> String {
        vectors
            .iter()
            .find(|v| v["name"].as_str() == Some(name))
            .unwrap_or_else(|| panic!("fixture has no vector named {name}"))["type_string"]
            .as_str()
            .expect("type_string")
            .to_string()
    };

    assert_eq!(eip712::EIP712_DOMAIN_TYPE, published("EIP712Domain"));
    assert_eq!(
        crate::eip3009::TRANSFER_WITH_AUTHORIZATION_TYPE,
        published("TransferWithAuthorization")
    );
    assert_eq!(
        crate::eip3009::RECEIVE_WITH_AUTHORIZATION_TYPE,
        published("ReceiveWithAuthorization")
    );
    assert_eq!(
        crate::eip3009::CANCEL_AUTHORIZATION_TYPE,
        published("CancelAuthorization")
    );
}

/// NIST SHA3-256 must *not* reproduce the published typehashes.
///
/// `sha3::Sha3_256` and `sha3::Keccak256` differ only in padding, have identical Rust signatures,
/// and are trivially swapped for one another. This asserts the negative directly, so the
/// distinction is pinned by a test rather than by a comment asking the reader to be careful.
#[test]
fn sha3_256_does_not_reproduce_keccak_typehashes() {
    use sha3::{Digest, Sha3_256};

    let doc = fixture(TYPEHASHES);
    for vector in doc["vectors"].as_array().expect("vectors is an array") {
        let type_string = vector["type_string"].as_str().expect("type_string");
        let expected: [u8; 32] =
            decode_hex_array(vector["typehash"].as_str().expect("typehash")).expect("typehash hex");

        let sha3: [u8; 32] = Sha3_256::digest(type_string.as_bytes()).into();
        assert_ne!(
            sha3, expected,
            "SHA3-256 reproduced a keccak256 typehash, which means this test cannot detect the swap"
        );
    }
}

/// Hashes an EIP-712 `Person` — test-local, because the library carries no general encoder.
fn person_hash(encode_type: &str, name: &str, wallet: &[u8; 20]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(96);
    buf.extend_from_slice(&keccak256(encode_type.as_bytes()));
    buf.extend_from_slice(&encode_string(name));
    buf.extend_from_slice(&encode_address(wallet));
    keccak256(&buf)
}

/// The EIP-712 worked example must recover to the signer the spec publishes.
///
/// The spec gives the domain, the types, the message, the signature, and the expected signer, but
/// no intermediate hashes and no final digest — so passing this requires computing the entire
/// chain. There is no published digest to accidentally transcribe.
#[test]
fn eip712_mail_recovers_published_signer() {
    let doc = fixture(EIP712_MAIL);

    let domain = mail_domain(&doc);
    let digest = eip712::digest(&domain.separator(), &mail_struct_hash(&doc));
    let signature = decode_hex(doc["signature"].as_str().expect("signature")).expect("sig hex");
    let expected: [u8; 20] =
        decode_hex_array(doc["expected_signer"].as_str().expect("expected_signer"))
            .expect("signer hex");

    assert_eq!(
        recover_address(&digest, &signature).expect("recovery succeeds"),
        expected,
        "recovered signer does not match the address published in EIP-712"
    );
}

/// A perturbed domain must not recover the published signer.
///
/// The positive test above would still pass if `domain_separator` ignored one of its fields and
/// happened to be compared against a digest built the same wrong way. This forces the domain to
/// actually participate: change one character of the domain name, and the recovered address must
/// change.
#[test]
fn eip712_mail_wrong_domain_does_not_recover_signer() {
    let doc = fixture(EIP712_MAIL);

    let mut domain = mail_domain(&doc);
    domain.name.push('!');

    let digest = eip712::digest(&domain.separator(), &mail_struct_hash(&doc));
    let signature = decode_hex(doc["signature"].as_str().expect("signature")).expect("sig hex");
    let expected: [u8; 20] =
        decode_hex_array(doc["expected_signer"].as_str().expect("expected_signer"))
            .expect("signer hex");

    // Recovery over a different digest still yields *some* address — that is what makes a wrong
    // digest dangerous rather than merely broken. It must not yield the right one.
    let recovered = recover_address(&digest, &signature).expect("recovery still succeeds");
    assert_ne!(
        recovered, expected,
        "the domain is not participating in the digest"
    );
}

fn mail_domain(doc: &Value) -> Eip712Domain {
    let d = &doc["domain"];
    Eip712Domain {
        name: d["name"].as_str().expect("name").to_string(),
        version: d["version"].as_str().expect("version").to_string(),
        chain_id: d["chain_id"].as_u64().expect("chain_id"),
        verifying_contract: decode_hex_array(
            d["verifying_contract"].as_str().expect("verifying_contract"),
        )
        .expect("contract hex"),
    }
}

fn mail_struct_hash(doc: &Value) -> [u8; 32] {
    let person_type = doc["encode_type"]["Person"].as_str().expect("Person type");
    let mail_type = doc["encode_type"]["Mail"].as_str().expect("Mail type");
    let message = &doc["message"];

    let party = |key: &str| -> [u8; 32] {
        let p = &message[key];
        person_hash(
            person_type,
            p["name"].as_str().expect("party name"),
            &decode_hex_array(p["wallet"].as_str().expect("wallet")).expect("wallet hex"),
        )
    };

    let mut buf = Vec::with_capacity(128);
    buf.extend_from_slice(&keccak256(mail_type.as_bytes()));
    buf.extend_from_slice(&party("from"));
    buf.extend_from_slice(&party("to"));
    buf.extend_from_slice(&encode_string(
        message["contents"].as_str().expect("contents"),
    ));
    keccak256(&buf)
}

/// Splits an EIP-712 type string into its declared `(type, name)` field list, in order.
fn declared_fields(type_string: &str) -> Vec<(&str, &str)> {
    let open = type_string.find('(').expect("type string has an opening paren");
    let close = type_string.rfind(')').expect("type string has a closing paren");
    type_string[open + 1..close]
        .split(',')
        .map(|field| {
            let mut parts = field.trim().split_whitespace();
            let ty = parts.next().expect("field type");
            let name = parts.next().expect("field name");
            (ty, name)
        })
        .collect()
}

/// `transfer_struct_hash` must encode its fields in the order and with the types the EIP-3009 type
/// string declares.
///
/// No published constant exists to check this hash against — that is exactly what OBOL-019 is
/// about — so this deliberately does not pin a hash the author computed. Instead it rebuilds
/// `encodeData` straight from the *published* type string, whose own bytes are pinned by
/// [`typehashes_match_published_constants`], and requires the implementation to agree with it.
///
/// This is the test that catches a transposed field pair. Permuting the struct's values cannot: if
/// the implementation swaps `from` and `to` internally, a test that swaps them in the input sees
/// both sides move together and stays green.
#[test]
fn transfer_struct_hash_follows_the_declared_field_order() {
    let doc = fixture(X402_AUTHORIZATION);
    let auth = x402_authorization(&doc);

    let fields = declared_fields(crate::eip3009::TRANSFER_WITH_AUTHORIZATION_TYPE);
    assert_eq!(fields.len(), 6, "EIP-3009 declares six authorization fields");

    let mut expected = Vec::with_capacity(224);
    expected.extend_from_slice(&keccak256(
        crate::eip3009::TRANSFER_WITH_AUTHORIZATION_TYPE.as_bytes(),
    ));
    for (declared_type, name) in fields {
        // Asserting the declared type alongside the value encodes the second half of the rule: a
        // `bytes32` goes in as a whole word, where hashing it — the natural reflex after seeing
        // `string` handled that way — would produce a digest no wallet ever signed.
        let (expected_type, word) = match name {
            "from" => ("address", encode_address(&auth.from)),
            "to" => ("address", encode_address(&auth.to)),
            "value" => ("uint256", crate::eip712::encode_u256(auth.value)),
            "validAfter" => ("uint256", crate::eip712::encode_u256(auth.valid_after as u128)),
            "validBefore" => (
                "uint256",
                crate::eip712::encode_u256(auth.valid_before as u128),
            ),
            "nonce" => ("bytes32", auth.nonce),
            other => panic!("type string declares an unexpected field: {other}"),
        };
        assert_eq!(
            declared_type, expected_type,
            "field {name} is declared {declared_type} but encoded as {expected_type}"
        );
        expected.extend_from_slice(&word);
    }

    assert_eq!(
        auth.transfer_struct_hash(),
        keccak256(&expected),
        "struct hash does not match the field order the EIP-3009 type string declares"
    );
}

/// Every authorization field must affect the struct hash.
///
/// A field dropped from the buffer entirely would survive the order check above only if the check
/// were also wrong, but it costs little to assert participation directly — and this is what catches
/// a field silently encoded as a constant.
#[test]
fn every_authorization_field_changes_the_struct_hash() {
    let doc = fixture(X402_AUTHORIZATION);
    let base = x402_authorization(&doc);
    let baseline = base.transfer_struct_hash();

    let mut mutations: Vec<(&str, crate::Authorization)> = Vec::new();

    let mut m = base.clone();
    m.from[0] ^= 0xff;
    mutations.push(("from", m));

    let mut m = base.clone();
    m.to[0] ^= 0xff;
    mutations.push(("to", m));

    let mut m = base.clone();
    m.value += 1;
    mutations.push(("value", m));

    let mut m = base.clone();
    m.valid_after += 1;
    mutations.push(("validAfter", m));

    let mut m = base.clone();
    m.valid_before += 1;
    mutations.push(("validBefore", m));

    let mut m = base.clone();
    m.nonce[0] ^= 0xff;
    mutations.push(("nonce", m));

    for (name, mutated) in mutations {
        assert_ne!(
            mutated.transfer_struct_hash(),
            baseline,
            "changing {name} left the struct hash unchanged, so it is not being encoded"
        );
    }
}

/// The x402 specification's published payload must verify against the Base Sepolia USDC domain.
///
/// The spec publishes the signature and every authorization field but **no** EIP-712 domain, so
/// this vector was unusable as published (OBOL-019). The domain below was not found by searching:
/// it is the single candidate stated in advance — Circle's published Base Sepolia USDC address,
/// that chain's id, and the FiatTokenV2 name and version — and one trial either matches or does
/// not.
///
/// It matches. That is the strongest evidence available here: a wrong domain yields a different
/// digest and therefore an essentially random recovered address, so agreeing with `from` on all
/// 160 bits is not something a wrong guess does. The published signature itself attests to the
/// domain the signer used, which is why the companion test below is mandatory — without it, this
/// assertion could not distinguish a correct domain from a `verify_transfer` that always agrees.
#[test]
fn x402_spec_payload_recovers_its_authorizing_party() {
    let doc = fixture(X402_AUTHORIZATION);
    let auth = x402_authorization(&doc);
    let signature = decode_hex(doc["signature"].as_str().expect("signature")).expect("sig hex");

    assert!(
        auth.verify_transfer(&base_sepolia_usdc_domain(&doc), &signature)
            .expect("recovery succeeds"),
        "the spec's published signature did not recover to its own `from` address"
    );
}

/// Each field of that domain must be load-bearing.
///
/// This is what makes the test above evidence rather than an assertion that verified itself. If
/// `verify_transfer` ignored the domain — or ignored any single field of it — the positive test
/// would pass just the same. Perturbing one field at a time must break verification every time.
#[test]
fn every_domain_field_is_load_bearing_for_the_x402_payload() {
    let doc = fixture(X402_AUTHORIZATION);
    let auth = x402_authorization(&doc);
    let signature = decode_hex(doc["signature"].as_str().expect("signature")).expect("sig hex");
    let base = base_sepolia_usdc_domain(&doc);

    let mut perturbations: Vec<(&str, Eip712Domain)> = Vec::new();

    let mut d = base.clone();
    d.name = "USD Coin".to_string();
    perturbations.push(("name", d));

    let mut d = base.clone();
    d.version = "1".to_string();
    perturbations.push(("version", d));

    // Base mainnet rather than Base Sepolia — the near-miss most likely to happen by accident.
    let mut d = base.clone();
    d.chain_id = 8453;
    perturbations.push(("chain_id", d));

    let mut d = base.clone();
    d.verifying_contract[0] ^= 0xff;
    perturbations.push(("verifying_contract", d));

    for (field, domain) in perturbations {
        assert!(
            !auth
                .verify_transfer(&domain, &signature)
                .expect("recovery still succeeds"),
            "changing the domain's {field} still verified, so that field is not reaching the digest"
        );
    }
}

fn base_sepolia_usdc_domain(doc: &Value) -> Eip712Domain {
    let d = &doc["domain"];
    Eip712Domain {
        name: d["name"].as_str().expect("name").to_string(),
        version: d["version"].as_str().expect("version").to_string(),
        chain_id: d["chain_id"].as_u64().expect("chain_id"),
        verifying_contract: decode_hex_array(
            d["verifying_contract"].as_str().expect("verifying_contract"),
        )
        .expect("contract hex"),
    }
}

fn x402_authorization(doc: &Value) -> crate::Authorization {
    let a = &doc["authorization"];
    let number = |key: &str| -> u128 {
        a[key]
            .as_str()
            .expect("numeric field is a decimal string")
            .parse()
            .expect("decimal string parses")
    };
    crate::Authorization {
        from: decode_hex_array(a["from"].as_str().expect("from")).expect("from hex"),
        to: decode_hex_array(a["to"].as_str().expect("to")).expect("to hex"),
        value: number("value"),
        valid_after: number("valid_after") as u64,
        valid_before: number("valid_before") as u64,
        nonce: decode_hex_array(a["nonce"].as_str().expect("nonce")).expect("nonce hex"),
    }
}

/// A hex string of the wrong length must be rejected rather than truncated or padded.
#[test]
fn fixed_width_hex_decoding_rejects_wrong_lengths() {
    assert!(decode_hex_array::<20>("0x00").is_err(), "too short");
    assert!(
        decode_hex_array::<20>("0x036CbD53842c5426634e7929541eC2318f3dCF7e00").is_err(),
        "too long"
    );
    assert!(decode_hex_array::<20>("0xzz").is_err(), "not hex");
    assert!(
        decode_hex_array::<20>("036CbD53842c5426634e7929541eC2318f3dCF7e").is_ok(),
        "unprefixed hex of the right length is accepted"
    );
}

/// `v` in either convention must recover the same address, and anything else must be rejected.
#[test]
fn recovery_id_conventions_agree() {
    let doc = fixture(EIP712_MAIL);
    let digest = eip712::digest(&mail_domain(&doc).separator(), &mail_struct_hash(&doc));
    let mut signature = decode_hex(doc["signature"].as_str().expect("signature")).expect("sig hex");

    let as_published = recover_address(&digest, &signature).expect("27/28 form recovers");

    // The published signature ends in 0x1c (28); its 0/1-convention equivalent is 1.
    assert_eq!(signature[64], 28, "fixture signature is in the 27/28 form");
    signature[64] = 1;
    assert_eq!(
        recover_address(&digest, &signature).expect("0/1 form recovers"),
        as_published,
        "the two recovery-id conventions disagree"
    );

    signature[64] = 42;
    assert!(recover_address(&digest, &signature).is_err(), "v=42 rejected");
    assert!(
        recover_address(&digest, &signature[..64]).is_err(),
        "64-byte signature rejected"
    );
}
