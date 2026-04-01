use std::fmt::Write as _;

use secp256k1::{Secp256k1, XOnlyPublicKey, schnorr::Signature};
use sha2::{Digest, Sha256};

use crate::EventRecord;

pub fn serialize_event_data(event: &EventRecord) -> String {
    nojson::array(|f| {
        f.element(0u8)?;
        f.element(&event.pubkey)?;
        f.element(event.created_at)?;
        f.element(event.kind)?;
        f.element(&event.tags)?;
        f.element(&event.content)
    })
    .to_string()
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(&mut out, "{:02x}", b);
    }
    out
}

pub fn compute_event_id(event: &EventRecord) -> String {
    let serialized = serialize_event_data(event);
    compute_event_id_from_serialized(&serialized)
}

pub fn compute_event_id_from_serialized(serialized: &str) -> String {
    let digest = Sha256::digest(serialized.as_bytes());
    bytes_to_hex(&digest)
}

fn from_hex_nibble(ch: u8) -> Result<u8, String> {
    match ch {
        b'0'..=b'9' => Ok(ch - b'0'),
        b'a'..=b'f' => Ok(ch - b'a' + 10),
        _ => Err("invalid: non-hex character encountered".to_string()),
    }
}

pub fn hex_to_fixed<const N: usize>(hex: &str) -> Result<[u8; N], String> {
    if hex.len() != N * 2 {
        return Err(format!("invalid: expected {} hex chars", N * 2));
    }

    let mut out = [0u8; N];
    let bytes = hex.as_bytes();

    for i in 0..N {
        let hi = from_hex_nibble(bytes[i * 2])?;
        let lo = from_hex_nibble(bytes[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }

    Ok(out)
}

pub fn verify_event_signature(event: &EventRecord) -> Result<(), String> {
    let id_bytes = hex_to_fixed::<32>(&event.id)?;
    let sig_bytes = hex_to_fixed::<64>(&event.sig)?;
    let pubkey_bytes = hex_to_fixed::<32>(&event.pubkey)?;

    let pubkey = XOnlyPublicKey::from_byte_array(pubkey_bytes)
        .map_err(|_| "invalid: pubkey is not a valid x-only secp256k1 key".to_string())?;
    let signature = Signature::from_byte_array(sig_bytes);
    let secp = Secp256k1::verification_only();

    secp.verify_schnorr(&signature, &id_bytes, &pubkey)
        .map_err(|_| "invalid: bad event signature".to_string())
}


pub fn verify_delegation_signature(
    delegator_pubkey: &str,
    delegatee_pubkey: &str,
    conditions: &str,
    token: &str,
) -> Result<(), String> {
    let pubkey_bytes = hex_to_fixed::<32>(delegator_pubkey)?;
    let sig_bytes = hex_to_fixed::<64>(token)?;

    let pubkey = XOnlyPublicKey::from_byte_array(pubkey_bytes).map_err(|_| {
        "invalid: delegation pubkey is not a valid x-only secp256k1 key".to_string()
    })?;
    let signature = Signature::from_byte_array(sig_bytes);
    let secp = Secp256k1::verification_only();

    let delegation_message = format!("nostr:delegation:{delegatee_pubkey}:{conditions}");
    let digest = Sha256::digest(delegation_message.as_bytes());
    let mut digest_bytes = [0u8; 32];
    digest_bytes.copy_from_slice(&digest);

    secp.verify_schnorr(&signature, &digest_bytes, &pubkey)
        .map_err(|_| "invalid: bad delegation signature".to_string())
}
