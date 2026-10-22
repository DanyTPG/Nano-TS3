use aes::Aes128;
use base64::prelude::*;
use eax::Eax;
use eax::aead::generic_array::typenum::U8;
use eax::aead::{AeadInPlace, KeyInit};
use num_bigint::{BigUint, RandBigInt};
use num_traits::Zero;
use p256::ecdsa::signature::Signer;
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::{AffinePoint, PublicKey, SecretKey};
use sha1::{Digest, Sha1};
use sha2::{Sha256, Sha512};
use std::convert::TryInto;
use tsproto_packets::packets::Direction;

type Eax8 = Eax<Aes128, U8>;

/// Well-known bootstrap AES-128 EAX key and nonce used for pre-SharedIV server commands (e.g. initivexpand2, clientek).
pub const BOOTSTRAP_KEY: &[u8; 16] = b"c:\\windows\\syste";
pub const BOOTSTRAP_NONCE: &[u8; 16] = b"m\\firewall32.cpl";

/// Server NIST P-256 private key scalar corresponding to the pre-authenticated Anonymous server proof.
pub const SERVER_KEY_K: [u8; 32] = [
    0x83, 0x92, 0x85, 0xd7, 0x1f, 0x15, 0x91, 0xaf, 0x9b, 0x23, 0x77, 0xf5, 0x7e, 0x35, 0x0b, 0x70,
    0x51, 0xb4, 0x69, 0xd3, 0x31, 0xbc, 0xe1, 0x70, 0x1d, 0x9a, 0x43, 0xeb, 0x26, 0xb6, 0xa7, 0x0a,
];

/// Server Curve25519/Ed25519 private key scalar corresponding to the Anonymous license Ephemeral block.
pub const SERVER_LICENSE_KEY_K: [u8; 32] = [
    0x00, 0xdb, 0x9f, 0x19, 0x56, 0x9a, 0x21, 0xd2, 0xc9, 0x41, 0x95, 0x0b, 0xe4, 0x5d, 0xb1, 0x2e,
    0x20, 0xa5, 0xff, 0xec, 0xf3, 0x7a, 0x97, 0x72, 0x3d, 0x35, 0x3c, 0x52, 0x8c, 0x1d, 0xc8, 0x63,
];

pub const ANONYMOUS_LICENSE: &str = "AQBgjAAqtcBUrw5futTtkl3+EM3OW4Lal6OTPlwuv4xV/gIRFlEAG0NlAAcAAAAgQW5vbnltb3VzAAAPbmHs1s6rL0qt4UT/VkmEju5rs6bz0Jq/06EpcieHTCAZ9g8aGfa32g==";

/// Dynamically signs the anonymous license with the server P-256 private key, returning the DER signature in base64.
pub fn sign_license_proof() -> String {
    let signing_key =
        p256::ecdsa::SigningKey::from_slice(&SERVER_KEY_K).expect("valid P-256 signing key");
    let lic_bytes = BASE64_STANDARD
        .decode(ANONYMOUS_LICENSE)
        .expect("valid base64 license");
    let sig: p256::ecdsa::DerSignature = signing_key.sign(&lic_bytes);
    BASE64_STANDARD.encode(sig.as_bytes())
}

/// Derives the 16-byte AES key and 16-byte Nonce for an individual packet stream.
pub fn derive_key_nonce(
    direction: Direction,
    p_type: u8,
    generation_id: u32,
    packet_id: u16,
    shared_iv: &[u8],
) -> ([u8; 16], [u8; 16]) {
    let mut temp = Vec::with_capacity(6 + shared_iv.len());
    temp.push(match direction {
        Direction::S2C => 0x30,
        Direction::C2S => 0x31,
    });
    temp.push(p_type);
    temp.extend_from_slice(&generation_id.to_be_bytes());
    temp.extend_from_slice(shared_iv);

    let hash = Sha256::digest(&temp);
    let mut key = [0u8; 16];
    let mut nonce = [0u8; 16];
    key.copy_from_slice(&hash[0..16]);
    nonce.copy_from_slice(&hash[16..32]);

    key[0] ^= ((packet_id & 0xFF00) >> 8) as u8;
    key[1] ^= (packet_id & 0x00FF) as u8;

    (key, nonce)
}

/// Encrypts plaintext in-place using AES-128 EAX with an 8-byte tag.
/// Returns the 8-byte authentication MAC.
pub fn encrypt_eax(
    key: &[u8; 16],
    nonce: &[u8; 16],
    associated_data: &[u8],
    buffer: &mut Vec<u8>,
) -> Result<[u8; 8], String> {
    let cipher = Eax8::new(key.into());
    let tag = cipher
        .encrypt_in_place_detached(nonce.into(), associated_data, buffer)
        .map_err(|e| format!("EAX encryption error: {:?}", e))?;

    let tag_bytes: [u8; 8] = tag
        .as_slice()
        .try_into()
        .map_err(|_| "Invalid tag length")?;
    Ok(tag_bytes)
}

/// Decrypts ciphertext in-place using AES-128 EAX, verifying the 8-byte tag.
pub fn decrypt_eax(
    key: &[u8; 16],
    nonce: &[u8; 16],
    associated_data: &[u8],
    tag: &[u8; 8],
    buffer: &mut [u8],
) -> Result<(), String> {
    let cipher = Eax8::new(key.into());
    cipher
        .decrypt_in_place_detached(nonce.into(), associated_data, buffer, tag.into())
        .map_err(|e| format!("EAX decryption / authentication failure: {:?}", e))
}

/// Encodes an affine public key point (x, y) into LibTomCrypt ASN.1 DER format.
pub fn encode_libtomcrypt_ecc_public(point: &AffinePoint) -> Vec<u8> {
    let encoded = point.to_sec1_point(false);
    let x = encoded.x().unwrap();
    let y = encoded.y().unwrap();

    fn der_encode_int(bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(0x02); // INTEGER
        if !bytes.is_empty() && (bytes[0] & 0x80) != 0 {
            out.push((bytes.len() + 1) as u8);
            out.push(0x00);
        } else {
            out.push(bytes.len() as u8);
        }
        out.extend_from_slice(bytes);
        out
    }

    let bit_string = vec![0x03, 0x02, 0x07, 0x00]; // LibTomCrypt BIT STRING (1 unused bit, tag 0x03, len 0x02, unused bits 0x07, byte 0x00)
    let key_size = vec![0x02, 0x01, 0x20]; // INTEGER 32 (256-bit curve)
    let x_int = der_encode_int(x.as_slice());
    let y_int = der_encode_int(y.as_slice());

    let payload_len = bit_string.len() + key_size.len() + x_int.len() + y_int.len();
    let mut seq = Vec::new();
    seq.push(0x30); // SEQUENCE
    if payload_len < 128 {
        seq.push(payload_len as u8);
    } else {
        seq.push(0x81);
        seq.push(payload_len as u8);
    }
    seq.extend_from_slice(&bit_string);
    seq.extend_from_slice(&key_size);
    seq.extend_from_slice(&x_int);
    seq.extend_from_slice(&y_int);

    seq
}

/// Decodes LibTomCrypt ASN.1 DER public key into a P-256 PublicKey.
pub fn decode_libtomcrypt_ecc_public(der: &[u8]) -> Result<PublicKey, String> {
    if der.len() < 10 || der[0] != 0x30 {
        return Err("Invalid ASN.1 SEQUENCE header".into());
    }

    let mut idx = 2;
    if der[1] == 0x81 {
        idx = 3;
    }

    // Skip bit string (0x03, len, val)
    if idx >= der.len() || der[idx] != 0x03 {
        return Err("Expected BIT STRING".into());
    }
    let bit_len = der[idx + 1] as usize;
    idx += 2 + bit_len;

    // Skip key size integer (0x02, len, val)
    if idx >= der.len() || der[idx] != 0x02 {
        return Err("Expected key size INTEGER".into());
    }
    let k_len = der[idx + 1] as usize;
    idx += 2 + k_len;

    // Read X integer
    if idx >= der.len() || der[idx] != 0x02 {
        return Err("Expected X INTEGER".into());
    }
    let x_len = der[idx + 1] as usize;
    let mut x_bytes = &der[idx + 2..idx + 2 + x_len];
    if !x_bytes.is_empty() && x_bytes[0] == 0x00 {
        x_bytes = &x_bytes[1..];
    }
    idx += 2 + x_len;

    // Read Y integer
    if idx >= der.len() || der[idx] != 0x02 {
        return Err("Expected Y INTEGER".into());
    }
    let y_len = der[idx + 1] as usize;
    let mut y_bytes = &der[idx + 2..idx + 2 + y_len];
    if !y_bytes.is_empty() && y_bytes[0] == 0x00 {
        y_bytes = &y_bytes[1..];
    }

    let mut x_fixed = [0u8; 32];
    let mut y_fixed = [0u8; 32];
    if x_bytes.len() > 32 || y_bytes.len() > 32 {
        return Err("Coordinate exceeds 32 bytes".into());
    }
    x_fixed[32 - x_bytes.len()..].copy_from_slice(x_bytes);
    y_fixed[32 - y_bytes.len()..].copy_from_slice(y_bytes);

    let mut uncompressed = [0u8; 65];
    uncompressed[0] = 0x04;
    uncompressed[1..33].copy_from_slice(&x_fixed);
    uncompressed[33..65].copy_from_slice(&y_fixed);

    PublicKey::from_sec1_bytes(&uncompressed)
        .map_err(|e| format!("Invalid SEC1 public key: {:?}", e))
}

/// Derives the 64-byte SharedIV for modern TS3 >= 3.1 handshake:
/// SharedIV = sha512(client_ek_pub * server_license_priv) ^ alpha ^ beta
pub fn compute_shared_iv_modern(
    client_ek_pub: &[u8; 32],
    server_priv: &[u8; 32],
    alpha: &[u8],
    beta: &[u8],
) -> Result<[u8; 64], String> {
    use curve25519_dalek::edwards::CompressedEdwardsY;
    use curve25519_dalek::scalar::Scalar;

    let pt = CompressedEdwardsY(*client_ek_pub)
        .decompress()
        .ok_or_else(|| "Failed to decompress client Ed25519 point".to_string())?;

    let scalar = Scalar::from_bytes_mod_order(*server_priv);
    let shared_point = pt * scalar;
    let shared_secret = shared_point.compress().0;

    let hash = Sha512::digest(&shared_secret);
    let mut shared_iv = [0u8; 64];
    shared_iv.copy_from_slice(&hash);

    for (i, b) in alpha.iter().enumerate().take(10) {
        shared_iv[i] ^= *b;
    }
    for (i, b) in beta.iter().enumerate().take(54) {
        shared_iv[10 + i] ^= *b;
    }

    Ok(shared_iv)
}

/// Derives the 20-byte SharedIV for old TS3 handshake:
/// SharedIV = sha1(shared_data) ^ alpha ^ beta
pub fn compute_shared_iv(
    server_secret: &SecretKey,
    client_public: &PublicKey,
    alpha: &[u8],
    beta: &[u8],
) -> Result<[u8; 20], String> {
    let shared =
        p256::ecdh::diffie_hellman(server_secret.to_nonzero_scalar(), client_public.as_affine());
    let raw_x = shared.raw_secret_bytes();

    let mut shared_data = [0u8; 32];
    if raw_x.len() <= 32 {
        shared_data[32 - raw_x.len()..].copy_from_slice(raw_x.as_slice());
    } else {
        shared_data.copy_from_slice(&raw_x[raw_x.len() - 32..]);
    }

    let mut siv = [0u8; 20];
    let hash = Sha1::digest(&shared_data);
    siv.copy_from_slice(&hash);

    // XOR alpha into first 10 bytes
    for i in 0..10.min(alpha.len()) {
        siv[i] ^= alpha[i];
    }
    // XOR beta into next 10 bytes
    for i in 0..10.min(beta.len()) {
        siv[10 + i] ^= beta[i];
    }

    Ok(siv)
}

/// Represents the parameters for an RSA puzzle in Init3.
#[derive(Clone, Debug)]
pub struct RsaPuzzle {
    pub x: [u8; 64],
    pub n: [u8; 64],
    pub level: u32,
    pub random2: [u8; 100],
}

impl RsaPuzzle {
    pub fn new() -> Self {
        let mut rng = rand::thread_rng();
        // Generate two 256-bit odd numbers with MSB set (in [2^255, 2^256-1])
        let mut p_bytes = [0u8; 32];
        let mut q_bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rng, &mut p_bytes);
        rand::RngCore::fill_bytes(&mut rng, &mut q_bytes);
        p_bytes[0] |= 0x80;
        p_bytes[31] |= 0x01;
        q_bytes[0] |= 0x80;
        q_bytes[31] |= 0x01;

        let p = BigUint::from_bytes_be(&p_bytes);
        let q = BigUint::from_bytes_be(&q_bytes);
        // n is guaranteed to be odd (Montgomery reduction in TS3 client requires odd modulus)
        // and exactly 512 bits (64 bytes)
        let n_val = &p * &q;
        let x_val = rng.gen_biguint_range(&BigUint::from(2u32), &n_val);

        let mut n_bytes = [0u8; 64];
        let mut x_bytes = [0u8; 64];
        let n_digits = n_val.to_bytes_be();
        let x_digits = x_val.to_bytes_be();

        if n_digits.len() <= 64 {
            n_bytes[64 - n_digits.len()..].copy_from_slice(&n_digits);
        } else {
            n_bytes.copy_from_slice(&n_digits[..64]);
        }

        if x_digits.len() <= 64 {
            x_bytes[64 - x_digits.len()..].copy_from_slice(&x_digits);
        } else {
            x_bytes.copy_from_slice(&x_digits[..64]);
        }

        let mut random2 = [0u8; 100];
        rand::Rng::fill(&mut rng, &mut random2[..]);

        Self {
            x: x_bytes,
            n: n_bytes,
            level: 10, // 10 modular squarings in TS3 client
            random2,
        }
    }

    pub fn verify(&self, y_bytes: &[u8; 64]) -> bool {
        let x = BigUint::from_bytes_be(&self.x);
        let n = BigUint::from_bytes_be(&self.n);
        let y = BigUint::from_bytes_be(y_bytes);

        if n.is_zero() {
            return false;
        }

        let mut cur = x % &n;
        for _ in 0..self.level {
            cur = (&cur * &cur) % &n;
        }

        cur == y
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    #[test]
    fn test_eax_encrypt_decrypt() {
        let key = [0x42u8; 16];
        let nonce = [0x13u8; 16];
        let aad = b"header_data";
        let original_data = b"clientinitiv alpha=123 omega=456".to_vec();

        let mut buffer = original_data.clone();
        let tag = encrypt_eax(&key, &nonce, aad, &mut buffer).expect("encryption failed");

        assert_ne!(buffer, original_data);

        decrypt_eax(&key, &nonce, aad, &tag, &mut buffer).expect("decryption failed");
        assert_eq!(buffer, original_data);
    }

    #[test]
    fn test_ecc_der_roundtrip() {
        let mut rng = rand::thread_rng();
        let mut key_bytes = [0u8; 32];
        let secret = loop {
            rng.fill_bytes(&mut key_bytes);
            if let Ok(sk) = SecretKey::from_slice(&key_bytes) {
                break sk;
            }
        };

        let public_key = secret.public_key();
        let affine = public_key.as_affine();
        let der = encode_libtomcrypt_ecc_public(affine);
        let decoded = decode_libtomcrypt_ecc_public(&der).expect("failed to decode DER");

        assert_eq!(public_key, decoded);
    }

    #[test]
    fn test_rsa_puzzle_verification() {
        let puzzle = RsaPuzzle::new();
        let x = BigUint::from_bytes_be(&puzzle.x);
        let n = BigUint::from_bytes_be(&puzzle.n);

        let mut cur = x % &n;
        for _ in 0..puzzle.level {
            cur = (&cur * &cur) % &n;
        }

        let y_digits = cur.to_bytes_be();
        let mut y_bytes = [0u8; 64];
        if y_digits.len() <= 64 {
            y_bytes[64 - y_digits.len()..].copy_from_slice(&y_digits);
        } else {
            y_bytes.copy_from_slice(&y_digits[..64]);
        }

        assert!(puzzle.verify(&y_bytes));

        let mut bad_y = y_bytes;
        bad_y[0] ^= 0x01;
        assert!(!puzzle.verify(&bad_y));
    }
}
