use base64::prelude::*;
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;
use nano_ts3::crypto::*;
use sha2::{Digest, Sha512};

const ROOT_KEY: [u8; 32] = [
    0xcd, 0x0d, 0xe2, 0xae, 0xd4, 0x63, 0x45, 0x50, 0x9a, 0x7e, 0x3c, 0xfd, 0x8f, 0x68, 0xb3, 0xdc,
    0x75, 0x55, 0xb2, 0x9d, 0xcc, 0xec, 0x73, 0xcd, 0x18, 0x75, 0x0f, 0x99, 0x38, 0x12, 0x40, 0x8a,
];

fn derive_block(
    block: &[u8],
    parent: curve25519_dalek::edwards::EdwardsPoint,
) -> curve25519_dalek::edwards::EdwardsPoint {
    let pub_point = CompressedEdwardsY(block[1..33].try_into().unwrap())
        .decompress()
        .expect("valid block pub");
    let mut h = Sha512::digest(&block[1..]);
    h[0] &= 248;
    h[31] &= 63;
    h[31] |= 64;
    let hs = Scalar::from_bytes_mod_order(h[..32].try_into().unwrap());
    pub_point * hs + parent
}

fn main() {
    let lic = BASE64_STANDARD.decode(ANONYMOUS_LICENSE).unwrap();
    // Block 1: TS3 server block, 57 bytes (42 + 6 + "Anonymous").
    // Block 2: Ephemeral block, 42 bytes.
    let b1 = &lic[1..58];
    let b2 = &lic[58..100];
    let root = CompressedEdwardsY(ROOT_KEY).decompress().unwrap();
    let d1 = derive_block(b1, root);
    let d2 = derive_block(b2, d1);
    let expected =
        (ED25519_BASEPOINT_POINT * Scalar::from_bytes_mod_order(SERVER_LICENSE_KEY_K)).compress();
    println!("derived : {}", hex(&d2.compress().0));
    println!("expected: {}", hex(&expected.0));
    println!("match: {}", d2.compress().0 == expected.0);
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}
