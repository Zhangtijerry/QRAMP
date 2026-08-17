// Testbed Rust crypto usage (RustCrypto ecosystem + ring)
use md5::Md5;
use sha1::Sha1;
use sha2::Sha256;
use rsa::RsaPrivateKey;
use aes_gcm::Aes256Gcm;
use des::Des;

fn hash_legacy(data: &[u8]) -> Vec<u8> {
    let mut hasher = Md5::new();          // weak hash
    hasher.update(data);
    hasher.finalize().to_vec()
}

fn hash_sha1(data: &[u8]) -> Vec<u8> {
    let d = Sha1::new();                   // weak hash
    Sha1::digest(data).to_vec()
}

fn hash_strong(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()          // ok
}

fn gen_rsa(rng: &mut impl rand::Rng) -> RsaPrivateKey {
    RsaPrivateKey::new(rng, 2048).unwrap() // quantum-broken, 2048-bit
}

fn encrypt_legacy(k: &[u8]) {
    let _c = Des::new_from_slice(k);       // DES-56, broken
}

fn encrypt_modern(k: &[u8]) {
    let _c = Aes256Gcm::new(k.into());     // ok
}
