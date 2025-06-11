use k256::ecdsa::SigningKey;
use k256::EncodedPoint;
use ethers::core::utils::keccak256;
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
    aead::generic_array::GenericArray,
};
use rand_core::RngCore;
use hex::{encode as hex_encode, decode as hex_decode};

/// 加密函数：用 AES-256-GCM 加密私钥（hex 格式）
fn encrypt_hex(key_hex: &str, plaintext: &str) -> (String, String) {
    let key_bytes = hex_decode(key_hex).expect("Invalid hex key");
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&key_bytes));
    let nonce_hex = "80e6683397afd4967c21cde0"; // 固定 nonce（建议生产中随机生成）
    let nonce = hex_decode(nonce_hex).expect("Invalid nonce hex");

    let ciphertext =
        cipher.encrypt(Nonce::from_slice(&nonce), plaintext.as_bytes()).expect("encryption failed");

    (hex_encode(ciphertext), hex_encode(nonce))
}

/// 解密函数（测试用）
fn decrypt_hex(key_hex: &str, ciphertext_hex: &str, nonce_hex: &str) -> String {
    let key_bytes = hex_decode(key_hex).expect("Invalid hex key");
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&key_bytes));
    let ciphertext = hex_decode(ciphertext_hex).expect("Invalid ciphertext hex");
    let nonce = hex_decode(nonce_hex).expect("Invalid nonce hex");

    let plaintext = cipher
        .decrypt(Nonce::from_slice(&nonce), &ciphertext[..])
        .expect("decryption failed");

    String::from_utf8(plaintext).expect("Invalid UTF-8")
}

fn main() {
    // === 1. 生成以太坊私钥、公钥、地址 ===
    let signing_key = SigningKey::random(&mut OsRng);
    let verify_key = signing_key.verifying_key();
    let secret_key_bytes = signing_key.to_bytes();
    let private_key_hex = hex_encode(&secret_key_bytes);
    println!("🔑 Private Key (hex): {}", private_key_hex);

    let pubkey_encoded = verify_key.to_encoded_point(false); // 未压缩
    let pubkey_bytes = &pubkey_encoded.as_bytes()[1..]; // 去掉0x04前缀

    let hash = keccak256(pubkey_bytes);
    let address = &hash[12..];
    println!("📬 Ethereum Address: 0x{}", hex_encode(address));

    // === 2. 加密私钥 ===
    let aes_key_hex = "967c2d7997b8272f24b2a9f5b9df49925c181b4ccb29ce05127875d2ff62e9ee";
    let (ciphertext_hex, nonce_hex) = encrypt_hex(aes_key_hex, &private_key_hex);

    println!("🔒 Encrypted Private Key (hex): {}", ciphertext_hex);
    println!("🧂 Nonce: {}", nonce_hex);

    // === 3. 解密验证 ===
    let decrypted = decrypt_hex(aes_key_hex, &ciphertext_hex, &nonce_hex);
    println!("✅ Decrypted Private Key: {}", decrypted);
}