use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::{
    aead::generic_array::GenericArray,
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use ethers::core::utils::keccak256;
use hex::{decode as hex_decode, encode as hex_encode, ToHex};
use k256::ecdsa::SigningKey;
use k256::EncodedPoint;
//use secp256k1::{PublicKey, Secp256k1, SecretKey};
use alloy_primitives::Address;
use reth_network_peers::{id2pk, pk2id, PeerId};
use std::str::FromStr;
/// AES-GCM 加密私钥
fn encrypt_hex(key_hex: &str, plaintext: &str) -> (String, String) {
    let key_bytes = hex_decode(key_hex).expect("Invalid hex key");
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&key_bytes));
    let nonce_hex = "80e6683397afd4967c21cde0"; // 注意：生产应使用随机 nonce
    let nonce = hex_decode(nonce_hex).expect("Invalid nonce hex");

    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext.as_bytes())
        .expect("encryption failed");

    (hex_encode(ciphertext), hex_encode(nonce))
}

/// 生成随机的 AES-256 密钥和 96-bit Nonce（用于 AES-GCM）
fn generate_aes_key_and_nonce() -> (String, String) {
    let mut key = [0u8; 32]; // 256-bit AES key
    let mut nonce = [0u8; 12]; // 96-bit AES-GCM nonce
    let mut rng = OsRng; // 实例化随机数生成器
    rng.fill_bytes(&mut key);
    rng.fill_bytes(&mut nonce);

    (hex_encode(key), hex_encode(nonce))
}

/// AES-GCM 解密
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
    for i in 1..=30 {
        println!("================= 第 {} 次循环 =================", i);
        run_once();
    }
}

fn run_once() {
    println!("================= 1. 生成密钥和地址 =================");
    let signing_key = SigningKey::random(&mut OsRng);
    let verify_key = signing_key.verifying_key();
    let secret_key_bytes = signing_key.to_bytes();
    let private_key_hex = hex_encode(&secret_key_bytes);
    println!("🔑 Private Key (hex): {}", private_key_hex);

    let pubkey_encoded = verify_key.to_encoded_point(false);
    let pubkey_bytes = &pubkey_encoded.as_bytes()[1..]; // 64字节（去掉0x04）
    let hash = keccak256(pubkey_bytes);
    let address = &hash[12..];
    println!("📬 Ethereum Address: 0x{}", hex_encode(address));

    println!("================= 2. 转换 PeerId =================");
    let secp = secp256k1::Secp256k1::new();

    let secret_key = secp256k1::SecretKey::from_slice(&secret_key_bytes).unwrap();
    let public_key = secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
    let peer_id = pk2id(&public_key);
    println!("🧑‍🤝‍🧑 Peer ID: {}", peer_id);

    let recovered_pubkey = id2pk(peer_id).expect("恢复 pubkey 失败");
    println!("🔁 Recovered Public Key: {}", recovered_pubkey);

    let recovered_address = Address::from_raw_public_key(peer_id.as_slice());
    println!("🏠 Recovered Address: {}", recovered_address);

    println!("================= 3. 加密私钥 =================");
    let aes_key_hex = "967c2d7997b8272f24b2a9f5b9df49925c181b4ccb29ce05127875d2ff62e9ee"; // 256-bit
    let (ciphertext_hex, nonce_hex) = encrypt_hex(aes_key_hex, &private_key_hex);
    println!("🔒 Encrypted Private Key (hex): {}", ciphertext_hex);
    println!("🧂 Nonce: {}", nonce_hex);

    println!("================= 4. 解密验证 =================");
    let decrypted = decrypt_hex(aes_key_hex, &ciphertext_hex, &nonce_hex);
    println!("✅ Decrypted Private Key: {}", decrypted);

    assert_eq!(decrypted, private_key_hex);
    println!("🎉 验证成功：解密后私钥一致！");

    println!("================= 5. 生成 AES 密钥和 Nonce =================");
    let (aes_key_hex, nonce_hex) = generate_aes_key_and_nonce();
    println!("🧬 AES Key (hex): {}", aes_key_hex);
    println!("🧂 Nonce: {}", nonce_hex);
}
