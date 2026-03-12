//! Example: Plutus-compatible cryptographic operations
//!
//! Demonstrates the use of secp256k1 (ECDSA/Schnorr) and BLS12-381
//! primitives for Plutus smart contract interoperability.
//!
//! Run with: `cargo run --example plutus_crypto --features "secp256k1,bls"`

#[cfg(all(feature = "secp256k1", feature = "bls"))]
fn main() {
    println!("=== Cardano Plutus Cryptographic Primitives Demo ===\n");

    // =========================================================================
    // Part 1: secp256k1 ECDSA Signatures (CIP-0049)
    // =========================================================================
    println!("--- Part 1: secp256k1 ECDSA (CIP-0049) ---");

    use cardano_crypto::dsign::secp256k1::{Secp256k1Ecdsa, Secp256k1Schnorr};

    // Generate an ECDSA key pair
    let seed = [42u8; 32];
    let ecdsa_signing_key = Secp256k1Ecdsa::gen_key(&seed);
    let ecdsa_verification_key = Secp256k1Ecdsa::derive_verification_key(&ecdsa_signing_key);

    println!("ECDSA Public Key (33 bytes, compressed):");
    println!("  {:?}", hex::encode(ecdsa_verification_key.as_bytes()));

    // Sign a message
    let message = b"Hello, Plutus smart contract!";
    let ecdsa_signature = Secp256k1Ecdsa::sign(&ecdsa_signing_key, message);

    println!("ECDSA Signature (64 bytes, r||s):");
    println!("  {:?}", hex::encode(ecdsa_signature.as_bytes()));

    // Verify the signature
    match Secp256k1Ecdsa::verify(&ecdsa_verification_key, message, &ecdsa_signature) {
        Ok(()) => println!("✓ ECDSA signature verified successfully!\n"),
        Err(e) => println!("✗ ECDSA verification failed: {:?}\n", e),
    }

    // =========================================================================
    // Part 2: secp256k1 Schnorr Signatures (CIP-0049, BIP-340)
    // =========================================================================
    println!("--- Part 2: secp256k1 Schnorr (BIP-340) ---");

    // Generate a Schnorr key pair
    let schnorr_signing_key = Secp256k1Schnorr::gen_key(&seed);
    let schnorr_verification_key = Secp256k1Schnorr::derive_verification_key(&schnorr_signing_key);

    println!("Schnorr Public Key (32 bytes, x-only):");
    println!("  {:?}", hex::encode(schnorr_verification_key.as_bytes()));

    // Sign a message
    let schnorr_signature = Secp256k1Schnorr::sign(&schnorr_signing_key, message)
        .expect("Schnorr signing failed");

    println!("Schnorr Signature (64 bytes, r||s):");
    println!("  {:?}", hex::encode(schnorr_signature.as_bytes()));

    // Verify the signature
    match Secp256k1Schnorr::verify(&schnorr_verification_key, message, &schnorr_signature) {
        Ok(()) => println!("✓ Schnorr signature verified successfully!\n"),
        Err(e) => println!("✗ Schnorr verification failed: {:?}\n", e),
    }

    // =========================================================================
    // Part 3: BLS12-381 Curve Operations (CIP-0381)
    // =========================================================================
    println!("--- Part 3: BLS12-381 (CIP-0381) ---");

    use cardano_crypto::bls::{bls_verify, Bls12381, BlsSecretKey, G1Point, G2Point, Scalar};

    // G1 operations
    println!("\nG1 Operations:");
    let g1_gen = G1Point::generator();
    let g1_compressed = Bls12381::g1_compress(&g1_gen);
    println!(
        "  G1 generator (48 bytes): {}...",
        hex::encode(&g1_compressed[..8])
    );

    // G2 operations
    println!("\nG2 Operations:");
    let g2_gen = G2Point::generator();
    let g2_compressed = Bls12381::g2_compress(&g2_gen);
    println!(
        "  G2 generator (96 bytes): {}...",
        hex::encode(&g2_compressed[..8])
    );

    // Scalar multiplication
    let mut scalar_bytes = [0u8; 32];
    scalar_bytes[31] = 42;
    let scalar = Scalar::from_bytes_be(&scalar_bytes).unwrap();
    let g1_scaled = Bls12381::g1_scalar_mul(&scalar, &g1_gen);
    println!(
        "\n  G1 * 42 = {}...",
        hex::encode(&Bls12381::g1_compress(&g1_scaled)[..8])
    );

    // Pairing
    println!("\nPairing Operations:");
    let pairing_result = Bls12381::pairing(&g1_gen, &g2_gen);
    println!("  e(G1, G2) computed (is_one: {})", pairing_result.is_one());

    // Hash to curve
    println!("\nHash to Curve:");
    let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
    let h1 = Bls12381::g1_hash_to_curve(b"test message", dst);
    println!(
        "  H1('test message') = {}...",
        hex::encode(&Bls12381::g1_compress(&h1)[..8])
    );

    // =========================================================================
    // Part 4: BLS Signatures
    // =========================================================================
    println!("\n--- Part 4: BLS Signatures ---");

    // Generate a BLS key pair
    let bls_seed = [123u8; 32];
    let bls_sk = BlsSecretKey::from_bytes(&bls_seed).unwrap();
    let bls_pk = bls_sk.public_key();

    println!("BLS Public Key (48 bytes):");
    println!("  {:?}", hex::encode(bls_pk.to_compressed()));

    // Sign a message
    let bls_message = b"BLS signature message for Plutus";
    let bls_signature = bls_sk.sign(bls_message);

    println!("BLS Signature (96 bytes):");
    println!(
        "  {:?}...",
        hex::encode(&bls_signature.to_compressed()[..32])
    );

    // Verify the signature
    match bls_verify(&bls_pk, bls_message, &bls_signature) {
        Ok(()) => println!("✓ BLS signature verified successfully!\n"),
        Err(e) => println!("✗ BLS verification failed: {:?}\n", e),
    }

    // =========================================================================
    // Part 5: Bilinearity Check (Core BLS Property)
    // =========================================================================
    println!("--- Part 5: Bilinearity Check ---");

    // Verify: e(aG1, bG2) = e(abG1, G2) = e(G1, abG2)
    let mut a_bytes = [0u8; 32];
    a_bytes[31] = 5;
    let a = Scalar::from_bytes_be(&a_bytes).unwrap();

    let mut b_bytes = [0u8; 32];
    b_bytes[31] = 7;
    let b = Scalar::from_bytes_be(&b_bytes).unwrap();

    let ag1 = Bls12381::g1_scalar_mul(&a, &g1_gen);
    let bg2 = Bls12381::g2_scalar_mul(&b, &g2_gen);
    let result1 = Bls12381::pairing(&ag1, &bg2);

    // ab = 5 * 7 = 35
    let mut ab_bytes = [0u8; 32];
    ab_bytes[31] = 35;
    let ab = Scalar::from_bytes_be(&ab_bytes).unwrap();
    let abg1 = Bls12381::g1_scalar_mul(&ab, &g1_gen);
    let result2 = Bls12381::pairing(&abg1, &g2_gen);

    if result1 == result2 {
        println!("✓ Bilinearity verified: e(aG1, bG2) = e(abG1, G2)");
    } else {
        println!("✗ Bilinearity check failed!");
    }

    println!("\n=== Demo Complete ===");
}

#[cfg(not(all(feature = "secp256k1", feature = "bls")))]
fn main() {
    eprintln!("This example requires the 'secp256k1' and 'bls' features.");
    eprintln!("Run with: cargo run --example plutus_crypto --features \"secp256k1,bls\"");
}
