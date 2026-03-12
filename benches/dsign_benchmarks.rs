//! Digital Signature Performance Benchmarks
//!
//! Benchmarks for Ed25519 and secp256k1 signature implementations.
//!
//! Run with: cargo bench --bench dsign_benchmarks

use cardano_crypto::dsign::{DsignAlgorithm, Ed25519};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

fn ed25519_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("Ed25519");

    let seed = [42u8; 32];

    group.bench_function("gen_key", |b| {
        b.iter(|| black_box(Ed25519::gen_key(black_box(&seed))));
    });

    group.finish();
}

fn ed25519_derive_vk(c: &mut Criterion) {
    let mut group = c.benchmark_group("Ed25519");

    let seed = [42u8; 32];
    let sk = Ed25519::gen_key(&seed).unwrap();

    group.bench_function("derive_verification_key", |b| {
        b.iter(|| black_box(Ed25519::derive_verification_key(black_box(&sk))));
    });

    group.finish();
}

fn ed25519_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("Ed25519");

    let seed = [42u8; 32];
    let sk = Ed25519::gen_key(&seed).unwrap();

    // Benchmark different message sizes
    for size in [32, 64, 256, 1024, 4096].iter() {
        let message = vec![0u8; *size];

        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::new("sign", size), size, |b, _| {
            b.iter(|| black_box(Ed25519::sign(black_box(&sk), black_box(&message))));
        });
    }

    group.finish();
}

fn ed25519_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("Ed25519");

    let seed = [42u8; 32];
    let sk = Ed25519::gen_key(&seed).unwrap();
    let vk = Ed25519::derive_verification_key(&sk);

    // Benchmark different message sizes
    for size in [32, 64, 256, 1024, 4096].iter() {
        let message = vec![0u8; *size];
        let signature = Ed25519::sign(&sk, &message);

        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::new("verify", size), size, |b, _| {
            b.iter(|| {
                black_box(Ed25519::verify(
                    black_box(&vk),
                    black_box(&message),
                    black_box(&signature),
                ))
                .unwrap()
            });
        });
    }

    group.finish();
}

#[cfg(feature = "secp256k1")]
fn secp256k1_benchmarks(c: &mut Criterion) {
    use cardano_crypto::dsign::{Secp256k1Ecdsa, Secp256k1Schnorr};

    // ECDSA benchmarks
    {
        let mut group = c.benchmark_group("secp256k1 ECDSA");

        let seed = [42u8; 32];
        let sk = Secp256k1Ecdsa::gen_key(&seed).unwrap();
        let vk = Secp256k1Ecdsa::derive_verification_key(&sk).unwrap();
        let message = b"Cardano transaction";

        group.bench_function("sign", |b| {
            b.iter(|| black_box(Secp256k1Ecdsa::sign(black_box(&sk), black_box(message)).unwrap()));
        });

        let signature = Secp256k1Ecdsa::sign(&sk, message).unwrap();
        group.bench_function("verify", |b| {
            b.iter(|| {
                black_box(Secp256k1Ecdsa::verify(
                    black_box(&vk),
                    black_box(message),
                    black_box(&signature),
                ))
                .unwrap()
            });
        });

        group.finish();
    }

    // Schnorr benchmarks
    {
        let mut group = c.benchmark_group("secp256k1 Schnorr");

        let seed = [42u8; 32];
        let sk = Secp256k1Schnorr::gen_key(&seed).unwrap();
        let vk = Secp256k1Schnorr::derive_verification_key(&sk).unwrap();
        let message = b"Cardano transaction";

        group.bench_function("sign", |b| {
            b.iter(|| {
                black_box(Secp256k1Schnorr::sign(black_box(&sk), black_box(message)).unwrap())
            });
        });

        let signature = Secp256k1Schnorr::sign(&sk, message).unwrap();
        group.bench_function("verify", |b| {
            b.iter(|| {
                black_box(Secp256k1Schnorr::verify(
                    black_box(&vk),
                    black_box(message),
                    black_box(&signature),
                ))
                .unwrap()
            });
        });

        group.finish();
    }
}

#[cfg(feature = "secp256k1")]
criterion_group!(
    dsign_benches,
    ed25519_keygen,
    ed25519_derive_vk,
    ed25519_sign,
    ed25519_verify,
    secp256k1_benchmarks,
);

#[cfg(not(feature = "secp256k1"))]
criterion_group!(
    dsign_benches,
    ed25519_keygen,
    ed25519_derive_vk,
    ed25519_sign,
    ed25519_verify,
);

criterion_main!(dsign_benches);
