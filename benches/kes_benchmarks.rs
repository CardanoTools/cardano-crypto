//! KES Performance Benchmarks
//!
//! Benchmarks for Key Evolving Signature implementations.
//!
//! Run with: cargo bench --bench kes_benchmarks

use cardano_crypto::kes::{KesAlgorithm, Sum2Kes, Sum6Kes};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

fn kes_sum2_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("KES Sum2");

    let seed = [42u8; 32];

    group.bench_function("gen_key_from_seed", |b| {
        b.iter(|| black_box(Sum2Kes::gen_key_kes_from_seed_bytes(black_box(&seed))).unwrap());
    });

    group.finish();
}

fn kes_sum2_derive_vk(c: &mut Criterion) {
    let mut group = c.benchmark_group("KES Sum2");

    let seed = [42u8; 32];
    let sk = Sum2Kes::gen_key_kes_from_seed_bytes(&seed).unwrap();

    group.bench_function("derive_verification_key", |b| {
        b.iter(|| black_box(Sum2Kes::derive_verification_key(black_box(&sk))).unwrap());
    });

    group.finish();
}

fn kes_sum2_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("KES Sum2");

    let seed = [42u8; 32];
    let sk = Sum2Kes::gen_key_kes_from_seed_bytes(&seed).unwrap();

    // Benchmark different message sizes
    for size in [32, 64, 256, 1024, 4096].iter() {
        let message = vec![0u8; *size];

        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::new("sign", size), size, |b, _| {
            b.iter(|| {
                black_box(Sum2Kes::sign_kes(
                    black_box(&()),
                    black_box(0),
                    black_box(&message),
                    black_box(&sk),
                ))
                .unwrap()
            });
        });
    }

    group.finish();
}

fn kes_sum2_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("KES Sum2");

    let seed = [42u8; 32];
    let sk = Sum2Kes::gen_key_kes_from_seed_bytes(&seed).unwrap();
    let vk = Sum2Kes::derive_verification_key(&sk).unwrap();

    // Benchmark different message sizes
    for size in [32, 64, 256, 1024, 4096].iter() {
        let message = vec![0u8; *size];
        let signature = Sum2Kes::sign_kes(&(), 0, &message, &sk).unwrap();

        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::new("verify", size), size, |b, _| {
            b.iter(|| {
                black_box(Sum2Kes::verify_kes(
                    black_box(&()),
                    black_box(&vk),
                    black_box(0),
                    black_box(&message),
                    black_box(&signature),
                ))
                .unwrap()
            });
        });
    }

    group.finish();
}

fn kes_sum2_update(c: &mut Criterion) {
    let mut group = c.benchmark_group("KES Sum2");

    let seed = [42u8; 32];

    group.bench_function("update_kes", |b| {
        b.iter_batched(
            || Sum2Kes::gen_key_kes_from_seed_bytes(&seed).unwrap(),
            |sk| {
                black_box(Sum2Kes::update_kes(
                    black_box(&()),
                    black_box(sk),
                    black_box(0),
                ))
                .unwrap()
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.finish();
}

fn kes_sum6_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("KES Sum6");

    let seed = [42u8; 32];

    group.bench_function("gen_key_from_seed", |b| {
        b.iter(|| black_box(Sum6Kes::gen_key_kes_from_seed_bytes(black_box(&seed))).unwrap());
    });

    group.finish();
}

fn kes_sum6_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("KES Sum6");

    let seed = [42u8; 32];
    let sk = Sum6Kes::gen_key_kes_from_seed_bytes(&seed).unwrap();
    let message = b"Cardano block header";

    group.bench_function("sign", |b| {
        b.iter(|| {
            black_box(Sum6Kes::sign_kes(
                black_box(&()),
                black_box(0),
                black_box(message),
                black_box(&sk),
            ))
            .unwrap()
        });
    });

    group.finish();
}

fn kes_sum6_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("KES Sum6");

    let seed = [42u8; 32];
    let sk = Sum6Kes::gen_key_kes_from_seed_bytes(&seed).unwrap();
    let vk = Sum6Kes::derive_verification_key(&sk).unwrap();
    let message = b"Cardano block header";
    let signature = Sum6Kes::sign_kes(&(), 0, message, &sk).unwrap();

    group.bench_function("verify", |b| {
        b.iter(|| {
            black_box(Sum6Kes::verify_kes(
                black_box(&()),
                black_box(&vk),
                black_box(0),
                black_box(message),
                black_box(&signature),
            ))
            .unwrap()
        });
    });

    group.finish();
}

fn kes_sum6_update(c: &mut Criterion) {
    let mut group = c.benchmark_group("KES Sum6");

    let seed = [42u8; 32];

    group.bench_function("update_kes", |b| {
        b.iter_batched(
            || Sum6Kes::gen_key_kes_from_seed_bytes(&seed).unwrap(),
            |sk| {
                black_box(Sum6Kes::update_kes(
                    black_box(&()),
                    black_box(sk),
                    black_box(0),
                ))
                .unwrap()
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.finish();
}

criterion_group!(
    kes_benches,
    kes_sum2_keygen,
    kes_sum2_derive_vk,
    kes_sum2_sign,
    kes_sum2_verify,
    kes_sum2_update,
    kes_sum6_keygen,
    kes_sum6_sign,
    kes_sum6_verify,
    kes_sum6_update,
);

criterion_main!(kes_benches);
