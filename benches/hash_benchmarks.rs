//! Hash Function Performance Benchmarks
//!
//! Benchmarks for Blake2b and SHA hash implementations.
//!
//! Run with: cargo bench --bench hash_benchmarks

use cardano_crypto::hash::{Blake2b224, Blake2b256, Blake2b512, HashAlgorithm};
use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};

fn blake2b224_hash(c: &mut Criterion) {
    let mut group = c.benchmark_group("Blake2b-224");

    // Benchmark different data sizes
    for size in [32, 64, 128, 256, 512, 1024, 4096, 16384].iter() {
        let data = vec![0u8; *size];

        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| black_box(Blake2b224::hash(black_box(&data))));
        });
    }

    group.finish();
}

fn blake2b256_hash(c: &mut Criterion) {
    let mut group = c.benchmark_group("Blake2b-256");

    // Benchmark different data sizes
    for size in [32, 64, 128, 256, 512, 1024, 4096, 16384].iter() {
        let data = vec![0u8; *size];

        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| black_box(Blake2b256::hash(black_box(&data))));
        });
    }

    group.finish();
}

fn blake2b512_hash(c: &mut Criterion) {
    let mut group = c.benchmark_group("Blake2b-512");

    // Benchmark different data sizes
    for size in [32, 64, 128, 256, 512, 1024, 4096, 16384].iter() {
        let data = vec![0u8; *size];

        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| black_box(Blake2b512::hash(black_box(&data))));
        });
    }

    group.finish();
}

fn blake2b256_hash_concat(c: &mut Criterion) {
    let mut group = c.benchmark_group("Blake2b-256");

    let left = Blake2b256::hash(b"left branch");
    let right = Blake2b256::hash(b"right branch");

    group.bench_function("hash_concat", |b| {
        b.iter(|| black_box(Blake2b256::hash_concat(black_box(&left), black_box(&right))));
    });

    group.finish();
}

criterion_group!(
    hash_benches,
    blake2b224_hash,
    blake2b256_hash,
    blake2b512_hash,
    blake2b256_hash_concat,
);

criterion_main!(hash_benches);
