//! VRF Performance Benchmarks
//!
//! Benchmarks for VRF Draft-03 and Draft-13 implementations.
//! 
//! Run with: cargo bench --bench vrf_benchmarks

use cardano_crypto::vrf::{VrfDraft03, VrfDraft13};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

fn vrf_draft03_keypair_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("VRF Draft-03");
    
    let seed = [42u8; 32];
    
    group.bench_function("keypair_from_seed", |b| {
        b.iter(|| {
            black_box(VrfDraft03::keypair_from_seed(black_box(&seed)))
        });
    });
    
    group.finish();
}

fn vrf_draft03_prove(c: &mut Criterion) {
    let mut group = c.benchmark_group("VRF Draft-03");
    
    let seed = [42u8; 32];
    let (sk, _pk) = VrfDraft03::keypair_from_seed(&seed);
    
    // Benchmark different message sizes
    for size in [0, 32, 64, 256, 1024].iter() {
        let message = vec![0u8; *size];
        
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::new("prove", size), size, |b, _| {
            b.iter(|| {
                black_box(VrfDraft03::prove(black_box(&sk), black_box(&message))).unwrap()
            });
        });
    }
    
    group.finish();
}

fn vrf_draft03_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("VRF Draft-03");
    
    let seed = [42u8; 32];
    let (sk, pk) = VrfDraft03::keypair_from_seed(&seed);
    
    // Benchmark different message sizes
    for size in [0, 32, 64, 256, 1024].iter() {
        let message = vec![0u8; *size];
        let proof = VrfDraft03::prove(&sk, &message).unwrap();
        
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::new("verify", size), size, |b, _| {
            b.iter(|| {
                black_box(VrfDraft03::verify(black_box(&pk), black_box(&proof), black_box(&message))).unwrap()
            });
        });
    }
    
    group.finish();
}

fn vrf_draft03_proof_to_hash(c: &mut Criterion) {
    let mut group = c.benchmark_group("VRF Draft-03");
    
    let seed = [42u8; 32];
    let (sk, _pk) = VrfDraft03::keypair_from_seed(&seed);
    let message = b"benchmark";
    let proof = VrfDraft03::prove(&sk, message).unwrap();
    
    group.bench_function("proof_to_hash", |b| {
        b.iter(|| {
            black_box(VrfDraft03::proof_to_hash(black_box(&proof))).unwrap()
        });
    });
    
    group.finish();
}

fn vrf_draft13_prove(c: &mut Criterion) {
    let mut group = c.benchmark_group("VRF Draft-13");
    
    let seed = [42u8; 32];
    let (sk, _pk) = VrfDraft13::keypair_from_seed(&seed);
    
    // Benchmark different message sizes
    for size in [0, 32, 64, 256, 1024].iter() {
        let message = vec![0u8; *size];
        
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::new("prove", size), size, |b, _| {
            b.iter(|| {
                black_box(VrfDraft13::prove(black_box(&sk), black_box(&message))).unwrap()
            });
        });
    }
    
    group.finish();
}

fn vrf_draft13_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("VRF Draft-13");
    
    let seed = [42u8; 32];
    let (sk, pk) = VrfDraft13::keypair_from_seed(&seed);
    
    // Benchmark different message sizes
    for size in [0, 32, 64, 256, 1024].iter() {
        let message = vec![0u8; *size];
        let proof = VrfDraft13::prove(&sk, &message).unwrap();
        
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::new("verify", size), size, |b, _| {
            b.iter(|| {
                black_box(VrfDraft13::verify(black_box(&pk), black_box(&proof), black_box(&message))).unwrap()
            });
        });
    }
    
    group.finish();
}

criterion_group!(
    vrf_benches,
    vrf_draft03_keypair_generation,
    vrf_draft03_prove,
    vrf_draft03_verify,
    vrf_draft03_proof_to_hash,
    vrf_draft13_prove,
    vrf_draft13_verify,
);

criterion_main!(vrf_benches);
