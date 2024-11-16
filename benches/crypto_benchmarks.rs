//! Performance benchmarks for cryptographic operations
//! Location: benches/crypto_benchmarks.rs

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use mcafee::crypto::{
    vdf::temporal::TemporalVDF,
    sharing::ThreePartySecretSharing,
};

fn bench_vdf(c: &mut Criterion) {
    let mut group = c.benchmark_group("VDF Operations");

    let sizes = [1024, 4096, 16384, 65536];
    for size in sizes {
        group.bench_with_input(
            BenchmarkId::new("iterate", size),
            &size,
            |b, &size| {
                let config = Default::default();
                let mut vdf = TemporalVDF::new(config);
                let input = vec![0u8; size];
                vdf.initialize(&input).unwrap();

                b.iter(|| {
                    vdf.iterate().unwrap();
                });
            }
        );
    }
    group.finish();
}

fn bench_secret_sharing(c: &mut Criterion) {
    let mut group = c.benchmark_group("Secret Sharing");

    let sizes = [1024, 4096, 16384, 65536];
    for size in sizes {
        // Benchmark splitting
        group.bench_with_input(
            BenchmarkId::new("split", size),
            &size,
            |b, &size| {
                let mut sharing = ThreePartySecretSharing::default();
                let secret = vec![0u8; size];

                b.iter(|| {
                    black_box(sharing.split(black_box(&secret)).unwrap());
                });
            }
        );

        // Benchmark reconstruction
        group.bench_with_input(
            BenchmarkId::new("reconstruct", size),
            &size,
            |b, &size| {
                let mut sharing = ThreePartySecretSharing::default();
                let secret = vec![0u8; size];
                let shares = sharing.split(&secret).unwrap();

                b.iter(|| {
                    black_box(sharing.reconstruct(black_box(&shares)).unwrap());
                });
            }
        );
    }
    group.finish();
}

criterion_group!(benches, bench_vdf, bench_secret_sharing);
criterion_main!(benches);