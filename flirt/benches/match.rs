//! benchmark building a signature set and matching it, using the
//! FLARE MSVC runtime signatures (~210k signatures) and some real code.
use std::path::PathBuf;

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use lancelot_flirt::{sig, FlirtSignatureSet};

fn resource(name: &str) -> Vec<u8> {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("../core/resources/test");
    path.push(name);
    std::fs::read(&path).unwrap_or_else(|_| panic!("missing {}", path.display()))
}

fn benchmark(c: &mut Criterion) {
    let buf = resource("cfg/sigs/flare_msvc_rtf_32_64.sig");
    let sigs = sig::parse(&buf).unwrap();

    let mut group = c.benchmark_group("flirt");
    group.sample_size(10);

    group.bench_function("parse", |b| b.iter(|| sig::parse(black_box(&buf)).unwrap()));

    group.bench_function("with_signatures", |b| {
        b.iter_batched(
            || sigs.clone(),
            FlirtSignatureSet::with_signatures,
            criterion::BatchSize::LargeInput,
        )
    });

    // match at each of the first 64k offsets of a binary.
    // most offsets fail after a few bytes, the same as most function starts.
    let set = FlirtSignatureSet::with_signatures(sigs);
    let code = resource("mimikatz.exe_");
    group.bench_function("match", |b| {
        b.iter(|| {
            let mut count = 0;
            for i in 0..0x10000 {
                count += set.r#match(black_box(&code[i..i + 0x400])).len();
            }
            count
        })
    });

    group.finish();
}

criterion_group!(benches, benchmark);
criterion_main!(benches);
