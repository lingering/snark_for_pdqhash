use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use pdqhash::regime_a::{client_submit, server_verify_and_decide, RegimeAParams, TtpSetup};

fn synth_db(n: usize, lambda: usize) -> Vec<Vec<u8>> {
    (0..n)
        .map(|i| {
            (0..lambda)
                .map(|j| ((i * 131 + j * 17 + 3) % 2) as u8)
                .collect::<Vec<_>>()
        })
        .collect()
}

fn synth_query(lambda: usize) -> Vec<u8> {
    (0..lambda).map(|i| ((i * 7 + 11) % 2) as u8).collect()
}

fn regime_a_microbenchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("regime_a_micro");

    for n in [32usize, 128, 512] {
        let params = RegimeAParams::new(16, 16, 6);
        let lambda = params.lambda();
        let db = synth_db(n, lambda);
        let query = synth_query(lambda);

        group.bench_with_input(BenchmarkId::new("ttp_setup", n), &n, |b, _| {
            b.iter(|| {
                black_box(TtpSetup::setup(
                    black_box(db.clone()),
                    black_box(params.clone()),
                    black_box(12345),
                ))
            })
        });

        let setup = TtpSetup::setup(db, params, 12345);

        group.bench_with_input(BenchmarkId::new("client_submit", n), &n, |b, _| {
            b.iter(|| {
                black_box(client_submit(
                    black_box(&setup),
                    black_box(query.clone()),
                    black_box(77),
                ))
            })
        });

        let submission = client_submit(&setup, query, 77);
        group.bench_with_input(BenchmarkId::new("server_verify", n), &n, |b, _| {
            b.iter(|| {
                black_box(server_verify_and_decide(
                    black_box(&setup),
                    black_box(&submission),
                ))
            })
        });
    }

    group.finish();
}

criterion_group!(benches, regime_a_microbenchmark);
criterion_main!(benches);
