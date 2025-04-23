use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use zk_ballot_validation::ballot_validation::{rated_voting, ranked_voting};

fn benchmark_setup(c: &mut Criterion) {
    let mut group = c.benchmark_group("Setup");

    let range = (-10, 10);
    let max_credits = 1;

    for &ballot_size in &[4, 8, 16, 32, 64, 128, 256] {
        group.bench_with_input(
            BenchmarkId::new("No Budget Rated Voting", ballot_size),
            &ballot_size,
            |b, &_size| {
                b.iter(|| {
                    let setup_params = rated_voting::no_budget::setup(range, ballot_size, None).expect("Failed to set up no-budget voting parameters");
                    let _ = black_box(setup_params);
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("Max Budget Rated Voting", ballot_size),
            &ballot_size,
            |b, &_size| {
                b.iter(|| {
                    let setup_params = rated_voting::max_budget::setup(max_credits, ballot_size, None).expect("Failed to set up max-budget voting parameters");
                    let _ = black_box(setup_params);
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("Ranked Voting", ballot_size),
            &ballot_size,
            |b, &_size| {
                b.iter(|| {
                    let setup_params = ranked_voting::setup(ballot_size);
                    let _ = black_box(setup_params);
                });
            },
        );
    }

    group.finish();
}

fn configure_criterion() -> Criterion {
    Criterion::default()
        .sample_size(10)
        .noise_threshold(0.05)
        .significance_level(0.05)
        .confidence_level(0.95)
}

criterion_group! {
    name = benches;
    config = configure_criterion();
    targets = benchmark_setup
}

criterion_main!(benches);
