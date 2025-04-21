use bulletproofs::PedersenGens;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use zk_ballot_validation::ballot_validation::rated_voting::no_budget;
use zk_ballot_validation::ballot_validation::rated_voting::max_budget;
use zk_ballot_validation::ballot_validation::ranked_voting;

fn benchmark_proof_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("Proof Generation");

    let pc_gens = PedersenGens::default();
    let range = (-10, 10);
    let max_credits = 1;

    for &ballot_size in &[4, 8, 16, 32, 64, 128, 256] {
        let bp_params_no_budget = no_budget::setup(range, ballot_size, Some(pc_gens)).expect("Failed to set up no-budget voting parameters");
        let ballot_no_budget: Vec<i64> = (0..ballot_size).map(|x| (x as i64 % 20) - 10).collect();

        group.bench_with_input(
            BenchmarkId::new("No Budget Rated Voting", ballot_size),
            &ballot_size,
            |b, &_size| {
                b.iter(|| {
                    let proof = no_budget::generate_proof(
                        black_box(ballot_no_budget.clone()),
                        &bp_params_no_budget
                    );
                    let _ = black_box(proof);
                });
            },
        );

        let bp_params_max_budget = max_budget::setup(max_credits, ballot_size, Some(pc_gens)).expect("Failed to set up max-budget voting parameters");
        let mut ballot_max_budget = vec![0; ballot_size];
        ballot_max_budget[0] = 1;

        group.bench_with_input(
            BenchmarkId::new("Max Budget Rated Voting", ballot_size),
            &ballot_size,
            |b, &_size| {
                b.iter(|| {
                    let proof = max_budget::generate_proof(
                        &bp_params_max_budget,
                        black_box(ballot_max_budget.clone()),
                    );
                    let _ = black_box(proof);
                });
            },
        );

        let vec_a: Vec<u32> = (0..ballot_size).map(|x| x as u32).collect();
        let vec_a_permuted: Vec<u32> = vec_a.iter().cloned().rev().collect();
        let setup_params = ranked_voting::setup(ballot_size, vec_a);

        group.bench_with_input(
            BenchmarkId::new("Ranked Voting", ballot_size),
            &ballot_size,
            |b, &_size| {
                b.iter(|| {
                    let proof = ranked_voting::generate_proof(
                        black_box(&vec_a_permuted),
                        &setup_params,
                    );
                    let _ = black_box(proof);
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
    targets = benchmark_proof_generation
}

criterion_main!(benches);
