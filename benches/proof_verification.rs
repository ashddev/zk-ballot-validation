use bulletproofs::PedersenGens;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use zk_ballot_validation::ballot_validation::rated_voting::no_budget;
use zk_ballot_validation::ballot_validation::rated_voting::max_budget;
use zk_ballot_validation::ballot_validation::ranked_voting;

fn benchmark_proof_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("Verify");

    let pc_gens = PedersenGens::default();
    let range = (-10, 10);
    let max_credits = 1;

    for &ballot_size in &[4, 8, 16, 32, 64, 128, 256] {
        let bp_params_no_budget = no_budget::setup(range, ballot_size, Some(pc_gens)).expect("Failed to set up no-budget voting parameters");
        let ballot_no_budget: Vec<i64> = (0..ballot_size).map(|x| (x as i64 % 20) - 10).collect();
        let validity_proof = no_budget::generate_vote(ballot_no_budget.clone(), &bp_params_no_budget).expect("Failed to generate no-budget voting proof");

        group.bench_with_input(
            BenchmarkId::new("No Budget Rated Voting", ballot_size),
            &ballot_size,
            |b, &_size| {
                b.iter(|| {
                    let result = no_budget::verify_proof(
                        &bp_params_no_budget,
                        black_box(validity_proof.clone()),
                    );
                    black_box(result);
                });
            },
        );

        let bp_params_max_budget = max_budget::setup(max_credits, ballot_size, Some(pc_gens)).expect("Failed to set up max-budget voting parameters");
        let mut ballot_max_budget = vec![0; ballot_size];
        ballot_max_budget[0] = 1;
        let validity_proof = max_budget::generate_vote(&bp_params_max_budget, ballot_max_budget.clone()).expect("Failed to generate max-budget voting proof");

        group.bench_with_input(
            BenchmarkId::new("Max Budget Rated Voting", ballot_size),
            &ballot_size,
            |b, &_size| {
                b.iter(|| {
                    let result = max_budget::verify_proof(
                        &bp_params_max_budget,
                        black_box(validity_proof.clone()),
                    );
                    black_box(result);
                });
            },
        );

        let vec_a: Vec<u32> = (0..ballot_size).map(|x| x as u32).collect();
        let vec_a_permuted: Vec<u32> = vec_a.iter().cloned().rev().collect();
        let setup_params = ranked_voting::setup(ballot_size);
        let proof = ranked_voting::generate_vote(&vec_a_permuted, &setup_params).expect("Failed to generate ranked voting proof");

        group.bench_with_input(
            BenchmarkId::new("Ranked Voting", ballot_size),
            &ballot_size,
            |b, &_size| {
                b.iter(|| {
                    let result = ranked_voting::verify_proof(
                        black_box(&proof),
                        black_box(&setup_params),
                    );
                    black_box(result);
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
    targets = benchmark_proof_verification
}

criterion_main!(benches);
