use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use zk_ballot_validation::rated_voting::no_budget::{generate_proof, verify_proof};
use bulletproofs::{BulletproofGens, PedersenGens};

fn benchmark_generate_no_budget_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("Generate No-Budget Proof");
    let pc_gens = PedersenGens::default();
    let range = (-10, 10);

    for &ballot_size in &[4, 8, 16, 32, 64, 128, 256] {
        let bp_gens = BulletproofGens::new(8, ballot_size);
        let ballot: Vec<i64> = (0..ballot_size).map(|x| (x as i64 % 20) - 10).collect();

        group.bench_with_input(
            BenchmarkId::from_parameter(ballot_size),
            &ballot_size,
            |b, &_size| {
                b.iter(|| {
                    let proof = generate_proof(
                        black_box(ballot.clone()),
                        black_box(range),
                        black_box(&pc_gens),
                        black_box(&bp_gens),
                    );
                    black_box(proof);
                });
            },
        );
    }

    group.finish();
}

fn benchmark_verify_no_budget_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("Verify No-Budget Proof");
    let pc_gens = PedersenGens::default();
    let range = (-10, 10);

    for &ballot_size in &[4, 8, 16, 32, 64, 128, 256] {
        let bp_gens = BulletproofGens::new(8, ballot_size);
        let ballot: Vec<i64> = (0..ballot_size).map(|x| (x as i64 % 20) - 10).collect();
        let (v_commitments, rangeproof) = generate_proof(ballot.clone(), range, &pc_gens, &bp_gens);

        group.bench_with_input(
            BenchmarkId::from_parameter(ballot_size),
            &ballot_size,
            |b, &_size| {
                b.iter(|| {
                    let result = verify_proof(
                        black_box(&pc_gens),
                        black_box(&bp_gens),
                        black_box(v_commitments.clone()),
                        black_box(rangeproof.clone()),
                        black_box(range),
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
    targets = benchmark_generate_no_budget_proof, benchmark_verify_no_budget_proof
}

criterion_main!(benches);
