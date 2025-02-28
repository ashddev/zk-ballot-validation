use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use zk_ballot_validation::rated_voting::max_budget::{generate_proof, verify_proof};
use bulletproofs::{BulletproofGens, PedersenGens};

fn benchmark_generate_max_budget_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("Generate Max-Budget Proof");
    let pc_gens = PedersenGens::default();
    let max_credits = 1;

    for &ballot_size in &[4, 8, 16, 32, 64, 128, 256] {
        let bp_gens = BulletproofGens::new(8, ballot_size);
        let mut ballot = vec![0; ballot_size];
        ballot[0] = 1;

        group.bench_with_input(
            BenchmarkId::from_parameter(ballot_size),
            &ballot_size,
            |b, &_size| {
                b.iter(|| {
                    let proof = generate_proof(
                        black_box(ballot.clone()),
                        black_box(max_credits),
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

fn benchmark_verify_max_budget_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("Verify Max-Budget Proof");
    let pc_gens = PedersenGens::default();
    let max_credits = 1;

    for &ballot_size in &[4, 8, 16, 32, 64, 128, 256] {
        let bp_gens = BulletproofGens::new(8, ballot_size);
        let mut ballot = vec![0; ballot_size];
        ballot[0] = 1;
        
        let (commitments, com_z, rangeproof_d) =
            generate_proof(ballot.clone(), max_credits, &pc_gens, &bp_gens);

        group.bench_with_input(
            BenchmarkId::from_parameter(ballot_size),
            &ballot_size,
            |b, &_size| {
                b.iter(|| {
                    let result = verify_proof(
                        black_box(&pc_gens),
                        black_box(&bp_gens),
                        black_box(commitments.clone()),
                        black_box(com_z),
                        black_box(rangeproof_d.clone()),
                        black_box(max_credits),
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
    targets = benchmark_generate_max_budget_proof, benchmark_verify_max_budget_proof
}

criterion_main!(benches);
