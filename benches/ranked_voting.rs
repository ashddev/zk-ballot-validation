use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use zk_ballot_validation::ranked_voting::shuffle_proof::{generate_crs, generate_shuffle_proof, verify_shuffle_proof};
use zk_ballot_validation::utils::ranked::find_permutation;

fn benchmark_generate_shuffle_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("Generate Shuffle Proof");

    for &vec_size in &[4, 8, 16, 32, 64, 128, 256] {
        let vec_a_u32: Vec<u32> = (0..vec_size).map(|x| x as u32).collect();
        let vec_a_permuted: Vec<u32> = vec_a_u32.iter().cloned().rev().collect();

        if let Some(permutation) = find_permutation(&vec_a_u32, &vec_a_permuted) {
            let crs = generate_crs(vec_size, vec_size);

            group.bench_with_input(
                BenchmarkId::from_parameter(vec_size),
                &vec_size,
                |b, &_size| {
                    b.iter(|| {
                        let proof = generate_shuffle_proof(
                            black_box(vec_a_u32.clone()),
                            black_box(vec_a_permuted.clone()),
                            black_box(permutation.clone()),
                            &crs,
                        );
                        black_box(proof);
                    });
                },
            );
        }
    }

    group.finish();
}

fn benchmark_verify_shuffle_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("Verify Shuffle Proof");

    for &vec_size in &[4, 8, 16, 32, 64, 128, 256] {
        let vec_a_u32: Vec<u32> = (0..vec_size).map(|x| x as u32).collect();
        let vec_a_permuted: Vec<u32> = vec_a_u32.iter().cloned().rev().collect();

        if let Some(permutation) = find_permutation(&vec_a_u32, &vec_a_permuted) {
            let crs = generate_crs(vec_size, vec_size);
            let proof = generate_shuffle_proof(vec_a_u32.clone(), vec_a_permuted.clone(), permutation, &crs);

            group.bench_with_input(
                BenchmarkId::from_parameter(vec_size),
                &vec_size,
                |b, &_size| {
                    b.iter(|| {
                        let result = verify_shuffle_proof(
                            black_box(&proof),
                            black_box(&crs),
                            black_box(vec_a_u32.clone()),
                            black_box(vec_size),
                        );
                        black_box(result);
                    });
                },
            );
        }
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
    targets = benchmark_generate_shuffle_proof, benchmark_verify_shuffle_proof
}

criterion_main!(benches);
