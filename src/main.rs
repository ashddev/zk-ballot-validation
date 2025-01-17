extern crate rand;
use rand::thread_rng;

extern crate curve25519_dalek_ng;
use curve25519_dalek_ng::scalar::Scalar;

extern crate merlin;
use merlin::Transcript;

extern crate bulletproofs;
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};

fn main() {
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(8, 4);

    let votes: Vec<i32> = vec![0, 199, 55];

    let votes_u64: Vec<u64> = votes.iter().map(|&v| v as u64).collect();
    let sum: u64 = votes_u64.iter().sum();
    
    let mut rng = thread_rng();
    let blindings: Vec<Scalar> = (0..votes.len() + 1).map(|_| Scalar::random(&mut rng)).collect();

    let mut prover_transcript = Transcript::new(b"multi-vote test");

    let all_values = votes_u64.iter().chain(std::iter::once(&sum)).cloned().collect::<Vec<u64>>();
    let all_blindings = blindings.clone();

    let (proof, committed_values) = RangeProof::prove_multiple(
        &bp_gens,
        &pc_gens,
        &mut prover_transcript,
        &all_values,
        &all_blindings,
        8, // 8 bits for each value
    )
    .expect("Failed to create aggregated rangeproof");

    println!("Aggregated rangeproof created successfully!");
    println!("Committed values: {:?}", committed_values);

    let mut verifier_transcript = Transcript::new(b"multi-vote test");
    
    if proof
        .verify_multiple(&bp_gens, &pc_gens, &mut verifier_transcript, &committed_values, 8)
        .is_ok()
    {
        println!("Aggregated rangeproof verified successfully!");
    } else {
        println!("Aggregated rangeproof verification failed");
    }

}
