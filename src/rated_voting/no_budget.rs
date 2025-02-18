extern crate rand;
use rand::thread_rng;

extern crate curve25519_dalek_ng;
use curve25519_dalek_ng::{ristretto::CompressedRistretto, scalar::Scalar};

extern crate merlin;
use merlin::Transcript;

extern crate bulletproofs;
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};

pub fn generate_proof(
    ballot: Vec<i64>,
    range: (i64, i64),
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
) -> (Vec<CompressedRistretto>, (RangeProof, Vec<CompressedRistretto>)) {
    let choice_space_cardinality: u64 = (range.1 - range.0).abs().try_into().unwrap();

    let shifted_ballot: Vec<u64> = ballot.iter().map(|&v| shift_vote(v, choice_space_cardinality)).collect();

    let blindings: Vec<Scalar> = (0..ballot.len()).map(|_| Scalar::random(&mut thread_rng())).collect();
    let v_commitments : Vec<CompressedRistretto> = shifted_ballot
        .iter()
        .zip(blindings.iter())
        .map(|(&v, &blinding)| pc_gens.commit(Scalar::from(v), blinding).compress())
        .collect();

    let d_values: Vec<u64> = shifted_ballot.iter().map(|&v|choice_space_cardinality - v).collect();
    let d_blindings: Vec<Scalar> = blindings.iter().map(|&r| -r).collect();

    let mut prover_transcript = Transcript::new(b"no budget rated voting");

    let rangeproof: (RangeProof, Vec<CompressedRistretto>) = RangeProof::prove_multiple(
        &bp_gens,
        &pc_gens,
        &mut prover_transcript,
        &d_values,
        &d_blindings,
        8,
    )
    .expect("Failed to create aggregated rangeproof");

    (v_commitments, rangeproof)
}

pub fn verify_proof(
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    v_commitments: Vec<CompressedRistretto>,
    rangeproof: (RangeProof, Vec<CompressedRistretto>),
    range: (i64, i64),
) -> bool {
    let choice_space_cardinality: u64 = (range.1 - range.0).abs().try_into().unwrap();

    let d_commitments = rangeproof.1;
    let proof = rangeproof.0;

    if proof
        .verify_multiple(
            &bp_gens, 
            &pc_gens, 
            &mut Transcript::new(b"no budget rated voting"), 
            &d_commitments, 
            8
        )
        .is_err()
    {
        println!("Range proof verification failed!");
        return false;
    }

    for (d_commitment, v_commitment) in d_commitments.iter().zip(v_commitments.iter()) {
        let com_max = pc_gens.commit(Scalar::from(choice_space_cardinality), Scalar::zero());
        if *d_commitment != (com_max - v_commitment.decompress().unwrap()).compress() {
            println!("Commitment consistency failed!");
            return false;
        }
    }

    println!("Proof verification successful!");
    true
}

fn shift_vote(value: i64, choice_space_cardinality:u64) -> u64 {
    (value + (choice_space_cardinality as i64/2)) as u64
}