extern crate rand;
use rand::thread_rng;

extern crate curve25519_dalek_ng;
use curve25519_dalek_ng::{ristretto::{CompressedRistretto, RistrettoPoint}, scalar::Scalar};

extern crate merlin;
use merlin::Transcript;

extern crate bulletproofs;
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};

pub fn generate_proof(
    ballot: Vec<u64>,
    max_credits: u64,
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
) -> (Vec<RistrettoPoint>, RistrettoPoint, (RangeProof, CompressedRistretto)) {
    let ballot_blindings: Vec<Scalar> = (0..ballot.len())
        .map(|_| Scalar::random(&mut thread_rng()))
        .collect();

    let commitments: Vec<RistrettoPoint> = ballot
        .iter()
        .zip(ballot_blindings.iter())
        .map(|(&b, &blinding)| pc_gens.commit(Scalar::from(b), blinding))
        .collect();

    let z: u64 = ballot.iter().sum();
    let z_blinding = ballot_blindings.iter().copied().reduce(|a, b| a + b).unwrap();
    let com_z: RistrettoPoint = pc_gens.commit(Scalar::from(z), z_blinding);

    let d: u64 = max_credits - z;
    let d_blinding= -z_blinding;
    
    let mut prover_transcript = Transcript::new(b"max budget rated voting");

    let rangeproof_d: (RangeProof, CompressedRistretto) = RangeProof::prove_single(
        &bp_gens,
        &pc_gens,
        &mut prover_transcript,
        d,
        &d_blinding,
        8,
    )
    .expect("Failed to create aggregated rangeproof");

    (commitments, com_z, rangeproof_d)
}

pub fn verify_proof(
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    ballot_commitments: Vec<RistrettoPoint>,
    com_z: RistrettoPoint,
    rangeproof_d: (RangeProof, CompressedRistretto),
    max_credits: u64
) -> bool {
    let aggregated_commitment: RistrettoPoint = ballot_commitments.iter().fold(RistrettoPoint::default(), |acc, &commit| acc + commit );
    if aggregated_commitment != com_z {
        println!("Commitment aggregation failed!");
        return false;
    }

    let com_max_credits: RistrettoPoint = pc_gens.commit(Scalar::from(max_credits), Scalar::zero());
    if rangeproof_d.1 != (com_max_credits - com_z).compress() {
        println!("Commitment consistency for D failed!");
        return false;
    }

    let mut verifier_transcript = Transcript::new(b"max budget rated voting");
    if rangeproof_d.0
        .verify_single(&bp_gens, &pc_gens, &mut verifier_transcript, &rangeproof_d.1, 8)
        .is_err()
    {
        println!("Range proof verification failed!");
        return false;
    }

    println!("Ballot verification successful!");
    true
}