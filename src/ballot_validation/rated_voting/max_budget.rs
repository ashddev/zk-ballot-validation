use rand::thread_rng;
use merlin::Transcript;
use curve25519_dalek_ng::{ristretto::{CompressedRistretto, RistrettoPoint}, scalar::Scalar};
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};

pub struct MaxCredit {
    commitment: RistrettoPoint,
    value: u64,
}

impl MaxCredit {
    pub fn new(pc_gens: &PedersenGens, value: u64) -> Self {
        let blinding_factor: Scalar = Scalar::zero();
        let commitment: RistrettoPoint = pc_gens.commit(Scalar::from(value), blinding_factor);
        MaxCredit {
            commitment,
            value,
        }
    }
}

pub struct SetupParameters {
    pc_gens: PedersenGens,
    bp_gens: BulletproofGens,
    max_credit: MaxCredit,
}

#[derive(Clone)]
pub struct MaxBudgetRatedVotingProof {
    votes_proof: (RangeProof, Vec<CompressedRistretto>), 
    com_z: RistrettoPoint, 
    rangeproof_d: (RangeProof, CompressedRistretto)
}


pub fn setup(max_credits: u64, ballot_size: usize, pc_gens: Option<PedersenGens>) -> SetupParameters {
    let pc_gens: PedersenGens = pc_gens.unwrap_or_else(PedersenGens::default);
    let bp_gens: BulletproofGens = BulletproofGens::new(8, ballot_size);
    let max_credit: MaxCredit = MaxCredit::new(&pc_gens, max_credits);

    SetupParameters {
        pc_gens,
        bp_gens,
        max_credit
    }
}

pub fn generate_proof(
    setup_params: &SetupParameters,
    ballot: Vec<u64>,
) -> MaxBudgetRatedVotingProof {
    let ballot_blindings: Vec<Scalar> = (0..ballot.len())
        .map(|_| Scalar::random(&mut thread_rng()))
        .collect();

    let rangeproof_votes: (RangeProof, Vec<CompressedRistretto>) = RangeProof::prove_multiple(
        &setup_params.bp_gens,
        &setup_params.pc_gens,
        &mut Transcript::new(b"max budget rated voting votes"),
        &ballot,
        &ballot_blindings,
        8,
    )
    .expect("Failed to create aggregated rangeproof");

    let z: u64 = ballot.iter().sum();
    let z_blinding: Scalar = ballot_blindings.iter().copied().reduce(|a, b| a + b).unwrap();
    let com_z: RistrettoPoint = setup_params.pc_gens.commit(Scalar::from(z), z_blinding);

    let d: u64 = setup_params.max_credit.value - z;
    let d_blinding: Scalar = -z_blinding;
    
    let rangeproof_d: (RangeProof, CompressedRistretto) = RangeProof::prove_single(
        &setup_params.bp_gens,
        &setup_params.pc_gens,
        &mut Transcript::new(b"max budget rated voting"),
        d,
        &d_blinding,
        8,
    )
    .expect("Failed to create rangeproof");

    MaxBudgetRatedVotingProof {
        votes_proof: rangeproof_votes, 
        com_z: com_z, 
        rangeproof_d: rangeproof_d
    }
}

pub fn verify_proof(
    setup_params: &SetupParameters,
    validity_proof: MaxBudgetRatedVotingProof,
) -> bool {
    let vote_proof: RangeProof = validity_proof.votes_proof.0;
    let vote_commitments: Vec<CompressedRistretto> = validity_proof.votes_proof.1;

    if vote_proof
        .verify_multiple(
            &setup_params.bp_gens, 
            &setup_params.pc_gens, 
            &mut Transcript::new(b"max budget rated voting votes"), 
            &vote_commitments, 
            8
        )
        .is_err()
    {
        return false;
    }

    let aggregated_commitment: RistrettoPoint = vote_commitments.iter()
    .map(|c| c.decompress().unwrap())
    .fold(RistrettoPoint::default(), |acc, commit| acc + commit);

    if aggregated_commitment != validity_proof.com_z {
        return false;
    }

    if validity_proof.rangeproof_d.1 != (setup_params.max_credit.commitment - validity_proof.com_z).compress() {
        return false;
    }

    if validity_proof.rangeproof_d.0
        .verify_single(&setup_params.bp_gens, &setup_params.pc_gens, &mut Transcript::new(b"max budget rated voting"), &validity_proof.rangeproof_d.1, 8)
        .is_err()
    {
        return false;
    }

    true
}