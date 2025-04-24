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
    ballot_size: usize,
    max_credit: MaxCredit,
}

#[derive(Clone)] 
pub struct MaxBudgetRatedVotingProof {
    votes_proof: (RangeProof, Vec<CompressedRistretto>), 
    com_z: RistrettoPoint, 
    rangeproof_d: (RangeProof, CompressedRistretto)
}


pub fn setup(max_credits: u64, ballot_size: usize, pc_gens: Option<PedersenGens>) -> Result<SetupParameters, String> {
    if !ballot_size.is_power_of_two() {
        return Err("ballot_size must be a power of two".into());
    }

    let pc_gens: PedersenGens = pc_gens.unwrap_or_else(PedersenGens::default);
    let bp_gens: BulletproofGens = BulletproofGens::new(8, ballot_size);
    let max_credit: MaxCredit = MaxCredit::new(&pc_gens, max_credits);

    Ok(SetupParameters {
        pc_gens,
        bp_gens,
        ballot_size,
        max_credit
    })
}

pub fn generate_vote(
    setup_params: &SetupParameters,
    ballot: Vec<u64>,
) -> Result<MaxBudgetRatedVotingProof, String> {
    if ballot.len() != setup_params.ballot_size {
        return Err(format!(
            "Ballot length {} does not match expected number of candidates {}",
            ballot.len(),
            setup_params.ballot_size
        ));
    }  

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
    .map_err(|e| format!("Failed to create aggregated rangeproof: {:?}", e))?;

    let z: u64 = ballot
    .iter()
    .try_fold(0u64, |acc, &val| acc.checked_add(val))
    .ok_or_else(|| "Overflow while summing ballot values".to_string())?;
    let z_blinding: Scalar = ballot_blindings.iter().copied().reduce(|a, b| a + b).unwrap();
    let com_z: RistrettoPoint = setup_params.pc_gens.commit(Scalar::from(z), z_blinding);

    let d = setup_params
    .max_credit
    .value
    .checked_sub(z)
    .ok_or_else(|| format!("Ballot sum {} exceeds max credit {}", z, setup_params.max_credit.value))?;
    let d_blinding: Scalar = -z_blinding;
    
    let rangeproof_d: (RangeProof, CompressedRistretto) = RangeProof::prove_single(
        &setup_params.bp_gens,
        &setup_params.pc_gens,
        &mut Transcript::new(b"max budget rated voting"),
        d,
        &d_blinding,
        8,
    )
    .map_err(|e| format!("Failed to create rangeproof: {:?}", e))?;

    Ok(MaxBudgetRatedVotingProof {
        votes_proof: rangeproof_votes, 
        com_z: com_z, 
        rangeproof_d: rangeproof_d
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    fn basic_setup(ballot_size: usize, max_credit: u64) -> SetupParameters {
        setup(max_credit, ballot_size, None).unwrap()
    }

    #[test]
    fn test_valid_proof() {
        let setup_params = basic_setup(4, 20);
        let ballot = vec![5, 3, 6, 6];

        let proof = generate_vote(&setup_params, ballot).expect("Should generate proof");
        assert!(verify_proof(&setup_params, proof), "Valid proof should verify");
    }

    #[test]
    fn test_overspending_fails() {
        let setup_params = basic_setup(4, 15);
        let ballot = vec![10, 5, 3, 0];

        let result = generate_vote(&setup_params, ballot);
        assert!(result.is_err(), "Should fail to generate proof for overspending ballot");
    }

    #[test]
    fn test_wrong_commitment_fails() {
        let setup_params = basic_setup(2, 10);
        let ballot = vec![5, 5];

        let mut proof = generate_vote(&setup_params, ballot).expect("Should generate proof");

        proof.votes_proof.1[0] = setup_params.pc_gens.commit(Scalar::from(999u64), Scalar::zero()).compress();

        assert!(!verify_proof(&setup_params, proof), "Tampered commitment should not verify");
    }

    #[test]
    fn test_mismatched_ballot_length() {
        let setup_params = basic_setup(4, 10);
        let ballot = vec![3, 4];

        let result = generate_vote(&setup_params, ballot);
        assert!(result.is_err(), "Should fail when ballot length doesn't match setup");
    }

    #[test]
    fn test_commitment_equality_check() {
        let setup_params = basic_setup(2, 8);
        let ballot = vec![4, 4];

        let proof = generate_vote(&setup_params, ballot).unwrap();
        let expected_sum_commitment = proof.votes_proof.1.iter()
            .map(|c| c.decompress().unwrap())
            .fold(RistrettoPoint::default(), |acc, c| acc + c);

        assert_eq!(expected_sum_commitment, proof.com_z, "Aggregated commitment should match com_z");
    }
}
