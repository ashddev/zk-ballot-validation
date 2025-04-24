use rand::thread_rng;
use merlin::Transcript;
use curve25519_dalek_ng::{ristretto::{CompressedRistretto, RistrettoPoint}, scalar::Scalar};
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};

pub struct SetupParameters {
    pc_gens: PedersenGens,
    bp_gens: BulletproofGens,
    range: (i64, i64),
    shifted_upperbound: RistrettoPoint
}

#[derive(Clone)] 
pub struct NoBudgetRatedVotingProof {
    shifted_ballot_committments: Vec<CompressedRistretto>,
    aggregated_rangeproof: (RangeProof, Vec<CompressedRistretto>)
}

pub fn setup(range: (i64, i64), ballot_size: usize, pc_gens: Option<PedersenGens>) -> Result<SetupParameters, String> {
    if !ballot_size.is_power_of_two() {
        return Err("ballot_size must be a power of two".into());
    }

    if range.0 >= range.1 {
        return Err("range must be in the form (-N, N) with N > 0".into());
    }

    if range.0 != -range.1 {
        return Err("range must be symmetric: lower = -upper".into());
    }

    let pc_gens: PedersenGens = pc_gens.unwrap_or_else(PedersenGens::default);
    let shifted_upperbound = pc_gens.commit(Scalar::from(range.1 as u64 * 2), Scalar::zero());
    
    Ok(SetupParameters {
        pc_gens,
        bp_gens: BulletproofGens::new(8, ballot_size),
        range,
        shifted_upperbound
    })
}

pub fn generate_proof(
    ballot: Vec<i64>,
    setup_params: &SetupParameters
) -> Result<NoBudgetRatedVotingProof, String> {
    let range_upperbound: i64 = setup_params.range.1;
    let shifted_range_upperbound: u64 = range_upperbound as u64 * 2;
    let shifted_ballot: Vec<u64> = ballot.iter().map(|&v| shift_vote(v, range_upperbound)).collect::<Result<_, _>>()?;

    let blindings: Vec<Scalar> = (0..ballot.len()).map(|_| Scalar::random(&mut thread_rng())).collect();
    let shifted_ballot_committments : Vec<CompressedRistretto> = shifted_ballot
        .iter()
        .zip(blindings.iter())
        .map(|(&v, &blinding)| setup_params.pc_gens.commit(Scalar::from(v), blinding).compress())
        .collect();

    let d_values: Vec<u64> = shifted_ballot
    .iter()
    .map(|&v| shifted_range_upperbound.checked_sub(v).ok_or("Vote is outside range!".to_string()))
    .collect::<Result<_, _>>()?;
    let d_blindings: Vec<Scalar> = blindings.iter().map(|&r| -r).collect();

    let aggregated_rangeproof: (RangeProof, Vec<CompressedRistretto>) = RangeProof::prove_multiple(
        &setup_params.bp_gens,
        &setup_params.pc_gens,
        &mut Transcript::new(b"no budget rated voting"),
        &d_values,
        &d_blindings,
        8,
    )
    .expect("Failed to create aggregated rangeproof");

    Ok(NoBudgetRatedVotingProof {
        shifted_ballot_committments,
        aggregated_rangeproof
    })
}

pub fn verify_proof(
    setup_params: &SetupParameters,
    validity_proof: NoBudgetRatedVotingProof
) -> bool {
    let d_commitments: Vec<CompressedRistretto> = validity_proof.aggregated_rangeproof.1;
    let d_rangeproof = validity_proof.aggregated_rangeproof.0;

    if d_rangeproof
        .verify_multiple(
            &setup_params.bp_gens, 
            &setup_params.pc_gens, 
            &mut Transcript::new(b"no budget rated voting"), 
            &d_commitments, 
            8
        )
        .is_err()
    {
        return false;
    }

    for (d_commitment, v_commitment) in d_commitments.iter().zip(validity_proof.shifted_ballot_committments.iter()) {
        if *d_commitment != (setup_params.shifted_upperbound - v_commitment.decompress().unwrap()).compress() {
            return false;
        }
    }

    true
}

fn shift_vote(value: i64, range_upperbound: i64) -> Result<u64, String> {
    value.checked_add(range_upperbound)
        .ok_or_else(|| format!("Overflow when shifting vote: {} + {}", value, range_upperbound))?
        .try_into()
        .map_err(|_| format!("Shifted value out of u64 range: {}", value + range_upperbound))
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek_ng::scalar::Scalar;

    fn basic_setup(ballot_size: usize) -> SetupParameters {
        let range = (-10, 10);
        setup(range, ballot_size, None).unwrap()
    }

    #[test]
    fn test_valid_proof_verification() {
        let setup_params = basic_setup(4);
        let ballot = vec![0, -5, 7, 10];

        let proof = generate_proof(ballot, &setup_params).expect("Proof generation failed");
        assert!(verify_proof(&setup_params, proof), "Proof verification failed for valid input");
    }

    #[test]
    fn test_invalid_proof_verification_wrong_commitments() {
        let setup_params = basic_setup(2);
        let ballot = vec![3, -2];
        let mut proof = generate_proof(ballot, &setup_params).expect("Proof generation failed");

        // Tamper with one of the commitments
        proof.shifted_ballot_committments[0] = setup_params.pc_gens.commit(Scalar::from(999u64), Scalar::random(&mut thread_rng())).compress();

        assert!(!verify_proof(&setup_params, proof), "Tampered proof should not verify");
    }

    #[test]
    fn test_invalid_proof_verification_out_of_range() {
        let setup_params = basic_setup(2);
        let ballot = vec![15, -12]; // Out of range since range is -10 to 10

        let result = generate_proof(ballot, &setup_params);
        assert!(result.is_err(), "Should not generate proof for out-of-range vote");
    }

    #[test]
    fn test_non_power_of_two_ballot_size() {
        let result = setup((-10, 10), 3, None);
        assert!(result.is_err(), "Ballot size not power of two should fail");
    }

    #[test]
    fn test_asymmetric_range_should_fail() {
        let result = setup((-10, 8), 2, None);
        assert!(result.is_err(), "Asymmetric range should be rejected");
    }
}
