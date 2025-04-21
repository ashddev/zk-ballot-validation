use core::iter;
use ark_std::UniformRand;
use ark_bls12_381::{Fr, G1Affine, G1Projective};
use ark_ec::{AffineCurve, ProjectiveCurve};
use merlin::Transcript;
use std::collections::HashMap;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use curdleproofs::msm_accumulator::MsmAccumulator;
use curdleproofs::same_permutation_argument::SamePermutationProof;
use curdleproofs::util::{generate_blinders, msm};

pub struct SetupParameters {
    crs_g_vec: Vec<G1Affine>,
    crs_h_vec: Vec<G1Affine>,
    crs_u: G1Projective,
    crs_g_sum: G1Affine,
    crs_h_sum: G1Affine,
    a_vec: Vec<u32>
}

pub struct RankedVotingProof {
    proof: SamePermutationProof,
    committed_ballot: G1Projective,
    committed_permutation: G1Projective,
}

pub fn setup(ballot_size: usize, a_vec: Vec<u32>) -> SetupParameters {
    let mut rng: StdRng = StdRng::from_entropy();

    let crs_g_vec: Vec<_> = iter::repeat_with(|| G1Projective::rand(&mut rng).into_affine())
        .take(ballot_size)
        .collect();
    let crs_h_vec: Vec<_> = iter::repeat_with(|| G1Projective::rand(&mut rng).into_affine())
        .take(ballot_size)
        .collect();

    let crs_u = G1Projective::rand(&mut rng);
    let crs_g_sum = sum_affine_points(&crs_g_vec);
    let crs_h_sum = sum_affine_points(&crs_h_vec);

    SetupParameters {
        crs_g_vec,
        crs_h_vec,
        crs_u,
        crs_g_sum,
        crs_h_sum,
        a_vec
    }
}

pub fn generate_proof(
    ballot: &Vec<u32>,
    setup_params: &SetupParameters,
) -> Result<RankedVotingProof, String> {
    let permutation= find_permutation(&setup_params.a_vec, &ballot)?;
    
    let mut rng: StdRng = StdRng::seed_from_u64(0u64);

    let ballot_size = permutation.len();

    let vec_a_fr: Vec<Fr> = setup_params.a_vec.iter().map(|&x| Fr::from(x)).collect();
    let vec_a_permuted_fr: Vec<Fr> = ballot.iter().map(|&x| Fr::from(x)).collect();
    let permutation_as_fr: Vec<Fr> = (0..permutation.len())
    .map(|i| Fr::from(permutation[i] as u64))
    .collect();

    let committed_ballot_blinders = generate_blinders(&mut rng, ballot_size);
    let committed_permutation_blinders = generate_blinders(&mut rng, ballot_size);

    let committed_ballot = msm(&setup_params.crs_g_vec, &vec_a_permuted_fr) + msm(&setup_params.crs_h_vec, &committed_ballot_blinders);
    let committed_permutation: ark_ec::short_weierstrass_jacobian::GroupProjective<ark_bls12_381::g1::Parameters> = msm(&setup_params.crs_g_vec, &permutation_as_fr) + msm(&setup_params.crs_h_vec, &committed_permutation_blinders);

    let proof = SamePermutationProof::new(
        &setup_params.crs_g_vec,
        &setup_params.crs_h_vec,
        &setup_params.crs_u,
        committed_ballot,
        committed_permutation,
        &vec_a_fr,
        permutation,
        committed_ballot_blinders,
        committed_permutation_blinders,
        &mut Transcript::new(b"sameperm"),
        &mut rng,
    );

    Ok(RankedVotingProof {
        proof,
        committed_ballot,
        committed_permutation,
    })
}

pub fn verify_proof(proof: &RankedVotingProof, setup_params: &SetupParameters) -> bool {
    let mut rng: StdRng = StdRng::seed_from_u64(0u64);
    let mut msm_accumulator = MsmAccumulator::default();

    let vec_a_fr: Vec<Fr> = setup_params.a_vec.iter().map(|&x| Fr::from(x)).collect();
    let ballot_size = vec_a_fr.len();

    let verification = proof.proof.verify(
        &setup_params.crs_g_vec,
        &setup_params.crs_h_vec,
        &setup_params.crs_u,
        &setup_params.crs_g_sum,
        &setup_params.crs_h_sum,
        &proof.committed_ballot,
        &proof.committed_permutation,
        &vec_a_fr,
        ballot_size,
        &mut Transcript::new(b"sameperm"),
        &mut msm_accumulator,
        &mut rng,
    );

    verification.is_ok() && msm_accumulator.verify().is_ok()
}

fn sum_affine_points(affine_points: &[G1Affine]) -> G1Affine {
    affine_points
        .iter()
        .map(|affine| affine.into_projective())
        .sum::<G1Projective>()
        .into_affine()
}


fn find_permutation(vec_a: &[u32], vec_b: &[u32]) -> Result<Vec<u32>, String> {
    if vec_a.len() != vec_b.len() {
        return Err("Vectors must be the same length".to_string());
    }

    let index_map: HashMap<u32, usize> = vec_a
        .iter()
        .enumerate()
        .map(|(i, &x)| (x, i))
        .collect();

    let p: Vec<usize> = vec_b
        .iter()
        .map(|&x| {
            index_map
                .get(&x)
                .copied()
                .ok_or_else(|| format!("Element {} not found in original vector", x))
        })
        .collect::<Result<Vec<usize>, String>>()?;
    
    let mut inv = vec![0; p.len()];
    for (i, &pi) in p.iter().enumerate() {
        inv[pi] = i as u32;
    }
    Ok(inv)
}
