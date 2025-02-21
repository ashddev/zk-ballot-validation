use core::iter;
use ark_std::UniformRand;
use ark_bls12_381::{Fr, G1Affine, G1Projective};
use ark_ec::ProjectiveCurve;

use ark_std::rand::{rngs::StdRng, SeedableRng};
use curdleproofs::msm_accumulator::MsmAccumulator;
use curdleproofs::same_permutation_argument::SamePermutationProof;
use curdleproofs::util::{generate_blinders, msm};
use crate::utils::ranked::sum_affine_points;

pub struct ShuffleCRS {
    pub crs_G_vec: Vec<G1Affine>,
    pub crs_H_vec: Vec<G1Affine>,
    pub crs_U: G1Projective,
    pub crs_G_sum: G1Affine,
    pub crs_H_sum: G1Affine,
}

pub struct ShuffleProof {
    pub proof: SamePermutationProof,
    pub A: G1Projective,
    pub M: G1Projective,
}

pub fn generate_crs(ell: usize, n_blinders: usize) -> ShuffleCRS {
    let mut rng: StdRng = StdRng::from_entropy();

    let crs_G_vec: Vec<_> = iter::repeat_with(|| G1Projective::rand(&mut rng).into_affine())
        .take(ell)
        .collect();
    let crs_H_vec: Vec<_> = iter::repeat_with(|| G1Projective::rand(&mut rng).into_affine())
        .take(n_blinders)
        .collect();

    let crs_U = G1Projective::rand(&mut rng);
    let crs_G_sum = sum_affine_points(&crs_G_vec);
    let crs_H_sum = sum_affine_points(&crs_H_vec);

    ShuffleCRS {
        crs_G_vec,
        crs_H_vec,
        crs_U,
        crs_G_sum,
        crs_H_sum,
    }
}

pub fn generate_shuffle_proof(
    vec_a_u32: Vec<u32>,
    vec_a_permuted_u32: Vec<u32>,
    permutation: Vec<u32>,
    crs: &ShuffleCRS,
) -> ShuffleProof {
    let mut rng: StdRng = StdRng::seed_from_u64(0u64);
    let mut transcript_prover = merlin::Transcript::new(b"sameperm");

    let ell = permutation.len();
    let n_blinders = 4.max(ell);

    let vec_a: Vec<Fr> = vec_a_u32.iter().map(|&x| Fr::from(x)).collect();
    let vec_a_permuted: Vec<Fr> = vec_a_permuted_u32.iter().map(|&x| Fr::from(x)).collect();
    let permutation_as_fr: Vec<Fr> = (0..permutation.len())
    .map(|i| Fr::from(permutation[i] as u64))
    .collect();

    let vec_a_blinders = generate_blinders(&mut rng, n_blinders);
    let vec_m_blinders = generate_blinders(&mut rng, n_blinders);

    let A = msm(&crs.crs_G_vec, &vec_a_permuted) + msm(&crs.crs_H_vec, &vec_a_blinders);
    let M = msm(&crs.crs_G_vec, &permutation_as_fr) + msm(&crs.crs_H_vec, &vec_m_blinders);

    let proof = SamePermutationProof::new(
        &crs.crs_G_vec,
        &crs.crs_H_vec,
        &crs.crs_U,
        A,
        M,
        &vec_a,
        permutation,
        vec_a_blinders,
        vec_m_blinders,
        &mut transcript_prover,
        &mut rng,
    );

    ShuffleProof {
        proof,
        A,
        M,
    }
}

pub fn verify_shuffle_proof(proof: &ShuffleProof, crs: &ShuffleCRS, vec_a: Vec<u32>, n_blinders: usize) -> bool {
    let mut rng: StdRng = StdRng::seed_from_u64(0u64);
    let mut transcript_verifier = merlin::Transcript::new(b"sameperm");
    let mut msm_accumulator = MsmAccumulator::default();

    let vec_a_fr: Vec<Fr> = vec_a.iter().map(|&x| Fr::from(x)).collect();

    let verification = proof.proof.verify(
        &crs.crs_G_vec,
        &crs.crs_H_vec,
        &crs.crs_U,
        &crs.crs_G_sum,
        &crs.crs_H_sum,
        &proof.A,
        &proof.M,
        &vec_a_fr,
        n_blinders,
        &mut transcript_verifier,
        &mut msm_accumulator,
        &mut rng,
    );

    verification.is_ok() && msm_accumulator.verify().is_ok()
}
