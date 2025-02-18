use core::iter;

use ark_std::UniformRand;
use ark_bls12_381::{Fr, G1Affine, G1Projective};
use ark_ec::{AffineCurve, ProjectiveCurve};

use ark_std::rand::{rngs::StdRng, Rng, SeedableRng};
use curdleproofs::msm_accumulator::MsmAccumulator;
use curdleproofs::same_permutation_argument::SamePermutationProof;
use curdleproofs::util::{generate_blinders, get_permutation, msm};

pub fn test_curdleproofs(permutation: Vec<u32>) {
    let mut rng: StdRng = StdRng::seed_from_u64(0u64);
    let mut transcript_prover = merlin::Transcript::new(b"sameperm");
    let ell = permutation.len();
    let n_blinders = 4;

    let crs_G_vec: Vec<_> = iter::repeat_with(|| G1Projective::rand(&mut rng).into_affine())
            .take(ell)
            .collect();
        let crs_H_vec: Vec<_> = iter::repeat_with(|| G1Projective::rand(&mut rng).into_affine())
            .take(n_blinders)
            .collect();

    let crs_U = G1Projective::rand(&mut rng);
    let crs_G_sum: G1Affine = sum_affine_points(&crs_G_vec);
    let crs_H_sum: G1Affine = sum_affine_points(&crs_H_vec);

    let vec_a_blinders = generate_blinders(&mut rng, n_blinders);
    let vec_m_blinders = generate_blinders(&mut rng, n_blinders);

    let permutation_as_fr: Vec<Fr> = permutation.iter().map(|s| Fr::from(*s)).collect();

    let vec_a: Vec<Fr> = iter::repeat_with(|| rng.gen()).take(ell).collect();
    let vec_a_permuted = get_permutation(&vec_a, &permutation);

    let A = msm(&crs_G_vec, &vec_a_permuted) + msm(&crs_H_vec, &vec_a_blinders);
    let M = msm(&crs_G_vec, &permutation_as_fr) + msm(&crs_H_vec, &vec_m_blinders);

    let same_perm_proof = SamePermutationProof::new(
        &crs_G_vec,
        &crs_H_vec,
        &crs_U,
        A,
        M,
        &vec_a,
        permutation,
        vec_a_blinders,
        vec_m_blinders,
        &mut transcript_prover,
        &mut rng,
    );

    let mut transcript_verifier = merlin::Transcript::new(b"sameperm");
    let mut msm_accumulator = MsmAccumulator::default();

    assert!(same_perm_proof
        .verify(
            &crs_G_vec,
            &crs_H_vec,
            &crs_U,
            &crs_G_sum,
            &crs_H_sum,
            &A,
            &M,
            &vec_a,
            n_blinders,
            &mut transcript_verifier,
            &mut msm_accumulator,
            &mut rng,
        )
        .is_ok());

    assert!(msm_accumulator.verify().is_ok());

}

pub(crate) fn sum_affine_points(affine_points: &[G1Affine]) -> G1Affine {
    affine_points
        .iter()
        .map(|affine| affine.into_projective())
        .sum::<G1Projective>()
        .into_affine()
}
