// mod rated_voting;
// mod utils;
mod ranked_voting;

use ark_bls12_381::{Fr, G1Affine, G1Projective};
use ark_ec::ProjectiveCurve;
// use bulletproofs::{BulletproofGens, PedersenGens};
use curdleproofs::curdleproofs::{CurdleproofsCrs, generate_crs};

fn main() {
    // let pc_gens = PedersenGens::default();
    // let bp_gens = BulletproofGens::new(8, 4);

    // let ballot: Vec<u64> = vec![2, 0, 5];
    // let max_credits = 20;

    // let (commitments, com_z, rangeproof_d) = rated_voting::max_budget::generate_proof(ballot, max_credits, &pc_gens, &bp_gens);
    // let result = rated_voting::max_budget::verify_proof(&pc_gens, &bp_gens, commitments, com_z, rangeproof_d, max_credits);
    // println!("{}", result);

    // let ballot: Vec<i64> = vec![-10, 10, 5, 2];
    // let range = (-10, 10);

    // let  (v_commitments, rangeproof) = rated_voting::no_budget::generate_proof(ballot,range, &pc_gens, &bp_gens);
    // let result = rated_voting::no_budget::verify_proof(&pc_gens, &bp_gens, v_commitments, rangeproof, range);
    // println!("{}", result);

    let permutation: Vec<u32> = (0..4 as u32).collect();
    // todo: function that creates permutation from ballot
    ranked_voting::shuffle_proof::test_curdleproofs(permutation);
}
