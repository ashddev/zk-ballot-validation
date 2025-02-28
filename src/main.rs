use bulletproofs::{BulletproofGens, PedersenGens};
use zk_ballot_validation::rated_voting;
// use zk_ballot_validation::utils::ranked::find_permutation;
// use zk_ballot_validation::ranked_voting::shuffle_proof::{generate_crs, generate_shuffle_proof, verify_shuffle_proof};

fn main() {
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(8, 4);

    let ballot: Vec<u64> = vec![0,0,1,0];
    let max_credits = 1;

    let (commitments, com_z, rangeproof_d) = rated_voting::max_budget::generate_proof(ballot, max_credits, &pc_gens, &bp_gens);
    let result = rated_voting::max_budget::verify_proof(&pc_gens, &bp_gens, commitments, com_z, rangeproof_d, max_credits);
    println!("{}", result);

    // let ballot: Vec<i64> = vec![-10, 10, 5, 2];
    // let range = (-10, 10);

    // let  (v_commitments, rangeproof) = rated_voting::no_budget::generate_proof(ballot,range, &pc_gens, &bp_gens);
    // let result = rated_voting::no_budget::verify_proof(&pc_gens, &bp_gens, v_commitments, rangeproof, range);
    // println!("{}", result);

    // let vec_a_u32 = vec![1];
    // let vec_a_permuted = vec![1];

    // if let Some(permutation) = find_permutation(&vec_a_u32, &vec_a_permuted) {
    //     let crs = generate_crs(vec_a_u32.len(), 4);
    //     let proof = generate_shuffle_proof(vec_a_u32.clone(), vec_a_permuted.clone(), permutation, &crs);

    //     if verify_shuffle_proof(&proof, &crs, vec_a_u32, 4) {
    //         println!("Verification successful!");
    //     } else {
    //         println!("Verification failed!");
    //     }
    // } else {
    //     println!("Error: Invalid permutation.");
    // }
}

