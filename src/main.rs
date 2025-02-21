// mod rated_voting;
mod utils;
mod ranked_voting;

// use bulletproofs::{BulletproofGens, PedersenGens};
use utils::ranked::find_permutation;
use ranked_voting::shuffle_proof::{generate_crs, generate_shuffle_proof, verify_shuffle_proof};

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

    let vec_a_u32 = vec![1, 2, 3, 4];
    let vec_a_permuted = vec![3, 2, 1, 4];

    if let Some(permutation) = find_permutation(&vec_a_u32, &vec_a_permuted) {
        let crs = generate_crs(vec_a_u32.len(), 4);
        let proof = generate_shuffle_proof(vec_a_u32.clone(), vec_a_permuted.clone(), permutation, &crs);

        // let fake_vec_a = vec![1,2,4,3];
        // let fake_crs = generate_crs(vec_a_u32.len(), 4);  

        if verify_shuffle_proof(&proof, &crs, vec_a_u32, 4) {
            println!("✅ Proof verification successful!");
        } else {
            println!("❌ Proof verification failed!");
        }
    } else {
        println!("Error: Invalid permutation.");
    }
}

