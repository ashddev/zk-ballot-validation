#![no_main]

use zk_ballot_validation::ballot_validation::ranked_voting::{setup, generate_vote};
use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

#[derive(Arbitrary, Debug)]
struct RankedVotingInput {
    ballot: [u32; 16]
}
fuzz_target!(|input: RankedVotingInput| {
    let ballot = input.ballot.to_vec();
    let vec_a = vec![1,2,3,4,5,6,7,8,9,10];

    let setup_params = setup(vec_a.len(), vec_a);
    let proof = generate_vote(&ballot, &setup_params);
});