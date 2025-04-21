#![no_main]

use zk_ballot_validation::ballot_validation::rated_voting::max_budget::{setup, generate_proof};
use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

#[derive(Arbitrary, Debug)]
struct RankedVotingInput {
    vec_a: [u64; 16],
    ballot: [u64; 16]
}
fuzz_target!(|input: NoBudgetInput| {
    let ballot = input.ballot.to_vec();
    let vec_a: input.vec_a.to_vec();

    let setup_params = ranked_voting::setup(vec_a.len(), vec_a);
    let proof = ranked_voting::generate_proof(&ballot, &setup_params);
});