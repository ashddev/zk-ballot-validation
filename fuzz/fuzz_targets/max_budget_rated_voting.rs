#![no_main]

use zk_ballot_validation::ballot_validation::rated_voting::max_budget::{setup, generate_vote};
use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

#[derive(Arbitrary, Debug)]
struct MaxBudgetInput {
    ballot: [u64; 16],
}
fuzz_target!(|input: MaxBudgetInput| {
    let ballot = input.ballot.to_vec();

    let setup_params = setup(100, ballot.len(), None);
    let _ = generate_vote(&setup_params, ballot);
});
