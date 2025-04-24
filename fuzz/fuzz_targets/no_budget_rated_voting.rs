#![no_main]

use zk_ballot_validation::ballot_validation::rated_voting::no_budget::{setup, generate_vote};
use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

#[derive(Arbitrary, Debug)]
struct NoBudgetInput {
    ballot: [i64; 16],
}

fuzz_target!(|input: NoBudgetInput| {
    let ballot = input.ballot.to_vec();

    let bp_params = match setup((-256, 256), ballot.len(), None) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Setup failed: {}", e);
            return;
        }
    };

    let _ = generate_vote(ballot, &bp_params);
});