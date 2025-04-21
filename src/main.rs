use zk_ballot_validation::ballot_validation::{ranked_voting, rated_voting};

fn main() {
    run_max_budget_rated_voting().unwrap();
    run_no_budget_rated_voting().unwrap();
    run_ranked_voting().unwrap();
}

fn run_no_budget_rated_voting() -> Result<(), String> {
    let setup_params = rated_voting::no_budget::setup((-10, 10), 4, None)?;
    let ballot: Vec<i64> = vec![-10, 10, 5, -18];
    let validity_proof = rated_voting::no_budget::generate_proof(ballot, &setup_params)?;

    let result = rated_voting::no_budget::verify_proof(&setup_params, validity_proof);
    println!("{}", result);
    Ok(())
}

fn run_max_budget_rated_voting() -> Result<(), String> {
    let setup_params = rated_voting::max_budget::setup(1, 4, None);
    let ballot: Vec<u64> = vec![0,0,2,0];

    let validity_proof = rated_voting::max_budget::generate_proof(&setup_params, ballot)?;
    let result: bool = rated_voting::max_budget::verify_proof(&setup_params, validity_proof);
    println!("{}", result);
    Ok(())
}

fn run_ranked_voting() -> Result<(), String> {
    let vec_a: Vec<u32> = vec![1,2,3,4];
    let vec_a_permuted: Vec<u32> = vec![1,4,3,2];

    let setup_params = ranked_voting::setup(vec_a.len(), vec_a);
    let proof = ranked_voting::generate_proof( &vec_a_permuted, &setup_params)?;
    let result: bool = ranked_voting::verify_proof(&proof, &setup_params);

    println!("{}", result);
    Ok(())
}