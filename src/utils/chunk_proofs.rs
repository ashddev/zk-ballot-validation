pub fn chunk(ballot: Vec<u64>) {
    let mut start: usize = 0; 
    let length: usize = ballot.len();
    let mut chunked_ballots: Vec<Vec<u64>> = vec!();

    while start < length {
        let remaining_length: usize = length - start;
        let chunk_size: usize = largest_power_of_two_smaller_than_or_equal(remaining_length );
        chunked_ballots.push((&ballot[start..start + chunk_size]).to_vec());
        start += chunk_size;
    }

    println!("{:?}", chunked_ballots);
}

fn largest_power_of_two_smaller_than_or_equal(n: usize) -> usize {
    if n == 0 {
        0
    } else if is_power_of_two(n) {
        n
    } else {
        let msb_position: u32 = usize::BITS - 1 - n.leading_zeros();
        1 << msb_position
    }
}

fn is_power_of_two(n: usize) -> bool {
    (n & (n - 1)) == 0
}
