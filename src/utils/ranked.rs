use std::collections::HashMap;
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_bls12_381::{G1Affine, G1Projective};

pub fn sum_affine_points(affine_points: &[G1Affine]) -> G1Affine {
    affine_points
        .iter()
        .map(|affine| affine.into_projective())
        .sum::<G1Projective>()
        .into_affine()
}

pub fn find_permutation(vec_a: &[u32], vec_a_permuted: &[u32]) -> Option<Vec<u32>> {
    if vec_a.len() != vec_a_permuted.len() {
        return None;
    }

    let mut index_map: HashMap<u32, usize> = HashMap::new();
    
    for (i, &value) in vec_a.iter().enumerate() {
        index_map.insert(value, i);
    }

    let mut permutation = vec![0u32; vec_a.len()];

    for (i, &value) in vec_a_permuted.iter().enumerate() {
        if let Some(&original_index) = index_map.get(&value) {
            permutation[original_index] = i as u32;
        } else {
            return None;
        }
    }

    Some(permutation)
}
