use ark_crypto_primitives::crh::{CRHScheme, TwoToOneCRHScheme};
use ark_crypto_primitives::merkle_tree::{Config, MerkleTree, Path};
use ark_serialize::CanonicalSerialize;

use arkworks_merkle_tree_example::{
    common::{write_params_to_file, write_to_file, LeafHash, TwoToOneHash},
    SimpleMerkleTree,
};

fn main() {
    let mut rng = rand::thread_rng();

    // First, let's sample the public parameters for the hash functions:
    let leaf_crh_params = <LeafHash as CRHScheme>::setup(&mut rng).unwrap();
    let two_to_one_crh_params = <TwoToOneHash as TwoToOneCRHScheme>::setup(&mut rng).unwrap();

    write_to_file("leaf_crh_params.bin", &leaf_crh_params);
    write_to_file("parent_crh_params.bin", &two_to_one_crh_params);
}
