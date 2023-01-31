use arkworks_merkle_tree_example::common::{write_to_file, LeafHash, TwoToOneHash};

use ark_crypto_primitives::crh::{CRHScheme, TwoToOneCRHScheme};

fn main() {
    let mut rng = rand::thread_rng();

    // First, let's sample the public parameters for the hash functions:
    let leaf_crh_params = <LeafHash as CRHScheme>::setup(&mut rng).unwrap();
    let two_to_one_crh_params = <TwoToOneHash as TwoToOneCRHScheme>::setup(&mut rng).unwrap();

    write_to_file("leaf_crh_params.bin", &leaf_crh_params);
    write_to_file("parent_crh_params.bin", &two_to_one_crh_params);
}
