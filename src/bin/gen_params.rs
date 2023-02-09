use arkworks_merkle_tree_example::{
    common::{
        gen_test_tree, write_to_file, PEDERSEN_PARAMS_FILENAME, POSSESSION_PK_FILENAME,
        POSSESSION_VK_FILENAME,
    },
    constraints::PossessionCircuit,
    hash::{LeafHash, TwoToOneHash},
    merkle::{Leaf, MerkleRoot},
    E, F,
};

use ark_crypto_primitives::crh::{CRHScheme, TwoToOneCRHScheme};
use ark_ff::UniformRand;
use ark_groth16::{generate_random_parameters, prepare_verifying_key, ProvingKey};
use rand::RngCore;

fn main() {
    let mut rng = rand::thread_rng();

    //
    // First step is to generate the Pedersen hashing parameters
    //

    // Sample the Pedersen params randomly
    let leaf_crh_params = <LeafHash as CRHScheme>::setup(&mut rng).unwrap();
    let two_to_one_crh_params = <TwoToOneHash as TwoToOneCRHScheme>::setup(&mut rng).unwrap();

    // Write the CRH params to a file
    write_to_file(
        PEDERSEN_PARAMS_FILENAME,
        &(leaf_crh_params.clone(), two_to_one_crh_params.clone()),
    );
    println!("Wrote {PEDERSEN_PARAMS_FILENAME}");

    //
    // Now we generate the Groth16 CRS for PossessionCircuit. To do so, we have to make a
    // placeholder circuit. We will just fill in everything with random values
    //

    // Make a uniform leaf
    let random_leaf = {
        let mut buf: Leaf = [0u8; 64];
        rng.fill_bytes(&mut buf);
        buf.to_vec()
    };
    // To make a correctly sized auth path, we make a Merkle tree of the same size as our test
    // tree, and create an auth path for any arbitrary index
    let random_auth_path = {
        let tree = gen_test_tree(&leaf_crh_params, &two_to_one_crh_params);
        tree.generate_proof(0).unwrap()
    };

    // Now construct the circuit with all the random values
    let circuit = PossessionCircuit {
        // Constants that the circuit needs
        leaf_crh_params,
        two_to_one_crh_params,

        // Public inputs to the circuit
        root: MerkleRoot::rand(&mut rng),
        leaf: random_leaf,
        card_serial_num: F::rand(&mut rng),

        // Witness to membership
        auth_path: random_auth_path,
        // Commitment opening details
        card_nonce: F::rand(&mut rng),
        card_purchase_price: F::rand(&mut rng),
    };

    // Generate the Groth16 proving and verifying key and write to files
    let pk: ProvingKey<E> = generate_random_parameters(circuit.clone(), &mut rng).unwrap();
    let vk = prepare_verifying_key(&pk.vk);
    write_to_file(POSSESSION_PK_FILENAME, &pk);
    write_to_file(POSSESSION_VK_FILENAME, &vk);
    println!("Wrote {POSSESSION_PK_FILENAME}");
    println!("Wrote {POSSESSION_VK_FILENAME}");
}
