use arkworks_merkle_tree_example::{
    util::{
        gen_test_tree, read_from_file, PEDERSEN_PARAMS_FILENAME, POSSESSION_PROOF_FILENAME,
        POSSESSION_REVEALED_SERIAL_FILENAME, POSSESSION_VK_FILENAME,
    },
    E, F,
};

use ark_ff::ToConstraintField;
use ark_groth16::{verify_proof, PreparedVerifyingKey, Proof};

fn main() {
    //
    // Setup
    //

    println!("Reading params, verifying key, proof, and public inputs...");
    // Read the hashing params from a file
    let (leaf_crh_params, two_to_one_crh_params) = read_from_file(PEDERSEN_PARAMS_FILENAME);
    // Read the Groth16 CRS, proof, and serial from a file
    let vk: PreparedVerifyingKey<E> = read_from_file(POSSESSION_VK_FILENAME);
    let proof: Proof<E> = read_from_file(POSSESSION_PROOF_FILENAME);
    let card_serial: F = read_from_file(POSSESSION_REVEALED_SERIAL_FILENAME);

    //
    // Compute the public inputs for the circuit. We know the Merkle root, and we were given the
    // card serial
    //

    // Get the root
    let root = {
        let tree = gen_test_tree(&leaf_crh_params, &two_to_one_crh_params);
        tree.root()
    };
    // Serialize everything to field elements
    let public_inputs = [
        root.to_field_elements().unwrap(),
        card_serial.to_field_elements().unwrap(),
    ]
    .concat();

    //
    // Verify the proof
    //

    // Prepare the verifying key and verify
    assert!(
        verify_proof(&vk, &proof, &public_inputs).unwrap(),
        "proof failed to verify"
    );

    println!("Proof verified successfully");
}
