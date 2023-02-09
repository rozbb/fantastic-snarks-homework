use arkworks_merkle_tree_example::{
    constraints::PossessionCircuit,
    util::{
        gen_test_tree, get_test_card, get_test_leaf, read_from_file, write_to_file,
        PEDERSEN_PARAMS_FILENAME, POSSESSION_PK_FILENAME, POSSESSION_PROOF_FILENAME,
        POSSESSION_REVEALED_SERIAL_FILENAME, POSSESSION_VK_FILENAME,
    },
    E,
};

use ark_ff::ToConstraintField;
use ark_groth16::{create_random_proof, verify_proof, ProvingKey};

fn main() {
    //
    // Setup
    //

    let mut rng = rand::thread_rng();

    println!("Reading params and proving key...");
    // Read the hashing params from a file
    let (leaf_crh_params, two_to_one_crh_params) = read_from_file(PEDERSEN_PARAMS_FILENAME);
    // Read the Groth16 CRS from a file
    let pk: ProvingKey<E> = read_from_file(POSSESSION_PK_FILENAME);

    // Generate a test tree and compute its root
    let tree = gen_test_tree(&leaf_crh_params, &two_to_one_crh_params);
    let root = tree.root();
    // Also imagine we possess the card that appears at index 7 in the tree
    let our_idx = 7;
    let (card, card_nonce) = get_test_card(our_idx);

    //
    // Now generate a proof
    //

    // We'll prove membership of our card, i.e., the 7th item in the tree
    let idx_to_prove = our_idx;
    let claimed_leaf = &get_test_leaf(&leaf_crh_params, idx_to_prove);

    // Generate an authentication path for our leaf
    let auth_path = tree.generate_proof(idx_to_prove).unwrap();

    // We now have everything we need to build the PossessionCircuit
    let circuit = PossessionCircuit {
        // Constants that the circuit needs
        leaf_crh_params,
        two_to_one_crh_params,

        // Public inputs to the circuit
        root,
        leaf: claimed_leaf.to_vec(),
        card_serial_num: card.serial_num,

        // Witness to membership
        auth_path,
        // Commitment opening details
        card_nonce,
        card_purchase_price: card.purchase_price,
    };

    // Create the proof
    println!("Proving...");
    let proof = create_random_proof(circuit.clone(), &pk, &mut rng).unwrap();
    // Serialize the public inputs that the verifier will use
    let public_inputs = [
        root.to_field_elements().unwrap(),
        card.serial_num.to_field_elements().unwrap(),
    ]
    .concat();

    //
    // Wrap-up
    //

    // Verify the proof package. This should succeed
    let vk = read_from_file(POSSESSION_VK_FILENAME);
    assert!(
        verify_proof(&vk, &proof, &public_inputs).unwrap(),
        "honest proof failed to verify with supplied verifying key"
    );

    // Write the proof and serial to a file
    write_to_file(POSSESSION_PROOF_FILENAME, &proof);
    write_to_file(POSSESSION_REVEALED_SERIAL_FILENAME, &card.serial_num);
    println!("Wrote {POSSESSION_PROOF_FILENAME}");
    println!("Wrote {POSSESSION_REVEALED_SERIAL_FILENAME}");
}
