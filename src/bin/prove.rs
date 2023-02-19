use arkworks_merkle_tree_example::{
    constraints::PossessionCircuit,
    merkle::MerkleRoot,
    util::{
        gen_test_tree, get_test_card, get_test_leaf, read_from_file, write_to_file,
        POSSESSION_PROOF_FILENAME, POSSESSION_REVEALED_SERIAL_FILENAME, POSSESSION_VK_FILENAME,
    },
    E,
};

use std::env;

use ark_ff::ToConstraintField;
use ark_groth16::{create_random_proof, verify_proof, ProvingKey};
use ark_serialize::CanonicalDeserialize;

const HELP_STR: &str = "\
Error: bad command line arguments

Usage:
    cargo run --release --bin prove -- PEDERSEN_PARAM_FILE PROVING_KEY_FILE MERKLE_ROOT
Example:
    cargo run --release --bin prove -- \\
        pedersen_params.bin \\
        possession_proving_key.bin \\
        f5pj64oh3m6anguhjb5rhfugwe44ximao17ya3wgx1fbmg1iobmo
";

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        println!("{}", HELP_STR);
        panic!("bad command line input");
    }
    // Unpack command line args
    let pedersen_params_filename = &args[1];
    let possession_pk_filename = &args[2];
    let given_merkle_root = {
        let bytes = zbase32::decode_full_bytes(args[3].as_bytes())
            .expect("could not decode Merkle root string");
        MerkleRoot::deserialize_compressed(bytes.as_slice())
            .expect("Merkle root string is an invalid hash")
    };

    //
    // Setup
    //

    let mut rng = rand::thread_rng();

    println!("Reading params and proving key...");
    // Read the hashing params from a file
    let (leaf_crh_params, two_to_one_crh_params) = read_from_file(&pedersen_params_filename);
    // Read the Groth16 CRS from a file
    let pk: ProvingKey<E> = read_from_file(&possession_pk_filename);

    // Generate a test tree and compute its root
    let tree = gen_test_tree(&leaf_crh_params, &two_to_one_crh_params);
    let root = tree.root();
    // Check that the root we generated is equal to the root that was given
    assert_eq!(
        root, given_merkle_root,
        "The Merkle root I'm trying to use is different than the one you gave me"
    );
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
    let auth_path = todo!(); // Generate an authentication path for idx_to_prove

    // We now have everything we need to build the PossessionCircuit
    let circuit = PossessionCircuit {
        // Constants that the circuit needs
        leaf_crh_params,
        two_to_one_crh_params,

        // Public inputs to the circuit
        root: todo!(), // The merkle root,
        leaf: claimed_leaf.to_vec(),
        card_serial_num: todo!(), // The card's serial

        // Witness to membership
        auth_path: todo!(), // The merkle authentication path
        // Commitment opening details
        card_nonce: todo!(),          // The card's nonce
        card_purchase_price: todo!(), // The cards' purchase price
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
