use arkworks_merkle_tree_example::{
    card::Card,
    common::{
        gen_test_tree, get_test_card, get_test_leaf, read_from_file, write_to_file,
        PEDERSEN_PARAMS_FILENAME, TESTCASE_BAD_FILENAME, TESTCASE_GOOD_FILENAME,
    },
    constraints::PossessionCircuit,
    merkle::{Leaf, MerkleRoot, SimpleMerkleTree},
    E, F,
};

use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use ark_ff::ToConstraintField;
use ark_ff::UniformRand;
use ark_groth16::{
    create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof,
};
use rand::RngCore;

/// Generates a Groth16 CRS, proof, and public input for the given merkle tree circuit, tree root,
/// and claimed-member leaf. Might return `None` if the proof fails (ie if the statement is false)
fn gen_proof_package(
    circuit: &PossessionCircuit,
    root: &MerkleRoot,
    serial_num: &F,
    claimed_leaf: &[u8],
) -> Option<(ark_groth16::ProvingKey<E>, ark_groth16::Proof<E>, Vec<F>)> {
    let mut rng = rand::thread_rng();

    // Generate the CRS (aka proving key)
    let crs = generate_random_parameters(circuit.clone(), &mut rng).unwrap();
    // Create the proof
    let proof = create_random_proof(circuit.clone(), &crs, &mut rng).ok();
    // Serialize the public inputs that the verifier will use
    let public_inputs = [
        root.to_field_elements().unwrap(),
        serial_num.to_field_elements().unwrap(),
        claimed_leaf.to_field_elements().unwrap(),
    ]
    .concat();

    // Return everything so long as the proof succeeded
    proof.map(|p| (crs, p, public_inputs))
}

fn main() {
    let mut rng = rand::thread_rng();

    // Read the hashing params from a file
    let (leaf_crh_params, two_to_one_crh_params) = read_from_file(PEDERSEN_PARAMS_FILENAME);

    // Generate a test tree and the root
    let tree = gen_test_tree(&leaf_crh_params, &two_to_one_crh_params);
    let correct_root = tree.root();
    // Also imagine we possess the card that appears at index 7 in the tree
    let our_idx = 7;
    let (card, card_nonce) = get_test_card(our_idx);

    // We also make an incorrect root. This should produce an invalid proof
    let incorrect_root = MerkleRoot::rand(&mut rng);

    // Now generate the proof

    // We'll reveal and prove membership of the 7th item in the tree
    let idx_to_prove = our_idx;
    let claimed_leaf = &get_test_leaf(&leaf_crh_params, idx_to_prove);

    // Now, let's try to generate an authentication path for the 5th item.
    let auth_path = tree.generate_proof(idx_to_prove).unwrap();

    let circuit = PossessionCircuit {
        // Constants that the circuit needs
        leaf_crh_params,
        two_to_one_crh_params,

        // Public inputs to the circuit
        root: correct_root,
        leaf: claimed_leaf.to_vec(),
        card_serial_num: card.serial_num,

        // Witness to membership
        auth_path,
        // Commitment opening details
        card_nonce,
        card_purchase_price: card.purchase_price,
    };

    // Create a proof package using the correct tree root. That is, generate the Groth16 CRS, the
    // proof with respect to that CRS, and the public inputs to that proof.
    let proof_package = gen_proof_package(&circuit, &correct_root, &card.serial_num, claimed_leaf)
        .expect("failed to make honest proof");
    let (crs, proof, public_inputs) = proof_package.clone();

    // Verify the proof package. This should work for the correct root
    let pvk = prepare_verifying_key(&crs.vk);
    assert!(
        verify_proof(&pvk, &proof, &public_inputs).unwrap(),
        "honest proof failed to verify"
    );

    // Now do the same thing but use the wrong root. This should fail to prove
    let mut circuit = circuit.clone();
    circuit.root = incorrect_root;
    let proof_package =
        gen_proof_package(&circuit, &incorrect_root, &card.serial_num, claimed_leaf)
            .expect("failed to make an incorrect proof");
    let (_, proof, public_inputs) = proof_package.clone();
    assert!(
        !verify_proof(&pvk, &proof, &public_inputs).unwrap(),
        "invalid proof succeeded at verification"
    );

    // Write everything to disk
    //write_to_file(TESTCASE_GOOD_FILENAME, &(
}
