use arkworks_merkle_tree_example::{
    card::Card,
    common::{
        read_from_file, write_to_file, PEDERSEN_PARAMS_FILENAME, TESTCASE_BAD_FILENAME,
        TESTCASE_GOOD_FILENAME,
    },
    constraints::PossessionCircuit,
    merkle::{Leaf, MerkleRoot, SimpleMerkleTree},
};

use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use ark_ff::ToConstraintField;
use ark_ff::UniformRand;
use ark_groth16::{
    create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof,
};
use rand::RngCore;

type E = Bls12_381;
type F = <E as Pairing>::ScalarField;

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

    // Make 7 random leaves
    let mut leaves: Vec<_> = core::iter::repeat_with(|| {
        let mut leaf_buf: Leaf = [0u8; 64];
        rng.fill_bytes(&mut leaf_buf);
        leaf_buf
    })
    .take(7)
    .collect();
    // Create a card and make the last leaf a commitment to that card
    let card = Card::rand(&mut rng);
    let card_nonce = F::rand(&mut rng);
    let card_com = card.commit(&leaf_crh_params, &card_nonce);
    leaves.push(card_com);

    // Generate the tree and compute the root
    let tree =
        SimpleMerkleTree::new(&leaf_crh_params, &two_to_one_crh_params, leaves.clone()).unwrap();
    let correct_root = tree.root();
    // We also make an incorrect root. This should produce an invalid proof
    let incorrect_root = MerkleRoot::rand(&mut rng);

    // Now generate the proof

    // We'll reveal and prove membership of the 7th item in the tree
    let idx_to_prove = 7;
    let claimed_leaf = &leaves[idx_to_prove];

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
