use arkworks_merkle_tree_example::{merkle::MerkleRoot, util::read_from_file, E, F};

use ark_ff::ToConstraintField;
use ark_groth16::{verify_proof, PreparedVerifyingKey, Proof};
use ark_serialize::CanonicalDeserialize;

const HELP_STR: &str = "\
Error: bad command line arguments

Usage:
    cargo run --release --bin verify -- VERIFYING_KEY_FILE PROOF_FILE PUBLIC_INPUTS_FILE MERKLE_ROOT
Example:
    cargo run --release --bin verify -- \\
        possession_verifying_key.bin \\
        possession_proof.bin \\
        possession_revealed_serial.bin \\
        f5pj64oh3m6anguhjb5rhfugwe44ximao17ya3wgx1fbmg1iobmo
";

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 5 {
        println!("{}", HELP_STR);
        panic!("bad command line input");
    }
    // Unpack command line args
    let possession_vk_filename = &args[1];
    let possession_proof_filename = &args[2];
    let possession_revealed_serial_filename = &args[3];
    let given_merkle_root = {
        let bytes = zbase32::decode_full_bytes(args[4].as_bytes())
            .expect("could not decode Merkle root string");
        MerkleRoot::deserialize_compressed(bytes.as_slice())
            .expect("Merkle root string is an invalid hash")
    };

    //
    // Setup
    //

    println!("Reading verifying key, proof, and public inputs...");
    // Read the Groth16 CRS, proof, and serial from a file
    let vk: PreparedVerifyingKey<E> = read_from_file(possession_vk_filename);
    let proof: Proof<E> = read_from_file(possession_proof_filename);
    let card_serial: F = read_from_file(possession_revealed_serial_filename);

    //
    // Compute the public inputs for the circuit. We know the Merkle root, and we were given the
    // card serial
    //

    // Serialize everything to field elements
    let public_inputs = [
        given_merkle_root.to_field_elements().unwrap(),
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
