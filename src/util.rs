use crate::{
    card::Card,
    hash::{LeafHashParams, TwoToOneHashParams},
    merkle::{Leaf, SimpleMerkleTree},
    F,
};

use std::{
    fs::OpenOptions,
    io::{Read, Write},
    path::Path,
};

use ark_ff::UniformRand;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

pub const POSSESSION_PK_FILENAME: &str = "possession_proving_key.bin";
pub const POSSESSION_VK_FILENAME: &str = "possession_verifying_key.bin";
pub const POSSESSION_PROOF_FILENAME: &str = "possession_proof.bin";
pub const POSSESSION_REVEALED_SERIAL_FILENAME: &str = "possession_revealed_serial.bin";

pub const PEDERSEN_PARAMS_FILENAME: &str = "pedersen_params.bin";

/// A helper function that deterministically creates 16 baseball cards and their nonces
fn all_cards() -> Vec<(Card, F)> {
    // Use a deterministic RNG
    let mut rng = ark_std::test_rng();

    core::iter::repeat_with(|| {
        let card = Card::rand(&mut rng);
        let card_nonce = F::rand(&mut rng);
        (card, card_nonce)
    })
    .take(16)
    .collect()
}

/// Returns a Merkle tree of all the cards generated above for our test
pub fn gen_test_tree(
    leaf_crh_params: &LeafHashParams,
    two_to_one_crh_params: &TwoToOneHashParams,
) -> SimpleMerkleTree {
    let leaves: Vec<Leaf> = all_cards()
        .into_iter()
        .map(|(card, nonce)| card.commit(&leaf_crh_params, &nonce))
        .collect();

    SimpleMerkleTree::new(&leaf_crh_params, &two_to_one_crh_params, leaves).unwrap()
}

/// Unfortuantely you can't get leaves out of trees, so we need a separate function for returning
/// the i-th leaf.
pub fn get_test_leaf(leaf_crh_params: &LeafHashParams, i: usize) -> Leaf {
    let (card, nonce) = all_cards().get(i).unwrap().clone();
    card.commit(&leaf_crh_params, &nonce)
}

/// Returns the i-th card and nonce in the test tree.
pub fn get_test_card(i: usize) -> (Card, F) {
    all_cards().get(i).unwrap().clone()
}

pub fn write_to_file<S: CanonicalSerialize>(path_str: &str, data: &S) {
    // Convert string to FS path
    let path = Path::new(path_str);

    // Open the file
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .open(path)
        .expect(&format!("could not open {path_str} for writing"));

    // Serialize the data
    let mut buf = Vec::new();
    data.serialize_compressed(&mut buf)
        .expect(&format!("failed to serialize to {path_str}"));

    // Write to file
    f.write(&buf).expect("failed to write to {path_str}");
}

pub fn read_from_file<S: CanonicalDeserialize>(path_str: &str) -> S {
    // Convert string to FS path
    let path = Path::new(path_str);

    // Open the file
    let mut f = OpenOptions::new()
        .read(true)
        .open(path)
        .expect(&format!("could not open {path_str} for reading"));

    // Read from file
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)
        .expect(&format!("failed to read from {path_str}"));

    // Deserialize the data
    S::deserialize_compressed_unchecked(buf.as_slice())
        .expect(&format!("failed to deserialize from {path_str}"))
}
