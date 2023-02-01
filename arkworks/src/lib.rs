pub mod common;
use crate::common::*;

use ark_ff::Field;

pub mod constraints;
// mod constraints_test;

use ark_crypto_primitives::{
    crh::{CRHScheme, TwoToOneCRHScheme},
    merkle_tree::{
        constraints::ConfigGadget, ByteDigestConverter, Config, DigestConverter, MerkleTree, Path,
    },
    Error as ArkError,
};
use ark_serialize::CanonicalSerialize;

#[derive(Clone)]
pub struct MerkleConfig;

impl Config for MerkleConfig {
    type Leaf = [u8];

    type LeafDigest = <LeafHash as CRHScheme>::Output;
    type LeafInnerDigestConverter = ByteDigestConverter<Self::LeafDigest>;
    type InnerDigest = <TwoToOneHash as TwoToOneCRHScheme>::Output;

    type LeafHash = LeafHash;
    type TwoToOneHash = TwoToOneHash;
}

/// A Merkle tree containing account information.
pub type SimpleMerkleTree = MerkleTree<MerkleConfig>;
/// The root of the account Merkle tree.
pub type MerkleRoot = <TwoToOneHash as TwoToOneCRHScheme>::Output;
/// A membership proof for a given account.
pub type SimplePath = Path<MerkleConfig>;

// Run this test via `cargo test --release test_merkle_tree`.
#[test]
fn test_merkle_tree() {
    use ark_crypto_primitives::crh::CRHScheme;
    // Let's set up an RNG for use within tests. Note that this is *not* safe
    // for any production use.
    let mut rng = ark_std::test_rng();

    // First, let's sample the public parameters for the hash functions:
    let leaf_crh_params = <LeafHash as CRHScheme>::setup(&mut rng).unwrap();
    let two_to_one_crh_params = <TwoToOneHash as TwoToOneCRHScheme>::setup(&mut rng).unwrap();

    // Next, let's construct our tree.
    // This follows the API in https://github.com/arkworks-rs/crypto-primitives/blob/6be606259eab0aec010015e2cfd45e4f134cd9bf/src/merkle_tree/mod.rs#L156
    let tree = SimpleMerkleTree::new(
        &leaf_crh_params,
        &two_to_one_crh_params,
        vec![
            &b"1"[..],
            &b"2"[..],
            &b"3"[..],
            &b"10"[..],
            &b"9"[..],
            &b"17"[..],
            &b"70"[..],
            &b"45"[..],
        ], // the i-th entry is the i-th leaf.
    )
    .unwrap();

    // Now, let's try to generate a membership proof for the 5th item.
    let proof = tree.generate_proof(4).unwrap(); // we're 0-indexing!
                                                 // This should be a proof for the membership of a leaf with value 9. Let's check that!

    // First, let's get the root we want to verify against:
    let root = tree.root();
    // The value of the leaf that's allegedly in the tree
    let claimed_leaf = &b"9"[..];
    // Next, let's verify the proof!
    let result = proof
        .verify(
            &leaf_crh_params,
            &two_to_one_crh_params,
            &root,
            claimed_leaf,
        )
        .unwrap();
    assert!(result);
}
