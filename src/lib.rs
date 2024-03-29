pub mod util;

pub mod card;
pub mod constraints;
pub mod constraints_showprice;
pub mod hash;
pub mod merkle;

use ark_r1cs_std::fields::fp::FpVar;

/// The bilinear pairing we will be using for our Groth16 proofs
pub type E = ark_bls12_381::Bls12_381;
/// A field element over BLS12-381. That is, the curve that our exercise uses for everything
pub type F = ark_bls12_381::Fr;

/// R1CS representation of a field element
pub type FV = FpVar<F>;

// This is a basic functionality test of the native Merkle tree. This does no ZK operations at all.
// It just checks that you can prove membership in a tree by giving a verifier the Merkle
// authentication path.
#[test]
fn test_merkle_tree() {
    use crate::{
        card::Card,
        hash::{LeafHash, TwoToOneHash},
        merkle::SimpleMerkleTree,
    };
    use ark_crypto_primitives::crh::{CRHScheme, TwoToOneCRHScheme};
    use ark_ff::UniformRand;

    // Let's set up an RNG for use within tests. Note that this is NOT safe for any production use.
    let mut rng = ark_std::test_rng();

    // First, sample the public parameters for the hash functions:
    let leaf_crh_params = <LeafHash as CRHScheme>::setup(&mut rng).unwrap();
    let two_to_one_crh_params = <TwoToOneHash as TwoToOneCRHScheme>::setup(&mut rng).unwrap();

    // Make 16 commitments and put them in the tree. For unimportant reasons, this must be a power
    // of two
    let num_leaves = 16;
    let leaves: Vec<_> = core::iter::repeat_with(|| {
        let card = Card::rand(&mut rng);
        let card_com_rand = F::rand(&mut rng);
        card.commit(&leaf_crh_params, &card_com_rand)
    })
    .take(num_leaves)
    .collect();

    // Construct a Merkle tree with 8 leaves
    let tree =
        SimpleMerkleTree::new(&leaf_crh_params, &two_to_one_crh_params, leaves.clone()).unwrap();

    // Generate a membership proof for the 5th item.
    let idx_to_prove = 4;
    let proof = tree.generate_proof(idx_to_prove).unwrap();

    //
    // Verification
    //

    // Get the root we want to verify against
    let root = tree.root();
    // Get the value of the leaf that's allegedly in the tree
    let claimed_leaf = leaves[idx_to_prove].as_slice();
    // Verify the proof
    assert!(proof
        .verify(
            &leaf_crh_params,
            &two_to_one_crh_params,
            &root,
            claimed_leaf,
        )
        .unwrap());
}
