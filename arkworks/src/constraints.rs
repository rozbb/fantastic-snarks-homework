use crate::common::*;
use crate::{MerkleConfig, MerkleRoot, SimplePath};

use ark_crypto_primitives::crh::{
    constraints::CRHSchemeGadget, CRHScheme, TwoToOneCRHScheme, TwoToOneCRHSchemeGadget,
};
use ark_crypto_primitives::merkle_tree::{
    constraints::{BytesVarDigestConverter, DigestVarConverter},
    constraints::{ConfigGadget, PathVar},
};
use ark_r1cs_std::prelude::*;
use ark_relations::{
    ns,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};

type LeafVar<ConstraintF> = [UInt8<ConstraintF>];

// Define the merkle tree params in R1CS land
struct MerkleConfigGadget;
impl ConfigGadget<MerkleConfig, ConstraintF> for MerkleConfigGadget {
    type Leaf = LeafVar<ConstraintF>;
    type LeafDigest = <LeafHashGadget as CRHSchemeGadget<LeafHash, ConstraintF>>::OutputVar;
    type LeafInnerConverter = BytesVarDigestConverter<Self::LeafDigest, ConstraintF>;
    type InnerDigest =
        <TwoToOneHashGadget as TwoToOneCRHSchemeGadget<TwoToOneHash, ConstraintF>>::OutputVar;
    type LeafHash = LeafHashGadget;
    type TwoToOneHash = TwoToOneHashGadget;
}

// (You don't need to worry about what's going on in the next two type definitions,
// just know that these are types that you can use.)

/// The R1CS equivalent of the the Merkle tree root.
pub type RootVar =
    <TwoToOneHashGadget as TwoToOneCRHSchemeGadget<TwoToOneHash, ConstraintF>>::OutputVar;

/// The R1CS equivalent of the the Merkle tree path.
pub type SimplePathVar = PathVar<MerkleConfig, ConstraintF, MerkleConfigGadget>;

////////////////////////////////////////////////////////////////////////////////

#[derive(Clone)]
pub struct MerkleTreeVerification {
    // These are constants that will be embedded into the circuit
    pub leaf_crh_params: <LeafHash as CRHScheme>::Parameters,
    pub two_to_one_crh_params: <TwoToOneHash as TwoToOneCRHScheme>::Parameters,

    // Public inputs to the circuit
    pub root: MerkleRoot,
    pub leaf: Vec<u8>,

    // Private witnesses for the circuit
    pub note_opening: Note,
    pub auth_path: Option<SimplePath>,
}

impl ConstraintSynthesizer<ConstraintF> for MerkleTreeVerification {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        // First, we allocate the public inputs
        let root =
            <RootVar as AllocVar<MerkleRoot, _>>::new_input(
                ns!(cs, "root_var"),
                || Ok(&self.root),
            )?;

        // Then, we allocate the public parameters as constants:
        let leaf_crh_params = LeafHashParamsVar::new_constant(cs.clone(), &self.leaf_crh_params)?;
        let two_to_one_crh_params =
            TwoToOneHashParamsVar::new_constant(cs.clone(), &self.two_to_one_crh_params)?;

        // Witness the note. It itself is a secret, but its commitment is a public input
        let note_var = NoteVar::new_witness(ns!(cs, "note"), || Ok(&self.note_opening))?;

        // Input the note commitment. It is also the leaf in our tree.
        let note_com_var = UInt8::new_input_vec(ns!(cs, "note com"), &self.leaf)?;

        // First real check: make sure that note_com_var is the hash of note_var
        let note_hash = {
            let note_bytes = note_var.to_bytes()?;
            let hash = LeafHashGadget::evaluate(&leaf_crh_params, &note_bytes)?;
            hash.to_bytes()?
            //<MerkleConfigGadget as ConfigGadget<_, _>>::LeafInnerConverter::convert(hash)?
        };
        note_com_var.enforce_equal(&note_hash)?;

        // Finally, we allocate our path as a private witness variable:
        let path = SimplePathVar::new_witness(ns!(cs, "path_var"), || {
            Ok(self.auth_path.as_ref().unwrap())
        })?;

        // Now, we have to check membership. How do we do that?
        // Hint: look at https://github.com/arkworks-rs/crypto-primitives/blob/6be606259eab0aec010015e2cfd45e4f134cd9bf/src/merkle_tree/constraints.rs#L135

        // TODO: FILL IN THE BLANK!
        // let is_member = XYZ
        //
        // is_member.enforce_equal(&Boolean::TRUE)?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use ark_crypto_primitives::merkle_tree::{Config, DigestConverter};
    use ark_relations::r1cs::{ConstraintLayer, ConstraintSystem, TracingMode};
    use tracing_subscriber::layer::SubscriberExt;

    // Run this test via `cargo test --release test_merkle_tree`.
    #[test]
    fn merkle_tree_constraints_correctness() {
        // Let's set up an RNG for use within tests. Note that this is *not* safe
        // for any production use.
        let mut rng = ark_std::test_rng();

        // First, let's sample the public parameters for the hash functions:
        let leaf_crh_params = <LeafHash as CRHScheme>::setup(&mut rng).unwrap();
        let two_to_one_crh_params = <TwoToOneHash as TwoToOneCRHScheme>::setup(&mut rng).unwrap();

        // Next, let's construct our tree. The i-th entry in the vec! is the i-th leaf
        let tree = crate::SimpleMerkleTree::new(
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
            ],
        )
        .unwrap();

        // Now generate
        let auth_path = tree.generate_proof(4).unwrap();

        // First, let's get the root we want to verify against:
        let root = tree.root();

        // The value of the leaf that's allegedly in the tree
        let claimed_leaf_hash = b"9".to_vec();

        let circuit = MerkleTreeVerification {
            // constants
            leaf_crh_params,
            two_to_one_crh_params,

            // public inputs
            root,
            leaf: claimed_leaf_hash,

            // witness
            auth_path: Some(auth_path),
        };
        // First, some boilerplat that helps with debugging
        let mut layer = ConstraintLayer::default();
        layer.mode = TracingMode::OnlyConstraints;
        let subscriber = tracing_subscriber::Registry::default().with(layer);
        let _guard = tracing::subscriber::set_default(subscriber);

        // Next, let's make the circuit!
        let cs = ConstraintSystem::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        // Let's check whether the constraint system is satisfied
        let is_satisfied = cs.is_satisfied().unwrap();
        if !is_satisfied {
            // If it isn't, find out the offending constraint.
            println!("{:?}", cs.which_is_unsatisfied());
        }
        assert!(is_satisfied);
    }

    // Run this test via `cargo test --release test_merkle_tree_constraints_soundness`.
    // This tests that a given invalid authentication path will fail.
    #[test]
    fn merkle_tree_constraints_soundness() {
        // Let's set up an RNG for use within tests. Note that this is *not* safe
        // for any production use.
        let mut rng = ark_std::test_rng();

        // First, let's sample the public parameters for the hash functions:
        let leaf_crh_params = <LeafHash as CRHScheme>::setup(&mut rng).unwrap();
        let two_to_one_crh_params = <TwoToOneHash as TwoToOneCRHScheme>::setup(&mut rng).unwrap();

        // Next, let's construct our tree.
        // This follows the API in https://github.com/arkworks-rs/crypto-primitives/blob/6be606259eab0aec010015e2cfd45e4f134cd9bf/src/merkle_tree/mod.rs#L156
        let tree = crate::SimpleMerkleTree::new(
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

        // We just mutate the first leaf
        let second_tree = crate::SimpleMerkleTree::new(
            &leaf_crh_params,
            &two_to_one_crh_params,
            vec![
                &b"4"[..],
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

        // Now, let's try to generate a membership proof for the 5th item, i.e. 9.
        let proof = tree.generate_proof(4).unwrap(); // we're 0-indexing!

        // But, let's get the root we want to verify against:
        let wrong_root = second_tree.root();

        // The value of the leaf that's allegedly in the tree
        let claimed_leaf_hash = LeafHash::evaluate(&leaf_crh_params, &b"9"[..]).unwrap();
        let claimed_leaf_hash_bytes =
            <MerkleConfig as Config>::LeafInnerDigestConverter::convert(claimed_leaf_hash).unwrap();

        // Build the circuit. We'll use this for verification
        let circuit = MerkleTreeVerification {
            // constants
            leaf_crh_params,
            two_to_one_crh_params,

            // public inputs
            root: wrong_root,
            leaf: claimed_leaf_hash_bytes,

            // witness
            auth_path: Some(proof),
        };
        // First, some boilerplate that helps with debugging
        let mut layer = ConstraintLayer::default();
        layer.mode = TracingMode::OnlyConstraints;
        let subscriber = tracing_subscriber::Registry::default().with(layer);
        let _guard = tracing::subscriber::set_default(subscriber);

        // Next, let's make the constraint system!
        let cs = ConstraintSystem::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        // Let's check whether the constraint system is satisfied
        let is_satisfied = cs.is_satisfied().unwrap();
        // We expect this to fail!
        assert!(!is_satisfied);
    }
}
