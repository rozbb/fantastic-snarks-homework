use crate::common::*;
use crate::{MerkleConfig, MerkleRoot, SimplePath};

use core::borrow::Borrow;

use ark_bls12_381::Fr as F;
use ark_crypto_primitives::crh::{
    constraints::CRHSchemeGadget, CRHScheme, TwoToOneCRHScheme, TwoToOneCRHSchemeGadget,
};
use ark_crypto_primitives::merkle_tree::{
    constraints::{BytesVarDigestConverter, DigestVarConverter},
    constraints::{ConfigGadget, PathVar},
};
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::{
    ns,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, Namespace, SynthesisError},
};

type LeafVar<ConstraintF> = [UInt8<ConstraintF>];
pub type FV = FpVar<F>;

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
type SimplePathVar = PathVar<MerkleConfig, ConstraintF, MerkleConfigGadget>;

/// A spendable "note". The leaves in our tree are note commitments.
pub struct NoteVar {
    amount: FV,
    nullifier: FV,
}

impl ToBytesGadget<F> for NoteVar {
    fn to_bytes(&self) -> Result<Vec<UInt8<F>>, SynthesisError> {
        Ok([self.amount.to_bytes()?, self.nullifier.to_bytes()?].concat())
    }
}

impl NoteVar {
    pub fn commit(
        &self,
        hash_params: &LeafHashParamsVar,
        nonce: &FV,
    ) -> Result<Vec<UInt8<F>>, SynthesisError> {
        let nonce_bytes = nonce.to_bytes()?;
        let note_bytes = self.to_bytes()?;
        let hash = LeafHashGadget::evaluate(&hash_params, &[nonce_bytes, note_bytes].concat())?;
        hash.to_bytes()
    }
}

////////////////////////////////////////////////////////////////////////////////

#[derive(Clone)]
pub struct MerkleTreeVerification {
    // These are constants that will be embedded into the circuit
    pub leaf_crh_params: <LeafHash as CRHScheme>::Parameters,
    pub two_to_one_crh_params: <TwoToOneHash as TwoToOneCRHScheme>::Parameters,

    // Public inputs to the circuit
    pub root: MerkleRoot,
    pub leaf: Vec<u8>,
    pub note_nullifier: F,

    // Private witnesses for the circuit
    pub note_amount: F,
    pub note_nonce: F,
    pub auth_path: Option<SimplePath>,
}

impl ConstraintSynthesizer<ConstraintF> for MerkleTreeVerification {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        // First, we allocate the public inputs
        let root_var =
            <RootVar as AllocVar<MerkleRoot, _>>::new_input(ns!(cs, "root"), || Ok(&self.root))?;

        // Then, we allocate the public parameters as constants:
        let leaf_crh_params = LeafHashParamsVar::new_constant(cs.clone(), &self.leaf_crh_params)?;
        let two_to_one_crh_params =
            TwoToOneHashParamsVar::new_constant(cs.clone(), &self.two_to_one_crh_params)?;

        // Witness the amount, which is secret. Input the nullifier, which is public
        let note_var = {
            let amount = FV::new_witness(ns!(cs, "note amt"), || Ok(&self.note_amount))?;
            let nullifier = FV::new_input(ns!(cs, "note nullifier"), || Ok(&self.note_nullifier))?;
            NoteVar { amount, nullifier }
        };
        // Witness the commitment nonce
        let nonce_var = FV::new_witness(ns!(cs, "note nonce"), || Ok(&self.note_nonce))?;

        // Input the note commitment. It is also the leaf in our tree.
        let claimed_note_com_var = UInt8::new_input_vec(ns!(cs, "note com"), &self.leaf)?;

        // First real check: make sure that the computed commitment equals the claimed commitment
        let computed_note_com_var = note_var.commit(&leaf_crh_params, &nonce_var)?;
        computed_note_com_var.enforce_equal(&claimed_note_com_var)?;

        // Finally, we allocate our path as a private witness variable:
        let path = SimplePathVar::new_witness(ns!(cs, "path_var"), || {
            Ok(self.auth_path.as_ref().unwrap())
        })?;

        // Recompute the root from the given path
        let leaf_var = computed_note_com_var;
        let computed_root =
            path.calculate_root(&leaf_crh_params, &two_to_one_crh_params, &leaf_var)?;
        // Second real check: ensure that the computed root equals the claimed public root
        computed_root.enforce_equal(&root_var)?;

        // All good
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::SimpleMerkleTree;

    use ark_bls12_381::Fr as F;
    use ark_ff::UniformRand;
    use ark_relations::r1cs::{ConstraintLayer, ConstraintSystem, TracingMode};
    use rand::RngCore;
    use tracing_subscriber::layer::SubscriberExt;

    #[test]
    fn correctness_and_soundness() {
        // Let's set up an RNG for use within tests. Note that this is *not* safe
        // for any production use.
        let mut rng = ark_std::test_rng();

        // First, let's sample the public parameters for the hash functions:
        let leaf_crh_params = <LeafHash as CRHScheme>::setup(&mut rng).unwrap();
        let two_to_one_crh_params = <TwoToOneHash as TwoToOneCRHScheme>::setup(&mut rng).unwrap();

        // Make 7 random leaves
        let mut leaves: Vec<_> = core::iter::repeat_with(|| {
            let mut leaf_buf: Leaf = [0u8; 64];
            rng.fill_bytes(&mut leaf_buf);
            leaf_buf
        })
        .take(7)
        .collect();
        // Create a note and make the last leaf a commitment to that note
        let note = Note::rand(&mut rng);
        let note_nonce = F::rand(&mut rng);
        let note_com = note.commit(&leaf_crh_params, &note_nonce);
        leaves.push(note_com);

        // Generate the tree and compute the root
        let tree = SimpleMerkleTree::new(&leaf_crh_params, &two_to_one_crh_params, leaves.clone())
            .unwrap();
        let correct_root = tree.root();

        // Now generate the proof

        // We'll reveal and prove membership of the 7th item in the tree
        let idx_to_prove = 7;
        let claimed_leaf = &leaves[idx_to_prove];

        // Now, let's try to generate an authentication path for the 5th item.
        let auth_path = tree.generate_proof(idx_to_prove).unwrap();

        let circuit = MerkleTreeVerification {
            // Constants that the circuit needs
            leaf_crh_params,
            two_to_one_crh_params,

            // Public inputs to the circuit
            root: correct_root,
            leaf: claimed_leaf.to_vec(),
            note_nullifier: note.nullifier,

            // Witness to membership
            auth_path: Some(auth_path),
            note_amount: note.amount,
            note_nonce,
        };

        // First, some boilerplate that helps with debugging
        let mut layer = ConstraintLayer::default();
        layer.mode = TracingMode::OnlyConstraints;
        let subscriber = tracing_subscriber::Registry::default().with(layer);
        let _guard = tracing::subscriber::set_default(subscriber);

        // Make a fresh constraint system and run the circuit
        let cs = ConstraintSystem::new_ref();
        circuit.clone().generate_constraints(cs.clone()).unwrap();
        // This execution should succeed
        assert!(
            cs.is_satisfied().unwrap(),
            "circuit correctness check failed; a valid circuit did not succeed"
        );

        // Now modify the circuit to have a random amount. This should make the proof fail.
        let mut bad_note_circuit = circuit.clone();
        bad_note_circuit.note_amount = F::rand(&mut rng);
        // Run the circuit
        let cs = ConstraintSystem::new_ref();
        bad_note_circuit.generate_constraints(cs.clone()).unwrap();
        // One of the enforce_equals should fail
        assert!(
            !cs.is_satisfied().unwrap(),
            "circuit should not be satisfied after changing the note amount"
        );

        // Now modify the circuit to have a random root. This should make the proof fail.
        let mut bad_root_circuit = circuit.clone();
        bad_root_circuit.root = MerkleRoot::rand(&mut rng);
        // Run the circuit
        let cs = ConstraintSystem::new_ref();
        bad_root_circuit.generate_constraints(cs.clone()).unwrap();
        // One of the enforce_equals should fail
        assert!(
            !cs.is_satisfied().unwrap(),
            "circuit should not be satisfied after changing the merkle root"
        );
    }
}
