use crate::{
    hash::{LeafHash, LeafHashParamsVar, TwoToOneHash, TwoToOneHashParamsVar},
    merkle::{MerkleRoot, RootVar, SimplePath, SimplePathVar},
    note::NoteVar,
    F, FV,
};

use ark_crypto_primitives::crh::{CRHScheme, TwoToOneCRHScheme};
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, uint8::UInt8};
use ark_relations::{
    ns,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};

/// Our ZK circuit. This is what we will create and pass to the Groth16 prover in order to do a ZK
/// Burn
#[derive(Clone)]
pub struct BurnCircuit {
    // These are constants that will be embedded into the circuit. They describe how the hash
    // function works. Don't worry about this.
    pub leaf_crh_params: <LeafHash as CRHScheme>::Parameters,
    pub two_to_one_crh_params: <TwoToOneHash as TwoToOneCRHScheme>::Parameters,

    // Public inputs to the circuit
    /// The root of the merkle tree we're proving membership in
    pub root: MerkleRoot,
    /// The leaf in that tree. In our case, the leaf is also a commitment to the note we're burning
    pub leaf: Vec<u8>,
    /// The nullifier of the note. This is a random value unique to every note. If we burn a note,
    /// revealing its nullifier, then any future burns of the same note will clearly be duplicates,
    /// because an observer can check for a repeated nullifier.
    pub note_nullifier: F,

    // Private inputs (aka "witnesses") for the circuit
    /// The amount of "money" contained in the note
    pub note_amount: F,
    /// The private nonce (i.e. randomness) used to commit to the note
    pub note_nonce: F,
    /// The merkle authentication path. Assuming the hash we use is secure, this path is proof that
    /// the committed leaf is in the tree.
    pub auth_path: Option<SimplePath>,
}

/// generate_constraints is where the circuit functionality is defined. It doesn't return any
/// value. Rather, it takes in a constraint system, and adds a bunch of constraints to that system
/// (implicitly or explicitly). A proof is valid if and only if the final constraint system is
/// satisfied.
impl ConstraintSynthesizer<F> for BurnCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // First, allocate the public parameters as constants
        let leaf_crh_params = LeafHashParamsVar::new_constant(cs.clone(), &self.leaf_crh_params)?;
        let two_to_one_crh_params =
            TwoToOneHashParamsVar::new_constant(cs.clone(), &self.two_to_one_crh_params)?;

        //
        // Next, allocate the public inputs. Note the ns! macros are just to create name spaces for
        // our constraints. It doesn't matter what this does, and it doesn't matter what string you
        // give it.
        //

        // Merkle root
        let claimed_root_var =
            <RootVar as AllocVar<MerkleRoot, _>>::new_input(ns!(cs, "root"), || Ok(&self.root))?;
        // Nullifier of the note. This is public so you can only burn a note once
        let note_nullifier = FV::new_input(ns!(cs, "note nullifier"), || Ok(&self.note_nullifier))?;
        // Note commitment. This is also the leaf in our tree.
        let claimed_note_com_var = UInt8::new_input_vec(ns!(cs, "note com"), &self.leaf)?;

        //
        // Now we witness our private inputs
        //

        // The amount of "money" in this note
        let note_amount = FV::new_witness(ns!(cs, "note amt"), || Ok(&self.note_amount))?;
        // Commitment nonce
        let nonce_var = FV::new_witness(ns!(cs, "note nonce"), || Ok(&self.note_nonce))?;
        // Merkle authentication path
        let path = SimplePathVar::new_witness(ns!(cs, "merkle path"), || {
            Ok(self.auth_path.as_ref().unwrap())
        })?;

        //
        // Ok everything has been inputted. Now we do the logic of the circuit.
        //

        // Put the pieces of our note together into a NoteVar
        let note_var = NoteVar {
            amount: note_amount,
            nullifier: note_nullifier,
        };

        // CHECK #1: Note opening.
        // We "open" the note commitment here. Concretely, we compute the commitment of our
        // note_var using nonce_var. We then assert that this value is equal to the publicly known
        // commitment.
        let computed_note_com_var = note_var.commit(&leaf_crh_params, &nonce_var)?;
        computed_note_com_var.enforce_equal(&claimed_note_com_var)?;

        // CHECK #2: Membership test.
        // We prove membership of the nonce commitment in the Merkle tree. Concretely, we use the
        // leaf from above and path_var to recompute the Merkle root. We then assert that this root
        // is equal to the publicly known root.
        let leaf_var = computed_note_com_var;
        let computed_root_var =
            path.calculate_root(&leaf_crh_params, &two_to_one_crh_params, &leaf_var)?;
        computed_root_var.enforce_equal(&claimed_root_var)?;

        // All done with the checks
        Ok(())
    }
}

//
// TESTS
//

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        merkle::{Leaf, SimpleMerkleTree},
        note::Note,
    };

    use ark_bls12_381::Fr as F;
    use ark_ff::UniformRand;
    use ark_relations::r1cs::{ConstraintLayer, ConstraintSystem, TracingMode};
    use rand::RngCore;
    use tracing_subscriber::layer::SubscriberExt;

    #[test]
    fn correctness_and_soundness() {
        //
        // Setup
        //

        // Let's set up an RNG for use within tests. Note that this is NOTE safe for any production
        // use
        let mut rng = ark_std::test_rng();

        // First, let's sample the public parameters for the hash functions
        let leaf_crh_params = <LeafHash as CRHScheme>::setup(&mut rng).unwrap();
        let two_to_one_crh_params = <TwoToOneHash as TwoToOneCRHScheme>::setup(&mut rng).unwrap();

        // Make 7 random leaves. These aren't even commitments. Technically, these are
        // distinguishable from commitments because our "hash function" is not a PRF. But I don't
        // care. This is a test.
        let num_placeholder_leaves = 7;
        let mut leaves: Vec<_> = core::iter::repeat_with(|| {
            let mut leaf_buf: Leaf = [0u8; 64];
            rng.fill_bytes(&mut leaf_buf);
            leaf_buf
        })
        .take(num_placeholder_leaves)
        .collect();

        // Create a note and make the last leaf a commitment to that note
        let note = Note::rand(&mut rng);
        let note_nonce = F::rand(&mut rng);
        let note_com = note.commit(&leaf_crh_params, &note_nonce);
        leaves.push(note_com);

        // Create the tree and compute the Merkle root
        let tree = SimpleMerkleTree::new(&leaf_crh_params, &two_to_one_crh_params, leaves.clone())
            .unwrap();
        let correct_root = tree.root();

        //
        // Proof construction
        //

        // We'll reveal and prove membership of the 8th leaf in the tree, i.e., the note we just
        // created.
        let idx_to_prove = num_placeholder_leaves;
        let claimed_leaf = &leaves[idx_to_prove];

        // Generate a Merkle authentication path that proves the membership of the 8th leaf
        let auth_path = tree.generate_proof(idx_to_prove).unwrap();

        // We have everything we need. Build the circuit
        let circuit = BurnCircuit {
            // Constants for hashing
            leaf_crh_params,
            two_to_one_crh_params,

            // Public inputs
            root: correct_root,
            leaf: claimed_leaf.to_vec(),
            note_nullifier: note.nullifier,

            // Private inputs
            auth_path: Some(auth_path),
            note_amount: note.amount,
            note_nonce,
        };

        //
        // Proof execution
        //

        // First, some boilerplate that helps with debugging
        let mut layer = ConstraintLayer::default();
        layer.mode = TracingMode::OnlyConstraints;
        let subscriber = tracing_subscriber::Registry::default().with(layer);
        let _guard = tracing::subscriber::set_default(subscriber);

        // Correctness test: Make a fresh constraint system and run the circuit.
        let cs = ConstraintSystem::new_ref();
        circuit.clone().generate_constraints(cs.clone()).unwrap();
        // This execution should succeed
        assert!(
            cs.is_satisfied().unwrap(),
            "circuit correctness check failed; a valid circuit did not succeed"
        );

        // Soundness test #1: Modify the circuit to have a random amount. This should make the
        // proof fail.
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

        // Soundness test #2: Modify the circuit to have a random root. This should also make the
        // proof fail.
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
