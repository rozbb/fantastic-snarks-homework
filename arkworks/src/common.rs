use crate::MerkleConfig;

use core::borrow::Borrow;

use ark_bls12_381::Fr as F;
use ark_crypto_primitives::{
    crh::{
        constraints::{CRHSchemeGadget, TwoToOneCRHSchemeGadget},
        pedersen, CRHScheme,
    },
    merkle_tree::{Config, DigestConverter},
};
use ark_ed_on_bls12_381::{constraints::EdwardsVar as JubjubVar, EdwardsProjective as Jubjub};
use ark_ff::UniformRand;
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    bits::{uint8::UInt8, ToBytesGadget},
    fields::fp::FpVar,
};
use ark_relations::{
    ns,
    r1cs::{Namespace, SynthesisError},
};
use ark_serialize::CanonicalSerialize;
use rand::Rng;

pub type Leaf = [u8; 64];

/// A spendable "note". The leaves in our tree are note commitments.
#[derive(Clone, CanonicalSerialize)]
pub struct Note {
    pub amount: F,
    pub nullifier: F,
}

impl Note {
    /// Commits to `(self.amount, self.nullifier)` using `nonce` as the nonce. Concretely, this
    /// computes `Hash(nonce || amount || nulifier)`
    pub fn commit(&self, leaf_crh_params: &<LeafHash as CRHScheme>::Parameters, nonce: &F) -> Leaf {
        // This will be the buffer we feed into the hash function
        let mut buf = Vec::new();

        // Serialize the nonce
        nonce.serialize_uncompressed(&mut buf).unwrap();

        // Now serialize the note
        self.serialize_uncompressed(&mut buf).unwrap();

        // Now compute Hash(nonce || amount || nulifier)
        let claimed_leaf_hash = LeafHash::evaluate(&leaf_crh_params, buf.as_slice()).unwrap();

        <MerkleConfig as Config>::LeafInnerDigestConverter::convert(claimed_leaf_hash)
            .unwrap()
            .try_into()
            .unwrap()
    }
}

// Helpful for testing. This lets you generate a random Note.
impl UniformRand for Note {
    fn rand<R: Rng + ?Sized>(rng: &mut R) -> Self {
        Note {
            amount: F::rand(rng),
            nullifier: F::rand(rng),
        }
    }
}

pub type LeafHash = pedersen::CRH<Jubjub, LeafWindow>;
pub type TwoToOneHash = pedersen::TwoToOneCRH<Jubjub, TwoToOneWindow>;

// We use the leaf hash for note commitments as well. So it needs to handle inputs of 256*3-bits,
// or 96 bytes
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct LeafWindow;
impl pedersen::Window for LeafWindow {
    const WINDOW_SIZE: usize = 6;
    const NUM_WINDOWS: usize = 128;
}

// `WINDOW_SIZE * NUM_WINDOWS` > 2 * 512 bits = enough for hashing two outputs. Affine curve points
// are 512 bits because there currently isn't a DigestConverterGadget that knows how to do
// compressed curve points.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct TwoToOneWindow;
impl pedersen::Window for TwoToOneWindow {
    const WINDOW_SIZE: usize = 8;
    const NUM_WINDOWS: usize = 144;
}

pub type TwoToOneHashGadget =
    pedersen::constraints::TwoToOneCRHGadget<Jubjub, JubjubVar, TwoToOneWindow>;

pub type LeafHashGadget = pedersen::constraints::CRHGadget<Jubjub, JubjubVar, LeafWindow>;

pub type LeafHashParamsVar = <LeafHashGadget as CRHSchemeGadget<LeafHash, F>>::ParametersVar;
pub type TwoToOneHashParamsVar =
    <TwoToOneHashGadget as TwoToOneCRHSchemeGadget<TwoToOneHash, F>>::ParametersVar;

use ark_serialize::CanonicalDeserialize;
use std::{
    fs::OpenOptions,
    io::{Read, Write},
    path::Path,
};

pub const PEDERSEN_PARAMS_FILENAME: &str = "pedersen_params.bin";
pub const TESTCASE_GOOD_FILENAME: &str = "proof_package_good.bin";
pub const TESTCASE_BAD_FILENAME: &str = "proof_package_bad.bin";

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
    S::deserialize_compressed(buf.as_slice())
        .expect(&format!("failed to deserialize from {path_str}"))
}
