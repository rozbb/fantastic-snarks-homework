use ark_crypto_primitives::crh::{
    constraints::{CRHSchemeGadget, TwoToOneCRHSchemeGadget},
    pedersen,
};
use ark_ed_on_bls12_381::{constraints::EdwardsVar as JubjubVar, EdwardsProjective as Jubjub};
use ark_serialize::CanonicalSerialize;

pub type TwoToOneHash = pedersen::TwoToOneCRH<Jubjub, TwoToOneWindow>;
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct TwoToOneWindow;

// `WINDOW_SIZE * NUM_WINDOWS` > 2 * 512 bits = enough for hashing two outputs. Affine curve points
// are 512 bits because there currently isn't a DigestConverterGadget that knows how to do
// compressed curve points.
impl pedersen::Window for TwoToOneWindow {
    const WINDOW_SIZE: usize = 8;
    const NUM_WINDOWS: usize = 144;
}

pub type LeafHash = pedersen::CRH<Jubjub, LeafWindow>;

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct LeafWindow;

// We let leaves be bytestrings of length at most 16, i.e., bitlength at most 128. Thus we need
// WINDOW_SIZE * NUM_WINDOWS to be at least 128.
impl pedersen::Window for LeafWindow {
    const WINDOW_SIZE: usize = 1;
    const NUM_WINDOWS: usize = 128;
}

pub type TwoToOneHashGadget =
    pedersen::constraints::TwoToOneCRHGadget<Jubjub, JubjubVar, TwoToOneWindow>;

pub type LeafHashGadget = pedersen::constraints::CRHGadget<Jubjub, JubjubVar, LeafWindow>;

pub type LeafHashParamsVar =
    <LeafHashGadget as CRHSchemeGadget<LeafHash, ConstraintF>>::ParametersVar;
pub type TwoToOneHashParamsVar =
    <TwoToOneHashGadget as TwoToOneCRHSchemeGadget<TwoToOneHash, ConstraintF>>::ParametersVar;

pub type ConstraintF = ark_ed_on_bls12_381::Fq;

use std::{fs::OpenOptions, io::Write, path::Path};

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
    data.serialize_uncompressed(&mut buf)
        .expect(&format!("failed to serialize to {path_str}"));

    // Write to file
    f.write(&buf).expect("failed to write to {path_str}");
}
