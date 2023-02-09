use crate::F;

use ark_crypto_primitives::crh::{
    constraints::{CRHSchemeGadget, TwoToOneCRHSchemeGadget},
    pedersen, CRHScheme, TwoToOneCRHScheme,
};
use ark_ed_on_bls12_381::{constraints::EdwardsVar as JubjubVar, EdwardsProjective as Jubjub};

pub type LeafHash = pedersen::CRH<Jubjub, LeafWindow>;
pub type TwoToOneHash = pedersen::TwoToOneCRH<Jubjub, TwoToOneWindow>;
pub type LeafHashParams = <LeafHash as CRHScheme>::Parameters;
pub type TwoToOneHashParams = <TwoToOneHash as TwoToOneCRHScheme>::Parameters;

// We use the leaf hash for card commitments as well. So it needs to handle inputs of 256*3-bits,
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
