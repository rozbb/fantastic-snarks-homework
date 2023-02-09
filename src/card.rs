use crate::{
    hash::{LeafHash, LeafHashGadget, LeafHashParamsVar},
    merkle::{Leaf, MerkleConfig},
    F, FV,
};

use ark_crypto_primitives::{
    crh::{constraints::CRHSchemeGadget, CRHScheme},
    merkle_tree::{Config, DigestConverter},
};
use ark_ff::UniformRand;
use ark_r1cs_std::{uint8::UInt8, ToBytesGadget};
use ark_relations::r1cs::SynthesisError;
use ark_serialize::CanonicalSerialize;
use rand::Rng;

//
// NATIVE IMPLEMENTATIONS
//

/// A baseball card. The leaves in our tree are card commitments.
#[derive(Clone, CanonicalSerialize)]
pub struct Card {
    pub purchase_price: F,
    pub serial_num: F,
}

impl Card {
    /// Commits to `(self.amount, self.nullifier)` using `nonce` as the nonce. Concretely, this
    /// computes `Hash(nonce || amount || nulifier)`
    pub fn commit(&self, leaf_crh_params: &<LeafHash as CRHScheme>::Parameters, nonce: &F) -> Leaf {
        // This will be the buffer we feed into the hash function
        let mut buf = Vec::new();

        // Serialize the nonce
        nonce.serialize_uncompressed(&mut buf).unwrap();

        // Now serialize the card
        self.serialize_uncompressed(&mut buf).unwrap();

        // Now compute Hash(nonce || amount || nulifier)
        let claimed_leaf_hash = LeafHash::evaluate(&leaf_crh_params, buf.as_slice()).unwrap();

        <MerkleConfig as Config>::LeafInnerDigestConverter::convert(claimed_leaf_hash)
            .unwrap()
            .try_into()
            .unwrap()
    }
}

// Helpful for testing. This lets you generate a random Card.
impl UniformRand for Card {
    fn rand<R: Rng + ?Sized>(rng: &mut R) -> Self {
        Card {
            purchase_price: F::rand(rng),
            serial_num: F::rand(rng),
        }
    }
}

//
// R1CS IMPLEMENTATIONS
//

/// R1CS representation of Card
pub struct CardVar {
    pub amount: FV,
    pub nullifier: FV,
}

/// Defines a way to serialize a CardVar to bytes. This is only works if it is identical to the
/// `impl CanonicalSerialize for Card` serialization.
impl ToBytesGadget<F> for CardVar {
    fn to_bytes(&self) -> Result<Vec<UInt8<F>>, SynthesisError> {
        // Serialize self.amount then self.nullifier
        Ok([self.amount.to_bytes()?, self.nullifier.to_bytes()?].concat())
    }
}

impl CardVar {
    /// Commits to this card using the given nonce. Concretely, this computes `Hash(nonce ||
    /// self.amount || self.nullifier)`.
    pub fn commit(
        &self,
        hash_params: &LeafHashParamsVar,
        nonce: &FV,
    ) -> Result<Vec<UInt8<F>>, SynthesisError> {
        let nonce_bytes = nonce.to_bytes()?;
        let card_bytes = self.to_bytes()?;
        let hash = LeafHashGadget::evaluate(&hash_params, &[nonce_bytes, card_bytes].concat())?;
        hash.to_bytes()
    }
}
