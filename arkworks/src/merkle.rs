use crate::{
    hash::{LeafHash, LeafHashGadget, TwoToOneHash, TwoToOneHashGadget},
    F,
};

use ark_crypto_primitives::{
    crh::{CRHScheme, TwoToOneCRHScheme},
    merkle_tree::{ByteDigestConverter, Config, MerkleTree, Path},
};

use ark_crypto_primitives::crh::{constraints::CRHSchemeGadget, TwoToOneCRHSchemeGadget};
use ark_crypto_primitives::merkle_tree::constraints::{
    BytesVarDigestConverter, ConfigGadget, PathVar,
};
use ark_r1cs_std::uint8::UInt8;

//
// NATIVE IMPLEMENTATIONS
//

/// Every leaf in our Merkle tree is just 64-byte bytestring
pub type Leaf = [u8; 64];

/// Defines how leaves are hashed alone and together, as well as how the digest is converted so it
/// can be input to the next hash function up.
#[derive(Clone)]
pub struct MerkleConfig;

impl Config for MerkleConfig {
    type Leaf = [u8];

    // This is an elliptic curve point
    type LeafDigest = <LeafHash as CRHScheme>::Output;
    // This just serializes the elliptic curve point into bytes, uncompressed
    type LeafInnerDigestConverter = ByteDigestConverter<Self::LeafDigest>;
    // Also an elliptic curve point
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

//
// R1CS IMPLEMENTATIONS
//

/// R1CS representation of a Leaf. Remember a Leaf is just a Vec<u8>, so this is a Vec<UInt8<F>>
pub type LeafVar<F> = [UInt8<F>];

/// Merkle tree params for R1CS. This is analogous to our MerkleConfig implementation
pub struct MerkleConfigGadget;
impl ConfigGadget<MerkleConfig, F> for MerkleConfigGadget {
    type Leaf = LeafVar<F>;
    type LeafDigest = <LeafHashGadget as CRHSchemeGadget<LeafHash, F>>::OutputVar;
    type LeafInnerConverter = BytesVarDigestConverter<Self::LeafDigest, F>;
    type InnerDigest = <TwoToOneHashGadget as TwoToOneCRHSchemeGadget<TwoToOneHash, F>>::OutputVar;
    type LeafHash = LeafHashGadget;
    type TwoToOneHash = TwoToOneHashGadget;
}

/// R1CS representation of MerkleRoot, the Merkle tree root
pub type RootVar = <TwoToOneHashGadget as TwoToOneCRHSchemeGadget<TwoToOneHash, F>>::OutputVar;

/// R1CS representation of SimplePath, i.e., the Merkle tree path
pub type SimplePathVar = PathVar<MerkleConfig, F, MerkleConfigGadget>;
