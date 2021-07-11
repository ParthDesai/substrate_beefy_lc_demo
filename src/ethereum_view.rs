use crate::block_generation::CommitmentPayload;
use crate::mmr::MMRNode;
use crate::types::{BlockNumber, HashOutput, LeafData, TestHeader};
use beefy_primitives::SignedCommitment;
use std::vec::Vec;

// Data structures that can be sent to ethereum by relayer
pub struct EthereumView {
    // Beefy mmr root (Technically this should be part of the block digest
    // but for simplicity it is kept here.
    pub(crate) beefy_mmr_root: MMRNode<LeafData>,
    pub(crate) beefy_mmr_leaves: u64,
    pub(crate) relay_header: TestHeader,
    // Optional signed commitment for this block
    pub(crate) signed_commitment:
        Option<SignedCommitment<BlockNumber, CommitmentPayload<LeafData>>>,

    pub para_header: TestHeader,
    pub para_header_merkle_proof: Vec<Vec<u8>>,
    pub para_header_merkle_root: HashOutput,
    // Proof of existence of selected kv pair
    pub(crate) chosen_kv_proof: Vec<Vec<u8>>,
    pub(crate) chosen_kv_pair: (Vec<u8>, Vec<u8>),
}
