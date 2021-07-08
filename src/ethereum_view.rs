use crate::block_generation::CommitmentPayload;
use crate::mmr::MMRNode;
use crate::types::{BlockNumber, HashOutput, TestHeader};
use beefy_primitives::SignedCommitment;
use std::vec::Vec;

// Data structures that can be sent to ethereum by relayer
pub struct EthereumView {
    // Beefy mmr root (Technically this should be part of the block digest
    // but for simplicity it is kept here.
    pub(crate) beefy_mmr_root: MMRNode<(BlockNumber, HashOutput)>,
    pub(crate) beefy_mmr_leaves: u64,
    pub(crate) header: TestHeader,
    // Optional signed commitment for this block
    pub(crate) signed_commitment:
        Option<SignedCommitment<BlockNumber, CommitmentPayload<(u64, HashOutput)>>>,
    // Proof of existence of selected kv pair
    pub(crate) chosen_kv_proof: Vec<Vec<u8>>,
    pub(crate) chosen_kv_pair: (Vec<u8>, Vec<u8>),
}
