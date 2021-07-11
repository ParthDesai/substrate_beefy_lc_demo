use crate::block_generation::CommitmentPayload;
use crate::ethereum_view::EthereumView;
use crate::mmr::{MMRNode, MergeStrategy};
use crate::types::{BlockNumber, HashOutput, HashingAlgo, LeafData, TestHeader};
use crate::utils::mmr_size_from_number_of_leaves;
use beefy_primitives::crypto::{AuthorityId, Pair};
use beefy_primitives::SignedCommitment;
use codec::{Decode, Encode};
use mmr_lib::util::{MemMMR, MemStore};
use std::vec::Vec;

pub struct BlockData {
    // Beefy mmr store
    pub beefy_mmr_store: MemStore<MMRNode<LeafData>>,
    pub beefy_mmr_leaves: u64,
    // Header must contain digest entry for MMR root
    pub relay_header: TestHeader,
    // Optional signed commitment for this block
    pub signed_commitment: Option<SignedCommitment<BlockNumber, CommitmentPayload<LeafData>>>,

    // Current Beefy authority set
    pub current_authority_set: Vec<(Pair, AuthorityId)>,
    pub current_authority_set_id: u64,

    // Parachain header
    pub para_header: TestHeader,
    pub encoded_para_head_data: Vec<(HashOutput, Vec<u8>)>,
    // Proof of existence of selected kv pair in parachain header's storage root
    pub para_header_merkle_proof: Vec<Vec<u8>>,
    pub para_header_merkle_root: HashOutput,
    pub chosen_kv_proof: Vec<Vec<u8>>,
    pub chosen_kv_pair: (Vec<u8>, Vec<u8>),
}

impl BlockData {
    pub fn ethereum_view(&self) -> EthereumView {
        let mem_mmr = MemMMR::<_, MergeStrategy<LeafData, HashingAlgo>>::new(
            mmr_size_from_number_of_leaves(self.beefy_mmr_leaves),
            self.beefy_mmr_store.clone(),
        );
        let root = mem_mmr.get_root().unwrap();

        let cloned_signed_commitment = if self.signed_commitment.is_none() {
            None
        } else {
            let encoded_signed_commitment = self.signed_commitment.as_ref().encode();
            Decode::decode(&mut encoded_signed_commitment.as_slice()).unwrap()
        };

        EthereumView {
            beefy_mmr_root: root,
            beefy_mmr_leaves: self.beefy_mmr_leaves,
            relay_header: self.relay_header.clone(),
            signed_commitment: cloned_signed_commitment,
            para_header: self.para_header.clone(),
            para_header_merkle_proof: self.para_header_merkle_proof.clone(),
            chosen_kv_proof: self.chosen_kv_proof.clone(),
            chosen_kv_pair: self.chosen_kv_pair.clone(),
            para_header_merkle_root: self.para_header_merkle_root.clone(),
        }
    }
}
