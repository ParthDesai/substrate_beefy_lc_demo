use crate::block_generation::verify_signed_commitment;
use crate::ethereum_view::EthereumView;
use crate::mmr::{MMRNode, MergeStrategy};
use crate::types::{HashOutput, HashingAlgo, LeafData, TestHeader, TrieLayout};
use crate::utils::mmr_size_from_number_of_leaves;
use beefy_primitives::crypto::AuthorityId;
use codec::Encode;
use mmr_lib::MerkleProof;
use std::vec::Vec;

pub struct EthereumActor {
    current_authorities: Vec<AuthorityId>,
    current_set_id: u64,
    last_finalized_block: Option<EthereumView>,
}

impl EthereumActor {
    pub fn new(initial_authorities: Vec<AuthorityId>, current_set_id: u64) -> Self {
        Self {
            current_authorities: initial_authorities,
            current_set_id,
            last_finalized_block: None,
        }
    }

    pub fn ingest_new_header(&mut self, ethereum_view: EthereumView) -> Result<(), String> {
        // Verify signed commitment
        if ethereum_view.signed_commitment.is_none() {
            return Err("Cannot ingest a block without signed commitment".to_string());
        }

        let signed_commitment = ethereum_view.signed_commitment.as_ref().unwrap();

        if signed_commitment.commitment.validator_set_id != self.current_set_id {
            return Err("Invalid validator set id".to_string());
        }

        let result = verify_signed_commitment(&signed_commitment, self.current_authorities.clone());
        if result.is_err() {
            return Err("Invalid signature".to_string());
        }

        if ethereum_view.relay_header.number != signed_commitment.commitment.block_number {
            return Err("Invalid block number".to_string());
        }

        if ethereum_view.beefy_mmr_root != signed_commitment.commitment.payload.mmr_node {
            return Err("MMR root not matching to that of block".to_string());
        }

        if signed_commitment
            .commitment
            .payload
            .changed_authority_ids
            .is_some()
        {
            self.current_authorities = signed_commitment
                .commitment
                .payload
                .changed_authority_ids
                .clone()
                .unwrap();
            self.current_set_id = signed_commitment.commitment.payload.new_validator_set_id;
        }

        self.last_finalized_block = Some(ethereum_view);

        Ok(())
    }

    pub fn verify_claim(
        &self,
        at_relay_block: TestHeader,
        beefy_mmr_proof_items: Vec<MMRNode<LeafData>>,
        block_pos_in_mmr: u64,
        para_block: TestHeader,
        para_block_inclusion_proof: Vec<Vec<u8>>,
        para_block_merkle_root: HashOutput,
        claimed_kv: (Vec<u8>, Vec<u8>),
        kv_proof: Vec<Vec<u8>>,
    ) -> Result<(), String> {
        if self.last_finalized_block.is_none() {
            return Err("Not ingested a block yet".to_string());
        }
        let last_finalized_block = self.last_finalized_block.as_ref().unwrap();

        if last_finalized_block.relay_header.number <= at_relay_block.number {
            return Err(
                "Cannot verify claims for last finalized block or after that block".to_string(),
            );
        }

        let mmr_root = last_finalized_block.beefy_mmr_root.clone();
        let mmr_size = mmr_size_from_number_of_leaves(last_finalized_block.beefy_mmr_leaves);

        println!("MMR root: {:?}, size: {}", mmr_root, mmr_size);

        let merkle_proof = MerkleProof::<_, MergeStrategy<LeafData, HashingAlgo>>::new(
            mmr_size,
            beefy_mmr_proof_items,
        );
        if !merkle_proof
            .verify(
                mmr_root,
                vec![(
                    block_pos_in_mmr,
                    MMRNode::Data((
                        at_relay_block.number,
                        at_relay_block.hash(),
                        para_block_merkle_root,
                    )),
                )],
            )
            .unwrap()
        {
            return Err("Block does not seems to be finalized".to_string());
        }

        // We now trust the para block merkle root
        // So, let's check if given para block is indeed part of that merkle root
        // if yes, that would mean that para block is finalized
        // and by extension the storage claim is also finalized.
        let items = vec![(para_block.hash(), Some(para_block.encode()))];
        if sp_trie::verify_trie_proof::<TrieLayout, _, _, _>(
            &para_block_merkle_root,
            &*para_block_inclusion_proof,
            items.iter(),
        )
        .is_err()
        {
            return Err("Unable to verify inclusion of parachain block".to_string());
        }

        // We now trust the para block
        let storage_root = para_block.state_root;
        let items = vec![(claimed_kv.0, Some(claimed_kv.1))];
        if sp_trie::verify_trie_proof::<TrieLayout, _, _, _>(
            &storage_root,
            &*kv_proof,
            items.iter(),
        )
        .is_err()
        {
            return Err("Unable to verify the storage claim".to_string());
        }

        Ok(())
    }
}
