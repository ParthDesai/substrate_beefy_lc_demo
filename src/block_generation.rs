use crate::block_data::BlockData;
use crate::mmr::{MMRNode, MergeStrategy};
use crate::traits::Hashable;
use crate::types::{HashingAlgo, LeafData, TestHeader, TrieLayout};
use crate::utils::mmr_size_from_number_of_leaves;
use beefy_primitives::crypto::{AuthorityId, AuthoritySignature, Pair};
use beefy_primitives::{Commitment, SignedCommitment};
use codec::{Decode, Encode};
use mmr_lib::util::{MemMMR, MemStore};
use rand::prelude::*;
use rand::rngs::StdRng;
use sp_core::crypto::Pair as _;
use sp_core::{Hasher, KeccakHasher};
use sp_runtime::RuntimeAppPublic;
use sp_trie::{MemoryDB, TrieDBMut, TrieMut};
use std::vec::Vec;

#[derive(Encode, Decode)]
pub struct CommitmentPayload<Leaf: Hashable + Encode + Decode> {
    pub mmr_node: MMRNode<Leaf>,
    pub changed_authority_ids: Option<Vec<AuthorityId>>,
    pub new_validator_set_id: u64,
}

fn generate_signed_commitment<TBlockNumber: Encode, TPayload: Encode>(
    set_id: u64,
    block_number: TBlockNumber,
    payload: TPayload,
    validator_pairs: &Vec<Pair>,
) -> SignedCommitment<TBlockNumber, TPayload> {
    let commitment = Commitment {
        payload,
        block_number,
        validator_set_id: set_id,
    };

    let signatures: Vec<Option<AuthoritySignature>> = validator_pairs
        .iter()
        .map(|k| Some(k.sign(commitment.encode().as_ref())))
        .collect();

    SignedCommitment {
        commitment,
        signatures,
    }
}

pub fn verify_signed_commitment<TBlockNumber: Encode, TPayload: Encode>(
    signed_commitment: &SignedCommitment<TBlockNumber, TPayload>,
    initial_authorities: Vec<AuthorityId>,
) -> Result<(), String> {
    if signed_commitment.signatures.len() != initial_authorities.len() {
        return Err("Number of signatures differ".to_string());
    }

    let encoded_commitment = signed_commitment.commitment.encode();
    for (i, maybe_signature) in signed_commitment.signatures.iter().enumerate() {
        if maybe_signature.is_none() {
            return Err("No signature at a position".to_string());
        }
        if !initial_authorities[i].verify(&encoded_commitment, &maybe_signature.as_ref().unwrap()) {
            return Err("Signature is invalid".to_string());
        }
    }
    Ok(())
}

fn generate_random_storage_and_proof() -> (
    sp_trie::MemoryDB<sp_core::KeccakHasher>,
    <sp_core::KeccakHasher as Hasher>::Out,
    (Vec<u8>, Vec<u8>),
    Vec<Vec<u8>>,
) {
    let mut rng = StdRng::from_entropy();
    let random_kvs = rng.next_u64() % 100 + 1;
    let generate_proof_for_index = rng.next_u64() % random_kvs;

    let mut trie_db = sp_trie::MemoryDB::<sp_core::KeccakHasher>::default();
    let mut trie_root = sp_trie::empty_trie_root::<TrieLayout>();

    let mut chosen_key = [0u8; 32];
    let mut chosen_value = [0u8; 64];

    {
        let mut trie = sp_trie::TrieDBMut::<TrieLayout>::new(&mut trie_db, &mut trie_root);
        let mut key = [0u8; 32];
        let mut value = [0u8; 64];
        for i in 0..random_kvs + 1 {
            rng.fill(&mut key);
            rng.fill(&mut value);
            trie.insert(&key, &value).unwrap();
            if i == generate_proof_for_index {
                chosen_key.copy_from_slice(&key);
                chosen_value.copy_from_slice(&value);
            }
        }
    }

    let proof =
        sp_trie::generate_trie_proof::<TrieLayout, _, _, _>(&trie_db, trie_root, vec![&chosen_key])
            .unwrap();

    return (
        trie_db,
        trie_root,
        (chosen_key.to_vec(), chosen_value.to_vec()),
        proof,
    );
}

pub fn create_random_child_block(
    block_data: Option<&BlockData>,
    should_generate_commitment: bool,
    new_authority_set: Option<Vec<(Pair, AuthorityId)>>,
) -> BlockData {
    let (_storage_trie_db, storage_trie_root, chosen_kv_pair, chosen_kv_proof) =
        generate_random_storage_and_proof();
    if block_data.is_none() {
        let genesis_para_header = TestHeader {
            parent_hash: Default::default(),
            number: 1,
            state_root: storage_trie_root,
            extrinsics_root: Default::default(),
            digest: Default::default(),
        };
        let encoded_para_heads = vec![(genesis_para_header.hash(), genesis_para_header.encode())];

        let mut memdb = MemoryDB::<KeccakHasher>::default();
        let mut current_para_heads_merkle_root = Default::default();
        {
            let mut trie_db =
                TrieDBMut::<TrieLayout>::new(&mut memdb, &mut current_para_heads_merkle_root);
            for (block_hash, para_head) in encoded_para_heads.iter() {
                trie_db.insert(block_hash.as_ref(), para_head).unwrap();
            }
        }

        let para_heads_merkle_proof = sp_trie::generate_trie_proof::<TrieLayout, _, _, _>(
            &memdb,
            current_para_heads_merkle_root,
            vec![&genesis_para_header.hash()],
        )
        .unwrap();

        // This is root
        BlockData {
            chosen_kv_pair,
            chosen_kv_proof,
            beefy_mmr_store: MemStore::<MMRNode<LeafData>>::default(),
            beefy_mmr_leaves: 0,
            relay_header: TestHeader {
                parent_hash: Default::default(),
                number: 1,
                state_root: Default::default(),
                extrinsics_root: Default::default(),
                digest: Default::default(),
            },
            para_header: genesis_para_header,
            encoded_para_head_data: encoded_para_heads,
            para_header_merkle_proof: para_heads_merkle_proof,
            signed_commitment: None,
            current_authority_set: new_authority_set.expect("Genesis needs initial authority set"),
            current_authority_set_id: 0,
            para_header_merkle_root: current_para_heads_merkle_root,
        }
    } else {
        if new_authority_set.is_some() && !should_generate_commitment {
            panic!("We must generate commitment when enacting new authority set");
        }

        let previous_block_data = block_data.unwrap();

        let previous_relay_header_hash = previous_block_data.relay_header.hash();
        let previous_relay_header_number = previous_block_data.relay_header.number;

        let previous_para_header_hash = previous_block_data.para_header.hash();
        let previous_para_header_number = previous_block_data.para_header.number;

        let new_para_header = TestHeader {
            parent_hash: previous_para_header_hash,
            number: previous_para_header_number + 1,
            state_root: storage_trie_root,
            extrinsics_root: Default::default(),
            digest: Default::default(),
        };

        let mut encoded_para_heads = previous_block_data.encoded_para_head_data.clone();
        // Update encoded para head to include current block here
        // We are deliberately doing this before trie root calculation
        // to mimic the real setup
        encoded_para_heads.push((new_para_header.hash(), new_para_header.encode()));

        let mut memdb = MemoryDB::<KeccakHasher>::default();
        let mut previous_para_heads_merkle_root = Default::default();
        {
            let mut trie_db =
                TrieDBMut::<TrieLayout>::new(&mut memdb, &mut previous_para_heads_merkle_root);
            for (block_hash, para_head) in encoded_para_heads.iter() {
                trie_db.insert(block_hash.as_ref(), para_head).unwrap();
            }
        }

        let para_heads_merkle_proof = sp_trie::generate_trie_proof::<TrieLayout, _, _, _>(
            &memdb,
            previous_para_heads_merkle_root,
            vec![&new_para_header.hash()],
        )
        .unwrap();

        let mut mem_mmr = MemMMR::<_, MergeStrategy<LeafData, HashingAlgo>>::new(
            mmr_size_from_number_of_leaves(previous_block_data.beefy_mmr_leaves),
            previous_block_data.beefy_mmr_store.clone(),
        );

        mem_mmr
            .push(MMRNode::Data((
                previous_relay_header_number,
                previous_relay_header_hash,
                previous_para_heads_merkle_root,
            )))
            .unwrap();

        let new_header = TestHeader {
            parent_hash: previous_relay_header_hash,
            number: previous_relay_header_number + 1,
            state_root: Default::default(),
            extrinsics_root: Default::default(),
            digest: Default::default(),
        };

        let maybe_signed_commitment = if should_generate_commitment {
            let mmr_root = mem_mmr.get_root().unwrap();
            let signed_commitment = if new_authority_set.is_none() {
                generate_signed_commitment(
                    previous_block_data.current_authority_set_id,
                    previous_relay_header_number + 1,
                    CommitmentPayload {
                        mmr_node: mmr_root,
                        changed_authority_ids: None,
                        new_validator_set_id: previous_block_data.current_authority_set_id,
                    },
                    previous_block_data
                        .current_authority_set
                        .iter()
                        .map(|(p, _)| p.clone())
                        .collect::<Vec<Pair>>()
                        .as_ref(),
                )
            } else {
                let new_authority_set = new_authority_set.clone().unwrap();
                generate_signed_commitment(
                    previous_block_data.current_authority_set_id,
                    previous_relay_header_number + 1,
                    CommitmentPayload {
                        mmr_node: mmr_root,
                        changed_authority_ids: Some(
                            new_authority_set.iter().map(|(_, id)| id.clone()).collect(),
                        ),
                        new_validator_set_id: previous_block_data.current_authority_set_id + 1,
                    },
                    previous_block_data
                        .current_authority_set
                        .iter()
                        .map(|(p, _)| p.clone())
                        .collect::<Vec<Pair>>()
                        .as_ref(),
                )
            };

            Some(signed_commitment)
        } else {
            None
        };

        BlockData {
            chosen_kv_pair,
            chosen_kv_proof,
            beefy_mmr_store: mem_mmr.store().clone(),
            beefy_mmr_leaves: previous_block_data.beefy_mmr_leaves + 1,
            relay_header: new_header,
            signed_commitment: maybe_signed_commitment,
            current_authority_set_id: if new_authority_set.is_none() {
                previous_block_data.current_authority_set_id
            } else {
                previous_block_data.current_authority_set_id + 1
            },
            current_authority_set: if new_authority_set.is_none() {
                previous_block_data.current_authority_set.clone()
            } else {
                new_authority_set.unwrap()
            },

            para_header: new_para_header,
            encoded_para_head_data: encoded_para_heads,
            para_header_merkle_proof: para_heads_merkle_proof,
            para_header_merkle_root: previous_para_heads_merkle_root,
        }
    }
}
