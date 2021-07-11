mod block_data;
mod block_generation;
mod ethereum_actor;
mod ethereum_view;
mod mmr;
mod traits;
mod types;
mod utils;

use crate::block_generation::create_random_child_block;
use crate::ethereum_actor::EthereumActor;
use crate::mmr::{MMRNode, MergeStrategy};
use crate::types::{HashOutput, HashingAlgo, LeafData, TestHeader, TrieLayout};
use crate::utils::mmr_size_from_number_of_leaves;
use beefy_primitives::crypto::{AuthorityId, Pair};
use mmr_lib::util::{MemMMR, MemStore};
use sp_core::crypto::Pair as _;
use sp_core::KeccakHasher;
use sp_trie::{MemoryDB, TrieDBMut, TrieMut};
use std::vec::Vec;

fn generate_beefy_pairs(number: usize) -> Vec<(Pair, AuthorityId)> {
    (0..number)
        .map(|_| {
            let pair = Pair::generate().0;
            let public = pair.public();
            (pair, public)
        })
        .collect()
}

fn generate_mmr_proof_items(
    block_pos_in_mmr: u64,
    mmr_size: u64,
    store: MemStore<MMRNode<LeafData>>,
) -> Vec<MMRNode<LeafData>> {
    let mmr = MemMMR::<_, MergeStrategy<LeafData, HashingAlgo>>::new(mmr_size, store);
    mmr.gen_proof(vec![block_pos_in_mmr])
        .unwrap()
        .proof_items()
        .clone()
        .to_vec()
}

fn generate_para_header_inclusion_proof(
    para_header: &TestHeader,
    encoded_para_head_data: &Vec<(HashOutput, Vec<u8>)>,
) -> Vec<Vec<u8>> {
    let mut para_header_merkle_root = Default::default();
    let mut memdb = MemoryDB::<KeccakHasher>::default();
    {
        let mut trie_db = TrieDBMut::<TrieLayout>::new(&mut memdb, &mut para_header_merkle_root);
        for (block_hash, para_head) in encoded_para_head_data {
            trie_db.insert(block_hash.as_ref(), para_head).unwrap();
        }
    }
    let para_header_to_generate_merkel_proof = para_header.hash();
    sp_trie::generate_trie_proof::<TrieLayout, _, _, _>(
        &memdb,
        para_header_merkle_root,
        vec![&para_header_to_generate_merkel_proof],
    )
    .unwrap()
}

pub fn beefy_light_client_demo() {
    let initial_authorities = generate_beefy_pairs(5);
    let next_authorities = generate_beefy_pairs(6);

    let mut blocks = vec![];
    blocks.push(create_random_child_block(
        None,
        false,
        Some(initial_authorities.clone()),
    ));
    println!("Creating genesis block with Initial authority set id: 0");
    for i in 0..10 {
        if i == 3 {
            blocks.push(create_random_child_block(
                Some(blocks.last().unwrap()),
                true,
                Some(next_authorities.clone()),
            ));
            println!("Created block: {} containing signed commitment since we updated beefy authority set", blocks.len());
        } else {
            blocks.push(create_random_child_block(
                Some(blocks.last().unwrap()),
                false,
                None,
            ));
            println!("Created block: {}", blocks.len());
        }
    }

    blocks.push(create_random_child_block(
        Some(blocks.last().unwrap()),
        true,
        None,
    ));
    println!("Created block: {} with signed commitment", blocks.len());

    let last_block = blocks.last().unwrap();
    let ethereum_view_of_last_block = last_block.ethereum_view();

    // Ethereum actor is a smart contract maintaining authority sets
    let mut ethereum_actor = EthereumActor::new(
        initial_authorities
            .iter()
            .map(|(_, id)| id.clone())
            .collect(),
        0,
    );

    // We need to send 5th block to ethereum since the authority set changes in that block
    ethereum_actor
        .ingest_new_header(blocks[4].ethereum_view())
        .unwrap();
    println!("Ethereum actor ingested 5th block (We need to do this since 5th block contains updated authority id)");

    ethereum_actor
        .ingest_new_header(ethereum_view_of_last_block)
        .unwrap();
    println!("Ethereum actor ingested last block (Which contains updated mmr root)");

    // We want to prove that 5th block is finalized, so that would mean we need to pass
    // 4th index in blockdata vector element's header.
    // It should be positioned at 4th index in merkle mountain range.

    println!(
        "Now, let's present a claim to ethereum actor that 5th block is finalized, \
    contains proof that corresponding para block is also finalized and storage claim \
    on para block is also valid as well."
    );

    let ethereum_view_of_verifying_block = blocks[4].ethereum_view();
    let child_block_of_verifying_block = &blocks[5];
    let ethereum_view_of_child_of_verifying_block = child_block_of_verifying_block.ethereum_view();

    let verifying_block_pos_in_mmr = mmr_lib::leaf_index_to_pos(4);
    let proof_items = generate_mmr_proof_items(
        verifying_block_pos_in_mmr,
        mmr_size_from_number_of_leaves(last_block.beefy_mmr_leaves),
        last_block.beefy_mmr_store.clone(),
    );

    let verifying_para_header_inclusion_proof = generate_para_header_inclusion_proof(
        &ethereum_view_of_verifying_block.para_header,
        &child_block_of_verifying_block.encoded_para_head_data,
    );

    // If this call is successful this means that we have verified that a key value pair exists on substrate
    // storage at specified block
    ethereum_actor
        .verify_claim(
            ethereum_view_of_verifying_block.relay_header,
            proof_items,
            verifying_block_pos_in_mmr,
            ethereum_view_of_verifying_block.para_header,
            verifying_para_header_inclusion_proof, // This needs to be custom
            ethereum_view_of_child_of_verifying_block.para_header_merkle_root,
            ethereum_view_of_verifying_block.chosen_kv_pair,
            ethereum_view_of_verifying_block.chosen_kv_proof,
        )
        .unwrap();

    println!(
        "We presented our beefy mmr proof, para header inclusion proof and storage proof which were accepted by ethereum actor"
    );
}
