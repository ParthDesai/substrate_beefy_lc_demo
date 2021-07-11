use std::vec::Vec;

use sp_core::Hasher;

use crate::traits::Hashable;
use crate::types::{HashOutput, HashingAlgo, LeafData};

pub fn mmr_size_from_number_of_leaves(leaves: u64) -> u64 {
    if leaves == 0 {
        0
    } else {
        mmr_lib::leaf_index_to_mmr_size(leaves - 1)
    }
}

impl Hashable for LeafData {
    type Out = HashOutput;

    fn hash(&self) -> Self::Out {
        let mut payload: Vec<u8> = vec![];
        payload.append(&mut self.0.to_le_bytes().to_vec());
        payload.append(&mut self.1.as_bytes().to_vec());
        payload.append(&mut self.2.as_bytes().to_vec());
        HashingAlgo::hash(payload.as_slice())
    }
}
