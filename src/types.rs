use sp_core::Hasher;
use sp_runtime::generic::Header;
use sp_runtime::traits::BlakeTwo256;

pub type BlockNumber = u64;
pub type HashingAlgo = BlakeTwo256;
pub type TestHeader = Header<BlockNumber, HashingAlgo>;

pub type HashOutput = <HashingAlgo as Hasher>::Out;

pub type TrieLayout = sp_trie::Layout<sp_core::KeccakHasher>;

pub type LeafData = (BlockNumber, HashOutput, HashOutput);
