use std::fmt::Debug;

use codec::{Decode, Encode};
use mmr_lib::Merge;
use sp_core::sp_std::marker::PhantomData;
use sp_core::Hasher;

use crate::traits::Hashable;

#[derive(Clone, PartialEq, Debug, Encode, Decode)]
pub enum MMRNode<Leaf>
where
    Leaf: Hashable + Encode + Decode,
{
    Data(Leaf),
    Hash(<Leaf as Hashable>::Out),
}

impl<Leaf> MMRNode<Leaf>
where
    Leaf: Hashable + Encode + Decode,
{
    fn hash(&self) -> Leaf::Out {
        match self {
            Self::Data(l) => l.hash(),
            Self::Hash(h) => *h,
        }
    }
}

pub struct MergeStrategy<L, H>(PhantomData<(L, H)>);

impl<Leaf, H> Merge for MergeStrategy<Leaf, H>
where
    Leaf: Hashable<Out = <H as Hasher>::Out> + Encode + Decode,
    H: Hasher,
{
    type Item = MMRNode<Leaf>;

    fn merge(left: &Self::Item, right: &Self::Item) -> Self::Item {
        let mut combined = left.hash().as_ref().to_vec();
        combined.append(&mut right.hash().as_ref().to_vec());
        MMRNode::Hash(H::hash(combined.as_slice()))
    }
}
