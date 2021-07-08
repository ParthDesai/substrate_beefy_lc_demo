use std::fmt::Debug;

pub trait Hashable {
    type Out: AsRef<[u8]> + AsMut<[u8]> + Copy + PartialEq + Debug;
    fn hash(&self) -> Self::Out;
}
