pub mod circuits;
// pub mod merkle_tree;
// pub mod recursion;
pub mod error;

pub type Result<T> = core::result::Result<T, error::CircuitError>;
