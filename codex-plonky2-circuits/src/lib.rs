pub mod circuits;
pub mod recursion;
pub mod error;
pub mod circuit_helper;
mod bundle;
pub mod bn254_wrapper;
pub mod serialization;

pub type Result<T> = core::result::Result<T, error::CircuitError>;
