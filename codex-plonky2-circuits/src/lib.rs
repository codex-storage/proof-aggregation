pub mod circuits;
pub mod recursion;
pub mod error;

pub type Result<T> = core::result::Result<T, error::CircuitError>;
