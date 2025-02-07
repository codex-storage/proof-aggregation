pub mod circuits;
pub mod error;

pub type Result<T> = core::result::Result<T, error::CircuitError>;
