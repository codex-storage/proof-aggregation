use plonky2::hash::hash_types::{HashOutTarget, NUM_HASH_OUT_ELTS};
use plonky2::iop::target::Target;
use serde::{Serialize, Deserialize};

/// Define a wrapper around HashOutTarget just for serialization
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SerializableHashOutTarget(pub HashOutTarget);

impl From<HashOutTarget> for SerializableHashOutTarget {
    fn from(inner: HashOutTarget) -> Self {
        SerializableHashOutTarget(inner)
    }
}

impl Serialize for SerializableHashOutTarget {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
    {
        self.0.elements.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SerializableHashOutTarget {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
    {
        let elements = <[Target; NUM_HASH_OUT_ELTS]>::deserialize(deserializer)?;
        Ok(SerializableHashOutTarget(HashOutTarget { elements }))
    }
}
