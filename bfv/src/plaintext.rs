//! Define the plaintext field of BFV

use algebra::{
    derive::{Field, Prime, Random},
    Polynomial,
};
use serde::{Deserialize, Serialize};

/// The field for the plaintext space.
#[derive(Field, Random, Prime, Serialize, Deserialize)]
#[modulus = 61]
pub struct PlainField(u16);

/// Define the type of platintext.
#[derive(Clone, Debug, PartialEq)]
pub struct BFVPlaintext(pub Polynomial<PlainField>);

impl BFVPlaintext {
    /// Create a new instance
    #[inline]
    pub fn new(poly: Polynomial<PlainField>) -> Self {
        Self(poly)
    }
}
