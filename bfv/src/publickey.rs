//! Define the ciphertext of BFV.
use algebra::Polynomial;
use serde::{Deserialize, Serialize};

use crate::CipherField;

/// Define the public key of BFV.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BFVPublicKey(pub [Polynomial<CipherField>; 2]);

impl BFVPublicKey {
    /// Creates a new instance.
    #[inline]
    pub fn new(polys: [Polynomial<CipherField>; 2]) -> Self {
        Self(polys)
    }
}
