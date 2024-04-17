//! Define the ciphertext of BFV.
use algebra::{
    derive::{Field, Prime, Random, NTT},
    Polynomial,
};
use serde::{Deserialize, Serialize};

/// The default rlwe dimension.
pub const DIMENSION_N: usize = 1024;

/// The field for the ciphertext space.
#[derive(Field, Random, Prime, NTT, Serialize, Deserialize)]
#[modulus = 132120577]
pub struct CipherField(u32);

/// Define the ciphertext of BFV.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BFVCiphertext(pub [Polynomial<CipherField>; 2]);
