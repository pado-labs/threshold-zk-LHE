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

    /// Serialize to `Vec<u8>`
    pub fn to_vec(&self) -> Vec<u8> {
        // layout: |len0,len1|data0,data1|
        let mut bytes = vec![];

        // length(2)
        for polys in self.0.iter() {
            let len = polys.coeff_count() as u32;
            bytes.extend(len.to_be_bytes());
        }

        // data
        for polys in self.0.iter() {
            for data in polys.iter() {
                bytes.extend(data.to_bytes());
            }
        }

        bytes
    }

    /// Deserialize from [u8]
    pub fn from_vec(bytes: &[u8]) -> Self {
        let mut iter = bytes
            .chunks_exact(4)
            .map(|chunk| <[u8; 4]>::try_from(chunk).unwrap());

        // length(2)
        let len0 = u32::from_be_bytes(iter.next().unwrap());
        let len1 = u32::from_be_bytes(iter.next().unwrap());

        // data
        let mut data0 = vec![];
        let mut data1 = vec![];
        for _ in 0..len0 {
            data0.push(CipherField::from_bytes(iter.next().unwrap()));
        }
        for _ in 0..len1 {
            data1.push(CipherField::from_bytes(iter.next().unwrap()));
        }

        Self([
            Polynomial::<CipherField>::new(data0),
            Polynomial::<CipherField>::new(data1),
        ])
    }
}
