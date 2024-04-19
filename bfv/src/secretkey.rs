//! The secret key of BFV.
use crate::{context::BFVContext, BFVPublicKey, CipherField};
use algebra::Polynomial;
use serde::{Deserialize, Serialize};

/// Define the secret key of BFV.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BFVSecretKey {
    ternary_key: Polynomial<CipherField>,
}

impl BFVSecretKey {
    /// Generate a new BFV secret key with ternary distribution.
    pub fn new(ctx: &BFVContext) -> Self {
        let mut csrng = ctx.csrng_mut();
        let poly =
            Polynomial::<CipherField>::random_with_ternary(ctx.rlwe_dimension(), &mut *csrng);
        Self { ternary_key: poly }
    }
    /// Returns the reference of secret key.
    #[inline]
    pub fn secret_key(&self) -> &Polynomial<CipherField> {
        &self.ternary_key
    }

    /// Generate a public key of BFV using the secret key.
    pub fn gen_pubkey(&self, ctx: &BFVContext) -> BFVPublicKey {
        let mut csrng = ctx.csrng_mut();
        let a = Polynomial::<CipherField>::random(ctx.rlwe_dimension(), &mut *csrng);

        let e = Polynomial::<CipherField>::random_with_gaussian(
            ctx.rlwe_dimension(),
            &mut *csrng,
            ctx.sampler(),
        );
        let b = &a * self.secret_key() + e;
        BFVPublicKey::new([b, -a])
    }

    /// Serialize to `Vec<u8>`
    pub fn to_vec(&self) -> Vec<u8> {
        let mut bytes = vec![];

        for data in self.secret_key().iter() {
            bytes.extend(data.to_bytes());
        }

        bytes
    }

    /// Deserialize from [u8]
    pub fn from_vec(bytes: &[u8]) -> Self {
        let iter = bytes
            .chunks_exact(4)
            .map(|chunk| <[u8; 4]>::try_from(chunk).unwrap());

        let mut data = vec![];
        for v in iter {
            data.push(CipherField::from_bytes(v));
        }
        Self {
            ternary_key: Polynomial::<CipherField>::new(data),
        }
    }
}
