//! Define threshold pke with BFV.

use algebra::{Field, Polynomial};
use chacha20poly1305::{aead::Aead, AeadCore, ChaCha20Poly1305, Key, KeyInit, Nonce};
use itybity::IntoBitIterator;
use rand::{CryptoRng, Rng};

use crate::{
    BFVCiphertext, BFVContext, BFVPlaintext, BFVPublicKey, BFVScheme, BFVSecretKey, PlainField,
    DIMENSION_N, MAX_NODES_NUMBER,
};

type F = PlainField;

/// Define the threshold policy.
#[derive(Debug, Clone)]
pub struct ThresholdPolicy {
    total_number: usize,
    threshold_number: usize,
    indices: Vec<F>,
}

impl ThresholdPolicy {
    /// Create a new instance.
    /// Make sure that no repeated index in `indices`
    /// `indices` should not contain `0`.
    pub fn new(total_number: usize, threshold_number: usize, indices: Vec<F>) -> Self {
        assert_eq!(
            indices.len(),
            total_number,
            "indices length should be consistent with total_number"
        );
        assert!(!indices.contains(&F::ZERO), "indices should not contain 0");
        assert!(
            threshold_number <= total_number,
            "threshold number exceeds total number"
        );
        assert!(
            total_number <= MAX_NODES_NUMBER,
            "total number exceeds MAX_USER_NUMBER"
        );

        Self {
            total_number,
            threshold_number,
            indices,
        }
    }

    /// Return total_number
    #[inline]
    pub fn total_number(&self) -> usize {
        self.total_number
    }

    /// Return threshold_number
    #[inline]
    pub fn threshold_number(&self) -> usize {
        self.threshold_number
    }

    /// Return the reference of indices
    #[inline]
    pub fn indices(&self) -> &[F] {
        &self.indices
    }

    /// Securely sharing a message using Shamir secret sharing.
    pub fn secret_sharing<R>(&self, secret: &Polynomial<F>, rng: &mut R) -> Vec<Polynomial<F>>
    where
        R: Rng + CryptoRng,
    {
        let mut res = vec![vec![F::ZERO; secret.coeff_count()]; self.total_number];

        for (i, m) in secret.iter().enumerate() {
            let mut poly = Polynomial::<F>::random(self.threshold_number, &mut *rng);
            poly[0] = *m;

            for (j, &point) in self.indices.iter().enumerate() {
                res[j][i] = poly.evaluate(point);
            }
        }

        res.into_iter().map(Polynomial::new).collect()
    }
}

/// Define Threshold PKE context.
#[derive(Debug, Clone)]
pub struct ThresholdPKEContext {
    bfv_ctx: BFVContext,
    policy: ThresholdPolicy,
}

impl ThresholdPKEContext {
    /// Create a new instance
    #[inline]
    pub fn new(total_number: usize, threshold_number: usize, indices: Vec<F>) -> Self {
        let bfv_ctx = BFVContext::new();
        let policy = ThresholdPolicy::new(total_number, threshold_number, indices);
        Self { bfv_ctx, policy }
    }

    /// Return the reference of BFV context
    #[inline]
    pub fn bfv_ctx(&self) -> &BFVContext {
        &self.bfv_ctx
    }

    /// Return the referance of policy.
    #[inline]
    pub fn policy(&self) -> &ThresholdPolicy {
        &self.policy
    }
}
/// Define the threshold pke scheme.
pub struct ThresholdPKE;

impl ThresholdPKE {
    /// Generate threshold pke context.
    #[inline]
    pub fn gen_context(
        total_number: usize,
        threshold_number: usize,
        indices: Vec<F>,
    ) -> ThresholdPKEContext {
        ThresholdPKEContext::new(total_number, threshold_number, indices)
    }

    /// Compute lagrange coefficients.
    pub fn gen_lagrange_coeffs(chosen_indices: &[F]) -> Vec<F> {
        assert!(
            !chosen_indices.contains(&F::ZERO),
            "indices should not contain 0"
        );
        let mut lagrange_coeff = vec![F::ZERO; chosen_indices.len()];

        for (i, point) in chosen_indices.iter().enumerate() {
            let mut points_without_i = chosen_indices.to_vec();
            points_without_i.retain(|x| *x != *point);

            let numerator = points_without_i.iter().fold(F::ONE, |acc, &x| acc * (-x));
            let denominator = points_without_i
                .iter()
                .fold(F::ONE, |acc, &x| acc * (*point - x));
            lagrange_coeff[i] = numerator / denominator;
        }

        lagrange_coeff
    }

    /// Generate key pair.
    #[inline]
    pub fn gen_keypair(ctx: &ThresholdPKEContext) -> (BFVSecretKey, BFVPublicKey) {
        BFVScheme::gen_keypair(ctx.bfv_ctx())
    }

    /// Encrypt a message, where the message is a polynomial.
    /// First secret sharing the message according to the policy.
    /// Encrypt each share using all the pk's of the parties.
    #[inline]
    pub fn encrypt(
        ctx: &ThresholdPKEContext,
        pks: &Vec<BFVPublicKey>,
        m: &BFVPlaintext,
    ) -> Vec<BFVCiphertext> {
        assert_eq!(
            pks.len(),
            ctx.policy.total_number(),
            "the length of pks should be total_number"
        );
        let polys = ctx
            .policy
            .secret_sharing(&m.0, &mut *ctx.bfv_ctx().csrng_mut());
        polys
            .into_iter()
            .zip(pks)
            .map(|(x, pk)| BFVScheme::encrypt(ctx.bfv_ctx(), pk, &BFVPlaintext(x)))
            .collect()
    }

    /// Encrypt a message, where the message consists of bytes.
    /// Note that we use a hybrid encryption, meaning use public key to encryt a symmetric key, and use the symmetric key to encryt the bytes with an AEAD algorithm.
    #[inline]
    pub fn encrypt_bytes(
        ctx: &ThresholdPKEContext,
        pks: &Vec<BFVPublicKey>,
        m: &[u8],
    ) -> (Vec<BFVCiphertext>, Nonce, Vec<u8>) {
        let sym_key = ChaCha20Poly1305::generate_key(&mut *ctx.bfv_ctx().csrng_mut());

        let key = BFVPlaintext(to_poly::<DIMENSION_N>(sym_key));
        let c1 = ThresholdPKE::encrypt(ctx, pks, &key);

        let cipher = ChaCha20Poly1305::new(&sym_key);
        let nonce = ChaCha20Poly1305::generate_nonce(&mut *ctx.bfv_ctx().csrng_mut());
        let c2 = cipher.encrypt(&nonce, m).unwrap();

        (c1, nonce, c2)
    }

    /// Decrypt the ciphertext.
    #[inline]
    pub fn decrypt(
        ctx: &ThresholdPKEContext,
        sk: &BFVSecretKey,
        c: &BFVCiphertext,
    ) -> BFVPlaintext {
        BFVScheme::decrypt(ctx.bfv_ctx(), sk, c)
    }

    /// Decrypt the ciphertext into bytes.
    #[inline]
    pub fn decrypt_bytes(
        ctx: &ThresholdPKEContext,
        sk: &BFVSecretKey,
        c1: &BFVCiphertext,
        nonce: &Nonce,
        c2: &[u8],
    ) -> Vec<u8> {
        let key = ThresholdPKE::decrypt(ctx, sk, c1);
        let sym_key = to_bits(key.0);

        let cipher = ChaCha20Poly1305::new(&sym_key);

        cipher.decrypt(nonce, c2).unwrap()
    }

    /// Re-encrypt the ciphertext.
    /// First decrypt the ciphertext `c` with `sk`
    /// Encrypt the above message with `pk_new`.
    #[inline]
    pub fn re_encrypt(
        ctx: &ThresholdPKEContext,
        c: &BFVCiphertext,
        sk: &BFVSecretKey,
        pk_new: &BFVPublicKey,
    ) -> BFVCiphertext {
        let m = Self::decrypt(ctx, sk, c);
        BFVScheme::encrypt(ctx.bfv_ctx(), pk_new, &m)
    }

    /// Combine the ciphertext.
    /// Homomorphically compute the Shamir reconstruction method.
    #[inline]
    pub fn combine(
        ctx: &ThresholdPKEContext,
        ctxts: &[BFVCiphertext],
        chosen_indices: &[F],
    ) -> BFVCiphertext {
        assert_eq!(
            ctxts.len(),
            chosen_indices.len(),
            "the length of ctxts and chosen_indices should be equal"
        );
        let lagrange_coeff = Self::gen_lagrange_coeffs(chosen_indices);
        BFVScheme::evaluate_inner_product(ctx.bfv_ctx(), ctxts, &lagrange_coeff)
    }
}

// Transfer a symmetric secret key into a polynomial with length N with 0 paddings.
fn to_poly<const N: usize>(key: Key) -> Polynomial<PlainField> {
    let poly = key.into_lsb0_vec();
    assert!(N >= poly.len());
    let mut poly: Vec<PlainField> = poly
        .into_iter()
        .map(|x| if x { PlainField::ONE } else { PlainField::ZERO })
        .collect();
    poly.resize(N, PlainField::ZERO);
    Polynomial::from_slice(&poly)
}

// Transfer a polynomial into a symmetric key.
fn to_bits(poly: Polynomial<PlainField>) -> Key {
    let (key, _) = poly.as_slice().split_at(256);
    let key: Vec<u8> = key
        .chunks(8)
        .map(|x| {
            let mut value = 0;
            for (i, &bit) in x.iter().enumerate() {
                if bit == PlainField::ONE {
                    value |= 1 << i;
                }
            }
            value
        })
        .collect();
    *Key::from_slice(&key)
}
