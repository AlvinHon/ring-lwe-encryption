//! Defines the decryption key and the decryption method.

use poly_ring_xnp1::Polynomial;
use std::ops::{Add, Mul, Neg, Sub};

use crate::{
    ciphertext::CipherText,
    intfield::IntField,
    polynomial::{modulo_coefficients, round_coefficients},
};

/// The decryption key created by the key generation method.
///
/// The size of the key can be calculated as `N * sizeof(I)` where `I` is the
/// integer type of the field `Zq`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptKey<Zq: IntField, const N: usize> {
    pub(crate) s: Polynomial<Zq::I, N>,
}

impl<Zq: IntField, const N: usize> DecryptKey<Zq, N> {
    /// Decrypts the given ciphertext into a vector of integers in {0, 1}.
    ///
    /// Please note that the length of the decrypted message is equal to `N`
    /// which can be larger than the original message length. The extended
    /// part is padded with zeros.
    pub fn decrypt(&self, c: CipherText<Zq, N>) -> Vec<Zq::I>
    where
        for<'a> &'a Zq::I:
            Add<Output = Zq::I> + Mul<Output = Zq::I> + Sub<Output = Zq::I> + Neg<Output = Zq::I>,
    {
        // m = v - u * s
        let m = {
            let u_s = modulo_coefficients::<Zq, N>(c.u.clone() * self.s.clone());
            modulo_coefficients::<Zq, N>(c.v.clone() - u_s)
        };

        let mb = round_coefficients::<Zq, N>(m);

        mb.iter().cloned().collect()
    }
}
