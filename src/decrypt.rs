//! Defines the decryption key and the decryption method.

use poly_ring_xnp1::Polynomial;
use std::ops::{Add, Mul, Neg, Sub};

use crate::{
    ciphertext::CipherText,
    intfield::IntField,
    polynomial::{modulo_coefficients, round_coefficients, to_fixed_coeffs_vec},
};

/// The decryption key created by the key generation method.
///
/// The size of the key can be calculated as `N * sizeof(I)` where `I` is the
/// integer type of the field `Zq`. Depending on the serialization method, the
/// size can be slightly larger (for additional metadata).
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

        // Pad with zeros if the length is less than N (due to coefficients trimming in round_coefficients)
        to_fixed_coeffs_vec::<Zq, N>(&mb)
    }
}

#[cfg(feature = "serde")]
impl<Zq: IntField, const N: usize> serde::Serialize for DecryptKey<Zq, N> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        to_fixed_coeffs_vec::<Zq, N>(&self.s).serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, Zq: IntField, const N: usize> serde::Deserialize<'de> for DecryptKey<Zq, N> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let vec = Vec::<Zq::I>::deserialize(deserializer)?;
        if vec.len() != N {
            return Err(serde::de::Error::custom(format!(
                "Invalid length of the vector: expected {}, got {}",
                N,
                vec.len()
            )));
        }

        Ok(Self {
            s: Polynomial::new(vec),
        })
    }
}
