//! Defines the encryption key and the encryption method.

use poly_ring_xnp1::Polynomial;
use rand::Rng;
use std::ops::{Add, Mul, Sub};

use crate::{
    ciphertext::CipherText,
    intfield::IntField,
    polynomial::{modulo_coefficients, scale_coefficients, small_polynomial},
};

/// The encryption key created by the key generation method.
///
/// The size of the key can be calculated as `2 * N * sizeof(I)`
/// where `I` is the integer type of the field `Zq`. Depending on the
/// serialization method, the size can be slightly larger (for additional
/// metadata).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptKey<Zq: IntField, const N: usize> {
    pub(crate) a: Polynomial<Zq::I, N>,
    pub(crate) t: Polynomial<Zq::I, N>,
}

impl<Zq: IntField, const N: usize> EncryptKey<Zq, N> {
    /// Encrypts a message `m` using the public key.
    ///
    /// ## Safety
    /// Message `m` must be a vector of integers in {0, 1}, i.e. binary message.
    /// and the length of the message must be less than or equal to `N`.
    pub fn encrypt(&self, rng: &mut impl Rng, m: Vec<Zq::I>) -> CipherText<Zq, N>
    where
        for<'a> &'a Zq::I: Add<Output = Zq::I> + Mul<Output = Zq::I> + Sub<Output = Zq::I>,
    {
        // Uncomment for checking the preconditions. Here commented for performance.
        // assert!(len <= N);
        // m.iter()
        //     .for_each(|mi| assert!(mi == &Zq::I::zero() || mi == &Zq::I::one()));

        let r = small_polynomial::<Zq, N>(rng);
        let e2 = small_polynomial::<Zq, N>(rng);
        let e3 = small_polynomial::<Zq, N>(rng);

        // u = a * r + e2
        let u = {
            let a_r = modulo_coefficients::<Zq, N>(self.a.clone() * r.clone());
            modulo_coefficients::<Zq, N>(a_r + e2)
        };

        let q_div_2_m = {
            let tmp = Polynomial::<_, N>::from_coeffs(m);
            scale_coefficients::<Zq, N>(tmp) // = [q/2] m
        };

        // v = t * r + e3 + [q/2] m
        let v = {
            let t_r = modulo_coefficients::<Zq, N>(self.t.clone() * r.clone());
            let t_r_e3 = modulo_coefficients::<Zq, N>(t_r + e3);
            modulo_coefficients::<Zq, N>(t_r_e3 + q_div_2_m)
        };

        CipherText { u, v }
    }
}

#[cfg(feature = "serde")]
impl<Zq: IntField, const N: usize> serde::Serialize for EncryptKey<Zq, N> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let a_vec = crate::polynomial::to_fixed_coeffs_vec::<Zq, N>(&self.a);
        let t_vec = crate::polynomial::to_fixed_coeffs_vec::<Zq, N>(&self.t);

        let mut ret = a_vec;
        ret.extend(t_vec);
        ret.serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, Zq: IntField, const N: usize> serde::Deserialize<'de> for EncryptKey<Zq, N> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let vec = Vec::<Zq::I>::deserialize(deserializer)?;
        if vec.len() != 2 * N {
            return Err(serde::de::Error::custom(format!(
                "Invalid length of the vector: expected {}, got {}",
                2 * N,
                vec.len()
            )));
        }
        let (a, t) = vec.split_at(N);

        Ok(Self {
            a: Polynomial::new(a.to_vec()),
            t: Polynomial::new(t.to_vec()),
        })
    }
}
