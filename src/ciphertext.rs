//! Defines the CipherText struct.

use poly_ring_xnp1::Polynomial;

use crate::intfield::IntField;

/// CipherText created by the encryption method.
///
/// The size of the key can be calculated as `2 * N * sizeof(I)`
/// where `I` is the integer type of the field `Zq`. Depending on the
/// serialization method, the size can be slightly larger (for additional
/// metadata).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CipherText<Zq: IntField, const N: usize> {
    pub(crate) u: Polynomial<Zq::I, N>,
    pub(crate) v: Polynomial<Zq::I, N>,
}

#[cfg(feature = "serde")]
impl<Zq: IntField, const N: usize> serde::Serialize for CipherText<Zq, N> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let u_vec = crate::polynomial::to_fixed_coeffs_vec::<Zq, N>(&self.u);
        let v_vec = crate::polynomial::to_fixed_coeffs_vec::<Zq, N>(&self.v);

        let mut ret = u_vec;
        ret.extend(v_vec);
        ret.serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, Zq: IntField, const N: usize> serde::Deserialize<'de> for CipherText<Zq, N> {
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
        let (u, v) = vec.split_at(N);

        Ok(Self {
            u: Polynomial::new(u.to_vec()),
            v: Polynomial::new(v.to_vec()),
        })
    }
}
