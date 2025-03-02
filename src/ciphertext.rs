//! Defines the CipherText struct.

use poly_ring_xnp1::Polynomial;

use crate::intfield::IntField;

/// CipherText created by the encryption method.
///
/// The size of the key can be calculated as `2 * N * sizeof(I)`
/// where `I` is the integer type of the field `Zq`. Depending on the
/// serialization method, the size can be slightly larger (for additional
/// metadata).
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CipherText<Zq: IntField, const N: usize> {
    pub(crate) u: Polynomial<Zq::I, N>,
    pub(crate) v: Polynomial<Zq::I, N>,
}
