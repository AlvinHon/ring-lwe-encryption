//! Defines the CipherText struct.

use poly_ring_xnp1::Polynomial;

use crate::intfield::IntField;

/// CipherText created by the encryption method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CipherText<Zq: IntField, const N: usize> {
    pub(crate) u: Polynomial<Zq::I, N>,
    pub(crate) v: Polynomial<Zq::I, N>,
}
