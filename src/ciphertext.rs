use poly_ring_xnp1::Polynomial;

use crate::intfield::IntField;

pub struct CipherText<Zq: IntField, const N: usize> {
    pub(crate) u: Polynomial<Zq::I, N>,
    pub(crate) v: Polynomial<Zq::I, N>,
}
