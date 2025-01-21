use poly_ring_xnp1::Polynomial;
use std::ops::{Add, Mul, Neg, Sub};

use crate::{
    ciphertext::CipherText,
    intfield::IntField,
    polynomial::{modulo_coefficients, round_coefficients},
};

pub struct DecryptKey<Zq: IntField, const N: usize> {
    pub(crate) s: Polynomial<Zq::I, N>,
}

impl<Zq: IntField, const N: usize> DecryptKey<Zq, N> {
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
