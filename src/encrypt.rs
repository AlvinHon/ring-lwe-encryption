use poly_ring_xnp1::Polynomial;
use rand::Rng;
use std::ops::{Add, Mul, Sub};

use crate::{
    ciphertext::CipherText,
    intfield::IntField,
    polynomial::{modulo_coefficients, scale_coefficients, small_polynomial},
};

pub struct EncryptKey<Zq: IntField, const N: usize> {
    pub(crate) a: Polynomial<Zq::I, N>,
    pub(crate) t: Polynomial<Zq::I, N>,
}

impl<Zq: IntField, const N: usize> EncryptKey<Zq, N> {
    /// Encrypts a message `m` using the public key.
    ///
    /// ## Safty
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
