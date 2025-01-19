use num::{traits::One, Integer};
use poly_ring_xnp1::Polynomial;
use rand::{distributions::uniform::SampleUniform, Rng};
use std::ops::{Add, Mul, Neg, Sub};

pub trait IntField {
    type I: Integer + Clone + SampleUniform;
    fn q() -> Self::I;
}

pub struct CipherText<Zq: IntField, const N: usize> {
    pub(crate) u: Polynomial<Zq::I, N>,
    pub(crate) v: Polynomial<Zq::I, N>,
}

pub struct EncryptKey<Zq: IntField, const N: usize> {
    pub(crate) a: Polynomial<Zq::I, N>,
    pub(crate) t: Polynomial<Zq::I, N>,
}

impl<T: IntField, const N: usize> EncryptKey<T, N> {
    pub fn encrypt(&self, rng: &mut impl Rng, m: Vec<T::I>) -> CipherText<T, N>
    where
        for<'a> &'a T::I: Add<Output = T::I> + Mul<Output = T::I> + Sub<Output = T::I>,
    {
        let q_div_2_m = {
            let tmp = Polynomial::<_, N>::from_coeffs(m);
            round_coefficients::<T, N>(tmp) // = [q/2] m
        };

        let r = small_polynomial::<T, N>(rng);
        let e2 = small_polynomial::<T, N>(rng);
        let e3 = small_polynomial::<T, N>(rng);

        // TODO apply modulo coefficients
        let u = self.a.clone() * r.clone() + e2;

        // TODO apply modulo coefficients
        let v = self.t.clone() * r.clone() + e3 + q_div_2_m;

        CipherText { u, v }
    }
}

pub struct DecryptKey<T: IntField, const N: usize> {
    pub(crate) s: Polynomial<T::I, N>,
}

impl<T: IntField, const N: usize> DecryptKey<T, N> {
    pub fn decrypt(&self, c: CipherText<T, N>) -> Vec<T::I>
    where
        for<'a> &'a T::I:
            Add<Output = T::I> + Mul<Output = T::I> + Sub<Output = T::I> + Neg<Output = T::I>,
    {
        let m = c.v.clone() - c.u.clone() * self.s.clone();
        // TODO apply modulo coefficients

        todo!()
    }
}

pub fn key_gen<T: IntField, const N: usize>(
    rng: &mut impl Rng,
) -> (EncryptKey<T, N>, DecryptKey<T, N>)
where
    for<'a> &'a T::I: Add<Output = T::I> + Mul<Output = T::I> + Sub<Output = T::I>,
{
    let a = rand_polynomial::<T, N>(rng);
    let s = small_polynomial::<T, N>(rng);
    let e = small_polynomial::<T, N>(rng);

    // TODO apply modulo coefficients
    let t = a.clone() * s.clone() + e;

    (EncryptKey { a, t }, DecryptKey { s })
}

#[inline]
fn rand_polynomial<T: IntField, const N: usize>(rng: &mut impl Rng) -> Polynomial<T::I, N> {
    let mut bound = T::q();
    bound.dec();
    rand_polynomial_within(rng, bound)
}

#[inline]
fn small_polynomial<T: IntField, const N: usize>(rng: &mut impl Rng) -> Polynomial<T::I, N> {
    rand_polynomial_within(rng, T::I::one())
}

/// Returns a random polynomial with coefficients in the range `[-bound, bound]`.
///
/// ## Safety
/// **bound** must be positive.
fn rand_polynomial_within<R: Rng, I, const N: usize>(rng: &mut R, bound: I) -> Polynomial<I, N>
where
    I: Integer + Clone + SampleUniform,
{
    let neg_bound = I::zero() - bound.clone();
    let mut bound = bound;
    bound.inc(); // inclusive bound

    let coeffs = (0..N)
        .map(|_| rng.gen_range(neg_bound.clone()..bound.clone()))
        .collect();

    Polynomial::new(coeffs)
}

fn round_coefficients<T: IntField, const N: usize>(p: Polynomial<T::I, N>) -> Polynomial<T::I, N> {
    let coeffs = p.iter().map(|c| todo!()).collect();
    Polynomial::new(coeffs)
}

fn modulo_coefficients<T: IntField, const N: usize>(p: Polynomial<T::I, N>) -> Polynomial<T::I, N> {
    let coeffs = p.iter().map(|c| todo!()).collect();
    Polynomial::new(coeffs)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ZqI32;

    impl IntField for ZqI32 {
        type I = i32;
        fn q() -> Self::I {
            8383489
        }
    }

    #[test]
    fn test() {
        let rng = &mut rand::thread_rng();
        let (ek, sk) = key_gen::<ZqI32, 512>(rng);
    }

    #[test]
    fn test_rand_polynomial() {
        let rng = &mut rand::thread_rng();
        let p = rand_polynomial_within::<_, i32, 512>(rng, 1);
        p.iter().for_each(|c| assert!(*c >= -1 && *c <= 1));
    }
}
