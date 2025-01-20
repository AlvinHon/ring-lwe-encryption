use num::{
    traits::{One, Zero},
    Integer, Signed,
};
use poly_ring_xnp1::Polynomial;
use rand::{distributions::uniform::SampleUniform, Rng};
use std::ops::{Add, Mul, Neg, Sub};

pub trait IntField {
    type I: Integer + Signed + Clone + SampleUniform;
    /// The prime modulus q.
    const Q: Self::I;
    /// Implements the modulo operation on an integer to make it an element of the field.
    /// For example, applying modulo q if the the finite field consists only positive integers.
    ///
    /// Example implementation using i32 as type `I`:
    /// ```rust ignore
    /// fn modulo(x: &Self::I) -> Self::I {
    ///     let a = x.rem_euclid(Self::Q);
    ///     if a > Self::Q / 2 {
    ///         a - Self::Q
    ///     } else {
    ///         a
    ///     }
    /// }
    /// ```
    fn modulo(x: &Self::I) -> Self::I;
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
    /// Encrypts a message `m` using the public key.
    ///
    /// ## Safty
    /// Message `m` must be a vector of integers in {0, 1}, i.e. binary message.
    /// and the length of the message must be less than or equal to `N`.
    pub fn encrypt(&self, rng: &mut impl Rng, m: Vec<T::I>) -> CipherText<T, N>
    where
        for<'a> &'a T::I: Add<Output = T::I> + Mul<Output = T::I> + Sub<Output = T::I>,
    {
        // Uncomment for checking the preconditions. Here commented for performance.
        // assert!(len <= N);
        // m.iter()
        //     .for_each(|mi| assert!(mi == &T::I::zero() || mi == &T::I::one()));

        let r = small_polynomial::<T, N>(rng);
        let e2 = small_polynomial::<T, N>(rng);
        let e3 = small_polynomial::<T, N>(rng);

        // u = a * r + e2
        let u = {
            let a_r = modulo_coefficients::<T, N>(self.a.clone() * r.clone());
            modulo_coefficients::<T, N>(a_r + e2)
        };

        let q_div_2_m = {
            let tmp = Polynomial::<_, N>::from_coeffs(m);
            scale_coefficients::<T, N>(tmp) // = [q/2] m
        };

        // v = t * r + e3 + [q/2] m
        let v = {
            let t_r = modulo_coefficients::<T, N>(self.t.clone() * r.clone());
            let t_r_e3 = modulo_coefficients::<T, N>(t_r + e3);
            modulo_coefficients::<T, N>(t_r_e3 + q_div_2_m)
        };

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
        // m = v - u * s
        let m = {
            let u_s = modulo_coefficients::<T, N>(c.u.clone() * self.s.clone());
            modulo_coefficients::<T, N>(c.v.clone() - u_s)
        };

        let mb = round_coefficients::<T, N>(m);

        mb.iter().cloned().collect()
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

    // t = a * s + e
    let t = {
        let a_s = modulo_coefficients::<T, N>(a.clone() * s.clone());
        modulo_coefficients::<T, N>(a_s + e)
    };

    (EncryptKey { a, t }, DecryptKey { s })
}

#[inline]
fn rand_polynomial<T: IntField, const N: usize>(rng: &mut impl Rng) -> Polynomial<T::I, N> {
    let mut bound = T::Q;
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
    let lower = I::zero() - bound.clone();

    let mut upper = bound;
    upper.inc(); // inclusive bound

    let range = lower.clone()..upper.clone();
    let coeffs = (0..N).map(|_| rng.gen_range(range.clone())).collect();

    Polynomial::new(coeffs)
}

/// Multiplies each coefficient of the polynomial with the closest integer to q/2.
fn scale_coefficients<T: IntField, const N: usize>(p: Polynomial<T::I, N>) -> Polynomial<T::I, N> {
    let q_div_2 = closest_integer_div_two(T::Q);
    let coeffs = p.iter().map(|c| q_div_2.clone() * c.clone()).collect();
    Polynomial::new(coeffs)
}

/// Converts each coefficient of the polynomial to either 0 or 1 by checking whether it
/// is closer to 0 or q/2.
fn round_coefficients<T: IntField, const N: usize>(p: Polynomial<T::I, N>) -> Polynomial<T::I, N> {
    let two = T::I::one() + T::I::one();
    let q_div_4 = closest_integer_div_two(T::Q) / two;
    let coeffs = p
        .iter()
        .map(|c| {
            if c.abs().gt(&q_div_4) {
                T::I::one()
            } else {
                T::I::zero()
            }
        })
        .collect();
    Polynomial::new(coeffs)
}

/// Applies modulo q to each coefficient of the polynomial.
fn modulo_coefficients<T: IntField, const N: usize>(p: Polynomial<T::I, N>) -> Polynomial<T::I, N> {
    let coeffs = p.iter().map(T::modulo).collect();
    Polynomial::new(coeffs)
}

/// Computes [x/2], the closest integer to x/2 with ties being broken upwards
#[inline]
fn closest_integer_div_two<I: Integer + Clone>(x: I) -> I {
    let two = I::one() + I::one();
    x.div_ceil(&two)
}

#[cfg(test)]
mod tests {

    use std::vec;

    use super::*;

    struct ZqI32;

    impl IntField for ZqI32 {
        type I = i32;
        const Q: i32 = 8383489; // a prime number
        fn modulo(x: &Self::I) -> Self::I {
            let a = x.rem_euclid(Self::Q);
            if a > Self::Q / 2 {
                a - Self::Q
            } else {
                a
            }
        }
    }

    #[test]
    fn test_encrypt_decrypt() {
        let rng = &mut rand::thread_rng();
        let (ek, sk) = key_gen::<ZqI32, 512>(rng);
        let m = vec![1, 0, 0, 1];
        let c = ek.encrypt(rng, m.clone());
        let d = sk.decrypt(c)[..m.len()].to_vec();
        assert_eq!(m, d);
    }

    #[test]
    fn test_rand_polynomial() {
        let rng = &mut rand::thread_rng();
        let p = rand_polynomial_within::<_, i32, 512>(rng, 1);
        p.iter().for_each(|c| assert!(*c >= -1 && *c <= 1));
    }

    #[test]
    fn test_closest_integer_div_two() {
        assert_eq!(closest_integer_div_two(1), 1);
        assert_eq!(closest_integer_div_two(2), 1);
        assert_eq!(closest_integer_div_two(3), 2);
        assert_eq!(closest_integer_div_two(5), 3);
        assert_eq!(closest_integer_div_two(7), 4);
        assert_eq!(closest_integer_div_two(13), 7);
    }

    #[test]
    fn test_modulo_coefficients() {
        struct ZqI32Q7;

        impl IntField for ZqI32Q7 {
            type I = i32;
            const Q: i32 = 7;
            fn modulo(x: &Self::I) -> Self::I {
                let a = x.rem_euclid(Self::Q);
                if a > Self::Q / 2 {
                    a - Self::Q
                } else {
                    a
                }
            }
        }

        // Let q = 7, the field elements are: -3,-2,-1,0,1,2,3
        // the operations should be eqvivalent to the positive integers field: 4,5,6,0,1,2,3
        // E.g. the result of multiplication of 1st element and 2nd element should be -3 * -2 = 6 = -1 mod 7,
        // i.e. the 3rd element in the field which is equivalent to 6 in the positive integers field.
        let p = Polynomial::new(vec![-9, -6, 0, 6]);
        let p = modulo_coefficients::<ZqI32Q7, 4>(p);
        let coeffs = p.iter().cloned().collect::<Vec<i32>>();
        assert_eq!(coeffs, [-2, 1, 0, -1]);
    }
}
