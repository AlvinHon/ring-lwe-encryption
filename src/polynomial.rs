//! Auxiliary functions for polynomial operations.

use num::{
    traits::{One, Zero},
    Integer, Signed,
};
use poly_ring_xnp1::Polynomial;
use rand::{distributions::uniform::SampleUniform, Rng};

use crate::IntField;

#[inline]
pub(crate) fn rand_polynomial<Zq: IntField, const N: usize>(
    rng: &mut impl Rng,
) -> Polynomial<Zq::I, N> {
    let bound = Zq::Q / (Zq::I::one() + Zq::I::one());
    rand_polynomial_within(rng, bound)
}

#[inline]
pub(crate) fn small_polynomial<Zq: IntField, const N: usize>(
    rng: &mut impl Rng,
) -> Polynomial<Zq::I, N> {
    rand_polynomial_within(rng, Zq::B)
}

/// Returns a random polynomial with coefficients in the range `[-bound, bound]`.
///
/// ## Safety
/// **bound** must be positive.
pub(crate) fn rand_polynomial_within<R: Rng, I, const N: usize>(
    rng: &mut R,
    bound: I,
) -> Polynomial<I, N>
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
pub(crate) fn scale_coefficients<Zq: IntField, const N: usize>(
    p: Polynomial<Zq::I, N>,
) -> Polynomial<Zq::I, N> {
    let q_div_2 = closest_integer_div_two(Zq::Q);
    let coeffs = p.iter().map(|c| q_div_2.clone() * c.clone()).collect();
    Polynomial::new(coeffs)
}

/// Converts each coefficient of the polynomial to either 0 or 1 by checking whether it
/// is closer to 0 or q/2.
pub(crate) fn round_coefficients<Zq: IntField, const N: usize>(
    p: Polynomial<Zq::I, N>,
) -> Polynomial<Zq::I, N> {
    let two = Zq::I::one() + Zq::I::one();
    let q_div_4 = closest_integer_div_two(Zq::Q) / two;
    let coeffs = p
        .iter()
        .map(|c| {
            if c.abs().gt(&q_div_4) {
                Zq::I::one()
            } else {
                Zq::I::zero()
            }
        })
        .collect();
    Polynomial::new(coeffs)
}

/// Applies modulo q to each coefficient of the polynomial.
#[inline]
pub(crate) fn modulo_coefficients<Zq: IntField, const N: usize>(
    p: Polynomial<Zq::I, N>,
) -> Polynomial<Zq::I, N> {
    Polynomial::new(p.iter().map(Zq::modulo).collect())
}

/// Computes [x/2], the closest integer to x/2 with ties being broken upwards
#[inline]
pub(crate) fn closest_integer_div_two<I: Integer + Clone>(x: I) -> I {
    x.div_ceil(&(I::one() + I::one()))
}

#[cfg(test)]
mod tests {

    use super::*;

    struct ZqI32Q7;

    impl IntField for ZqI32Q7 {
        type I = i32;
        const Q: i32 = 7;
        const B: i32 = 1;
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
