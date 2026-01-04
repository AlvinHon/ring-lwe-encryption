//! Defines the `IntField` trait for finite fields over integers.

use num::{Integer, One, Signed};
use rand::distr::uniform::SampleUniform;

/// Implements a finite field over integers with prime modulus q.
///
/// The value of `Q` and `B` must be carefully chosen in order to make it work.
/// The parameters should satisfy the following condition:
///
/// 2N * B^2 + B < Q/4
///
/// where N - 1 is the degree of the polynomial (see the `key_gen` method).
///
/// Please note the lower layer of arithmetics relies on the implementation of
/// [std::ops] for the type `I`. The overflow behavior is not handled in this
/// library.
pub trait IntField {
    #[cfg(not(any(feature = "serde")))]
    type I: Integer + Signed + Clone + SampleUniform;

    #[cfg(feature = "serde")]
    type I: Integer
        + Signed
        + Clone
        + SampleUniform
        + serde::Serialize
        + for<'de> serde::Deserialize<'de>;

    /// The prime modulus q.
    const Q: Self::I;
    /// A positive integer, defines the boundary of the range of field element. This boundary determines
    /// how "small" the coefficients are in the polynomials for randomness. Usually, the boundary is 1,
    /// i.e. the coefficients are in range \[-1, 1].
    const B: Self::I;
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

    /// Checks whether the parameters Q and B are valid for encryption:
    /// 2N * B^2 + B < Q/4
    fn valid() -> bool {
        let four = Self::I::one() + Self::I::one() + Self::I::one() + Self::I::one();
        let two = Self::I::one() + Self::I::one();
        let lhs = two * Self::B.clone() * Self::B.clone() + Self::B.clone();
        let rhs = Self::Q.clone() / four;
        lhs < rhs
    }
}
