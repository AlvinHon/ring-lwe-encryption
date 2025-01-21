//! Defines the `IntField` trait for finite fields over integers.

use num::{Integer, Signed};
use rand::distributions::uniform::SampleUniform;

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
    type I: Integer + Signed + Clone + SampleUniform;
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
}
