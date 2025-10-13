#![doc = include_str!("../README.md")]

mod ciphertext;
pub use ciphertext::CipherText;
mod decrypt;
pub use decrypt::DecryptKey;
mod encrypt;
pub use encrypt::EncryptKey;
mod intfield;
pub use intfield::IntField;
pub(crate) mod polynomial;

use polynomial::{modulo_coefficients, rand_polynomial, small_polynomial};
use rand::Rng;
use std::ops::{Add, Mul, Sub};

/// Generate a pair of encryption and decryption keys from the parameters
/// defined in the generic type `Zq` and the value of `N`.
///
/// ## Parameters
///
/// The generic type `Zq` implements the [IntField] trait. Please refer to the
/// documentation of the trait in order to make it work properly.
///
/// The constant `N` defines the length of the polynomial, as well as the maximum
/// length of the message that can be encrypted. It must be a power of 2.
///
/// ## Example
///
/// ```rust
/// use rlwe_encryption::{key_gen, IntField};
///
/// // Define your own field Zq
/// struct ZqI32;
///
/// impl IntField for ZqI32 {
///     type I = i32;
///     const Q: i32 = 8383489; // a prime number
///     const B: i32 = 4;
///
///     fn modulo(x: &Self::I) -> Self::I {
///         let a = x.rem_euclid(Self::Q);
///         if a > Self::Q / 2 {
///             a - Self::Q
///         } else {
///             a
///         }
///     }
/// }
///
/// let rng = &mut rand::rng();
///
/// let (ek, dk) = key_gen::<ZqI32, 512>(rng);
///
/// let message = vec![1, 0, 0, 1];
/// let ciphertext = ek.encrypt(rng, message.clone());
/// let decrypted = dk.decrypt(ciphertext)[..message.len()].to_vec();
/// assert_eq!(message, decrypted);
/// ```
pub fn key_gen<Zq: IntField, const N: usize>(
    rng: &mut impl Rng,
) -> (EncryptKey<Zq, N>, DecryptKey<Zq, N>)
where
    for<'a> &'a Zq::I: Add<Output = Zq::I> + Mul<Output = Zq::I> + Sub<Output = Zq::I>,
{
    let a = rand_polynomial::<Zq, N>(rng);
    let s = small_polynomial::<Zq, N>(rng);
    let e = small_polynomial::<Zq, N>(rng);

    // t = a * s + e
    let t = {
        let a_s = modulo_coefficients::<Zq, N>(a.clone() * s.clone());
        modulo_coefficients::<Zq, N>(a_s + e)
    };

    (EncryptKey { a, t }, DecryptKey { s })
}

/// A pre-defined field over integers with prime modulus 3329.
/// The parameters are chosen according to the NIST standard
/// [FIPS203](https://csrc.nist.gov/pubs/fips/203/final).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZqI32;

impl IntField for ZqI32 {
    type I = i32;
    const Q: i32 = 3329;
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

/// Generate a pair of encryption and decryption keys using the parameters
/// defined in the NIST standard [FIPS203](https://csrc.nist.gov/pubs/fips/203/final).
/// It uses `i32` as the integer type and the length of the message is at most 256 bits.
///
/// ## Example
///
/// ```rust
/// let rng = &mut rand::rng();
///
/// let (ek, dk) = rlwe_encryption::standard(rng);
///
/// let message = vec![0, 1, 0, 1];
/// let ciphertext = ek.encrypt(rng, message.clone());
/// let decrypted = dk.decrypt(ciphertext)[..message.len()].to_vec();
/// assert_eq!(message, decrypted);
/// ```
pub fn standard(rng: &mut impl rand::Rng) -> (EncryptKey<ZqI32, 256>, DecryptKey<ZqI32, 256>) {
    key_gen::<ZqI32, 256>(rng)
}
