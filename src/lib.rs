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

#[cfg(test)]
mod tests {

    use std::vec;

    use super::*;

    struct ZqI32;

    impl IntField for ZqI32 {
        type I = i32;
        const Q: i32 = 8383489; // a prime number
        const B: i32 = 16;
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
}
