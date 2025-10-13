# Ring-LWE Encryption

Rust implementation of a Lattice-based encryption using polynomial ring based on hardness of LWE problem.

This work is inspired by the paper [Basic Lattice Cryptography](https://eprint.iacr.org/2024/1287.pdf) by Vadim Lyubashevsky.

To use this library, you will need to use integers compatible to the types that implements the `Integer` trait in the crate [num](https://crates.io/crates/num). The message to encrypt are represented as a vector of integers in {0, 1}. Natively, you can use rust primitive types such as `i32` and `i64`. You can also use `BigInt` depending on your needs.

## Usage

For convenience, the key generation method `standard` is provided using the NIST standard parameters.

```rust
let rng = &mut rand::rng();

// Key generation using standard parameters
let (ek, dk) = rlwe_encryption::standard(rng);
// message is a vector of ones and zeros
let message = vec![0, 1, 0, 1];
// Encrypt the message
let ciphertext = ek.encrypt(rng, message.clone());
// Decrypt the ciphertext and then truncate to the length of the original message.
let decrypted = dk.decrypt(ciphertext)[..message.len()].to_vec();
assert_eq!(message, decrypted);
```