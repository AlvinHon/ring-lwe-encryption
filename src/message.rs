//! Defines the Message struct and its associated methods.

use num::{One, Zero};

use crate::IntField;

/// Represents a message to be encrypted or decrypted.
///
/// The message is represented as a vector of integers in the field `Zq`,
/// and the length of the message must be less than or equal to `N`.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message<Zq: IntField, const N: usize> {
    pub(crate) data: Vec<Zq::I>,
}

impl<Zq: IntField, const N: usize> Message<Zq, N> {
    /// Creates a new message from a vector of integers.
    ///
    /// ## Safety
    /// Message `m` must be a vector of integers in {0, 1}, i.e. binary message.
    /// and the length of the message must be less than or equal to `N`.
    pub fn new(data: Vec<Zq::I>) -> Self {
        assert!(data.len() <= N);
        data.iter()
            .for_each(|mi| assert!(mi == &Zq::I::zero() || mi == &Zq::I::one()));

        Self { data }
    }

    /// Returns the length of the message.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns true if the message is empty.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Returns the data of the message as a vector of integers.
    pub fn data(self) -> Vec<Zq::I> {
        self.data
    }

    pub fn random<R: rand::Rng>(rng: &mut R, len: usize) -> Self {
        assert!(len <= N);
        let data = (0..len)
            .map(|_| {
                if rng.random_bool(0.5) {
                    Zq::I::one()
                } else {
                    Zq::I::zero()
                }
            })
            .collect();

        Self { data }
    }
}

impl<Zq: IntField, const N: usize> From<Vec<Zq::I>> for Message<Zq, N> {
    fn from(value: Vec<Zq::I>) -> Self {
        Message::new(value)
    }
}
