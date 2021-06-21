// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! Trait specifying a slow hashing function

use crate::{errors::InternalPakeError, hash::Hash};
use digest::Digest;
#[cfg(feature = "slow-hash")]
use generic_array::typenum::Unsigned;
use generic_array::GenericArray;

/// Used for the slow hashing function in OPAQUE
pub trait SlowHash<D: Hash>: Default {
    /// Computes the slow hashing function
    fn hash(
        &self,
        input: GenericArray<u8, <D as Digest>::OutputSize>,
    ) -> Result<Vec<u8>, InternalPakeError>;
}

/// A no-op hash which simply returns its input
#[derive(Default)]
pub struct NoOpHash;

impl<D: Hash> SlowHash<D> for NoOpHash {
    fn hash(
        &self,
        input: GenericArray<u8, <D as Digest>::OutputSize>,
    ) -> Result<Vec<u8>, InternalPakeError> {
        Ok(input.to_vec())
    }
}

#[cfg(feature = "slow-hash")]
impl<D: Hash> SlowHash<D> for argon2::Argon2<'_> {
    fn hash(
        &self,
        input: GenericArray<u8, <D as Digest>::OutputSize>,
    ) -> Result<Vec<u8>, InternalPakeError> {
        let mut output = vec![0u8; <D as Digest>::OutputSize::to_usize()];
        self
            .hash_password_into(
                argon2::Algorithm::Argon2id,
                &input,
                &[0; argon2::MIN_SALT_LENGTH],
                &[],
                &mut output,
            )
            .map_err(|_| InternalPakeError::SlowHashError)?;
        Ok(output)
    }
}
