// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! Trait specifying a slow hashing function

use crate::{
    errors::InternalError,
    hash::{Hash, ProxyHash},
};
use alloc::vec::Vec;
use digest::core_api::{BlockSizeUser, CoreProxy};
use digest::Output;
use generic_array::typenum::{IsLess, Le, NonZero, U256};

/// Used for the slow hashing function in OPAQUE
pub trait SlowHash<D: Hash>: Default
where
    <D as CoreProxy>::Core: ProxyHash,
    <<D as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<<D as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    /// Computes the slow hashing function
    fn hash(&self, input: Output<D>) -> Result<Vec<u8>, InternalError>;
}

/// A no-op hash which simply returns its input
#[derive(Default)]
pub struct NoOpHash;

impl<D: Hash> SlowHash<D> for NoOpHash
where
    <D as CoreProxy>::Core: ProxyHash,
    <<D as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<<D as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    fn hash(&self, input: Output<D>) -> Result<Vec<u8>, InternalError> {
        Ok(input.to_vec())
    }
}

#[cfg(feature = "slow-hash")]
impl<D: Hash> SlowHash<D> for argon2::Argon2<'_>
where
    <D as CoreProxy>::Core: ProxyHash,
    <<D as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<<D as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    fn hash(&self, input: Output<D>) -> Result<Vec<u8>, InternalError> {
        let mut output = alloc::vec![0u8; D::output_size()];
        self.hash_password_into(&input, &[0; argon2::MIN_SALT_LEN], &mut output)
            .map_err(|_| InternalError::SlowHashError)?;
        Ok(output)
    }
}
