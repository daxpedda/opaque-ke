// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

/// Macro used for deriving `serde`'s `Serialize` and `Deserialize` traits.
macro_rules! impl_serialize_and_deserialize_for {
    ($t:ident) => {
        #[cfg(feature = "serialize")]
        impl<CS: CipherSuite> serde::Serialize for $t<CS> {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                use serde::ser::Error;

                if serializer.is_human_readable() {
                    serializer
                        .serialize_str(&base64::encode(&self.serialize().map_err(Error::custom)?))
                } else {
                    serializer.serialize_bytes(&self.serialize().map_err(Error::custom)?)
                }
            }
        }

        #[cfg(feature = "serialize")]
        impl<'de, CS: CipherSuite> serde::Deserialize<'de> for $t<CS> {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                use serde::de::Error;

                if deserializer.is_human_readable() {
                    let s = <&str>::deserialize(deserializer)?;
                    Self::deserialize(&base64::decode(s).map_err(Error::custom)?)
                        .map_err(Error::custom)
                } else {
                    struct ByteVisitor<CS: CipherSuite>(core::marker::PhantomData<CS>);

                    impl<'de, CS: CipherSuite> serde::de::Visitor<'de> for ByteVisitor<CS> {
                        type Value = $t<CS>;

                        fn expecting(
                            &self,
                            formatter: &mut core::fmt::Formatter,
                        ) -> core::fmt::Result {
                            formatter.write_str(core::concat!(
                                "the byte representation of a ",
                                core::stringify!($t)
                            ))
                        }

                        fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
                        where
                            E: Error,
                        {
                            $t::<CS>::deserialize(value).map_err(|_| {
                                Error::invalid_value(
                                    serde::de::Unexpected::Bytes(value),
                                    &core::concat!(
                                        "invalid byte sequence for ",
                                        core::stringify!($t)
                                    ),
                                )
                            })
                        }
                    }

                    deserializer
                        .deserialize_bytes(ByteVisitor::<CS>(core::marker::PhantomData))
                        .map_err(Error::custom)
                }
            }
        }
    };
}
