use core::fmt;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub(crate) mod u64_string {
    use super::*;

    pub(crate) fn serialize<S>(value: &u64, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.to_string())
    }

    pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<u64, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        if value.is_empty()
            || (value.len() > 1 && value.starts_with('0'))
            || !value.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(D::Error::custom("expected canonical decimal u64 string"));
        }
        value.parse().map_err(D::Error::custom)
    }
}

macro_rules! fixed_hex {
    ($name:ident, $size:expr) => {
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; $size]);

        impl $name {
            #[must_use]
            pub const fn new(bytes: [u8; $size]) -> Self {
                Self(bytes)
            }

            #[must_use]
            pub const fn to_bytes(self) -> [u8; $size] {
                self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "("))?;
                formatter.write_str(&hex::encode(self.0))?;
                formatter.write_str(")")
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                if serializer.is_human_readable() {
                    serializer.serialize_str(&hex::encode(self.0))
                } else {
                    self.0.as_slice().serialize(serializer)
                }
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                if deserializer.is_human_readable() {
                    let value = String::deserialize(deserializer)?;
                    if value.len() != $size * 2
                        || !value
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                    {
                        return Err(D::Error::custom(concat!(
                            "expected fixed-width lowercase hex for ",
                            stringify!($name)
                        )));
                    }
                    let decoded = hex::decode(value).map_err(D::Error::custom)?;
                    let bytes: [u8; $size] = decoded.try_into().map_err(|_| {
                        D::Error::custom(concat!("wrong byte length for ", stringify!($name)))
                    })?;
                    Ok(Self(bytes))
                } else {
                    let decoded = Vec::<u8>::deserialize(deserializer)?;
                    let bytes: [u8; $size] = decoded.try_into().map_err(|_| {
                        D::Error::custom(concat!("wrong byte length for ", stringify!($name)))
                    })?;
                    Ok(Self(bytes))
                }
            }
        }
    };
}

fixed_hex!(FixedBytes32, 32);
fixed_hex!(FixedBytes33, 33);
fixed_hex!(FixedBytes64, 64);

pub(crate) mod bytes_hex {
    use super::*;

    pub(crate) fn serialize<S>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&hex::encode(value))
        } else {
            value.serialize(serializer)
        }
    }

    pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let value = String::deserialize(deserializer)?;
            if value.len() % 2 != 0
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(D::Error::custom("expected canonical lowercase hex"));
            }
            hex::decode(value).map_err(D::Error::custom)
        } else {
            Vec::<u8>::deserialize(deserializer)
        }
    }
}

pub(crate) mod option_bytes_hex {
    use super::*;

    pub(crate) fn serialize<S>(value: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(value) if serializer.is_human_readable() => {
                serializer.serialize_some(&hex::encode(value))
            }
            Some(value) => serializer.serialize_some(value),
            None => serializer.serialize_none(),
        }
    }

    pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let value = Option::<String>::deserialize(deserializer)?;
            value
                .map(|value| {
                    if value.len() % 2 != 0
                        || !value
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                    {
                        return Err(D::Error::custom("expected canonical lowercase hex"));
                    }
                    hex::decode(value).map_err(D::Error::custom)
                })
                .transpose()
        } else {
            Option::<Vec<u8>>::deserialize(deserializer)
        }
    }
}
