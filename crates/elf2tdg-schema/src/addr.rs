//! Address representation.
//!
//! Addresses are stored as `u64` and serialized as lowercase `0x`-prefixed
//! strings. Hexadecimal strings avoid the precision hazards of JSON numbers for
//! 64-bit addresses and are readable in diffs and hand-written fixtures.
//!
//! Deserialization accepts hex strings, decimal strings and JSON integers for
//! robustness when importing data from other tools. Serialization is always
//! canonical hex.

use std::borrow::Cow;
use std::fmt;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

/// A virtual address.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Addr(u64);

impl Addr {
    /// The zero address.
    pub const ZERO: Self = Self(0);

    /// Creates an address from a raw integer.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the raw integer value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Adds a byte offset, returning `None` on overflow.
    #[must_use]
    pub fn checked_add(self, offset: u64) -> Option<Self> {
        self.0.checked_add(offset).map(Self)
    }

    /// Subtracts a byte offset, returning `None` on underflow.
    #[must_use]
    pub fn checked_sub(self, offset: u64) -> Option<Self> {
        self.0.checked_sub(offset).map(Self)
    }

    /// Returns the canonical serialized form (`0x` plus lowercase hex, no
    /// zero-padding).
    #[must_use]
    pub fn to_hex(self) -> String {
        format!("0x{:x}", self.0)
    }
}

impl fmt::Display for Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl From<u64> for Addr {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<Addr> for u64 {
    fn from(value: Addr) -> Self {
        value.0
    }
}

impl Serialize for Addr {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Addr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct AddrVisitor;

        impl de::Visitor<'_> for AddrVisitor {
            type Value = Addr;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an address as \"0x...\" (hex), a decimal string, or an integer")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let value = value.trim();
                let (digits, radix) = if let Some(rest) = value
                    .strip_prefix("0x")
                    .or_else(|| value.strip_prefix("0X"))
                {
                    (rest, 16)
                } else {
                    (value, 10)
                };
                if digits.is_empty() {
                    return Err(E::custom(format!(
                        "invalid address {value:?}: empty digits"
                    )));
                }
                u64::from_str_radix(digits, radix)
                    .map(Addr)
                    .map_err(|error| E::custom(format!("invalid address {value:?}: {error}")))
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(Addr(value))
            }

            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                u64::try_from(value)
                    .map(Addr)
                    .map_err(|_| E::custom(format!("invalid negative address {value}")))
            }
        }

        deserializer.deserialize_any(AddrVisitor)
    }
}

impl JsonSchema for Addr {
    fn schema_name() -> Cow<'static, str> {
        "Address".into()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "string",
            "pattern": "^0x[0-9a-f]+$",
            "description": "Lowercase hexadecimal address with a 0x prefix."
        })
    }
}

#[cfg(test)]
mod tests {
    use super::Addr;

    #[test]
    fn serializes_canonically() {
        assert_eq!(Addr::new(0x0800_1234).to_hex(), "0x8001234");
        assert_eq!(
            serde_json::to_string(&Addr::new(0x0800_1234)).unwrap(),
            "\"0x8001234\""
        );
    }

    #[test]
    fn deserializes_hex_decimal_and_integer() {
        let hex: Addr = serde_json::from_str("\"0x08001234\"").unwrap();
        let decimal: Addr = serde_json::from_str("\"134222388\"").unwrap();
        let integer: Addr = serde_json::from_str("134222388").unwrap();
        assert_eq!(hex, decimal);
        assert_eq!(hex, integer);
        assert_eq!(hex.get(), 0x0800_1234);
    }

    #[test]
    fn rejects_invalid_input() {
        assert!(serde_json::from_str::<Addr>("\"0x\"").is_err());
        assert!(serde_json::from_str::<Addr>("\"nope\"").is_err());
        assert!(serde_json::from_str::<Addr>("\"-1\"").is_err());
        assert!(serde_json::from_str::<Addr>("-1").is_err());
    }

    #[test]
    fn checked_arithmetic() {
        assert_eq!(Addr::new(10).checked_add(5), Some(Addr::new(15)));
        assert_eq!(Addr::new(u64::MAX).checked_add(1), None);
        assert_eq!(Addr::new(0).checked_sub(1), None);
    }
}
