//! Stable, typed identifiers used by the TDG.
//!
//! IDs are strings rather than integers so that they remain meaningful across
//! serialization, merging and diffing. Every ID type has a fixed prefix; the
//! prefix is part of the schema contract, not just a naming convention.

use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

macro_rules! define_prefixed_id {
    ($(#[$meta:meta])* $name:ident, $prefix:literal) => {
        $(#[$meta])*
        #[derive(
            Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
        )]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Creates an ID from any string. Format checking is explicit via
            /// [`Self::is_well_formed`].
            #[must_use]
            pub fn new(value: impl Into<String>) -> Self {
                Self(value.into())
            }

            /// Returns the ID as a string slice.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// Returns `true` when the ID starts with the required prefix and
            /// has a non-empty suffix.
            #[must_use]
            pub fn is_well_formed(&self) -> bool {
                self.0
                    .strip_prefix($prefix)
                    .is_some_and(|suffix| !suffix.is_empty())
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }

        impl From<&str> for $name {
            fn from(value: &str) -> Self {
                Self(value.to_owned())
            }
        }

        impl From<String> for $name {
            fn from(value: String) -> Self {
                Self(value)
            }
        }
    };
}

define_prefixed_id!(
    /// Identifies a function node. Well-formed IDs start with `fn:`.
    FunctionId,
    "fn:"
);
define_prefixed_id!(
    /// Identifies a basic block. Well-formed IDs start with `bb:`.
    BlockId,
    "bb:"
);
define_prefixed_id!(
    /// Identifies an execution context. Well-formed IDs start with `ctx:`.
    ContextId,
    "ctx:"
);
define_prefixed_id!(
    /// Identifies an edge. Well-formed IDs start with `e:`.
    EdgeId,
    "e:"
);
define_prefixed_id!(
    /// Identifies a synchronization/lock event. Well-formed IDs start with
    /// `lock:`.
    LockEventId,
    "lock:"
);
define_prefixed_id!(
    /// Identifies a structured-concurrency scope. Well-formed IDs start with
    /// `scope:`.
    ScopeId,
    "scope:"
);
define_prefixed_id!(
    /// Identifies a clock/frequency domain. Well-formed IDs start with `clk:`.
    FrequencyDomainId,
    "clk:"
);

macro_rules! define_plain_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(
            Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
        )]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Creates an ID from any non-empty string.
            #[must_use]
            pub fn new(value: impl Into<String>) -> Self {
                Self(value.into())
            }

            /// Returns the ID as a string slice.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// Returns `true` when the ID is not empty or whitespace.
            #[must_use]
            pub fn is_well_formed(&self) -> bool {
                !self.0.trim().is_empty()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }

        impl From<&str> for $name {
            fn from(value: &str) -> Self {
                Self(value.to_owned())
            }
        }

        impl From<String> for $name {
            fn from(value: String) -> Self {
                Self(value)
            }
        }
    };
}

define_plain_id!(
    /// Names a concurrency runtime (for example `freertos`, `zephyr`,
    /// `rust-std`, `rust-rayon`, `rust-tokio`, `openmp`).
    RuntimeId
);
define_plain_id!(
    /// Names a timing model (for example `cortex-m4`).
    TimingModelId
);

#[cfg(test)]
mod tests {
    use super::{ContextId, FunctionId, RuntimeId, TimingModelId};

    #[test]
    fn prefixed_ids_require_prefix_and_suffix() {
        assert!(FunctionId::new("fn:0x08000100").is_well_formed());
        assert!(!FunctionId::new("0x08000100").is_well_formed());
        assert!(!FunctionId::new("fn:").is_well_formed());
        assert!(ContextId::new("ctx:thread:sensor").is_well_formed());
    }

    #[test]
    fn plain_ids_require_non_empty_content() {
        assert!(RuntimeId::new("freertos").is_well_formed());
        assert!(!RuntimeId::new("").is_well_formed());
        assert!(!RuntimeId::new("   ").is_well_formed());
        assert!(TimingModelId::new("cortex-m4").is_well_formed());
    }
}
