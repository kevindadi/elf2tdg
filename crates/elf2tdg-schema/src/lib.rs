//! Versioned data model for the elf2tdg Task Dependency Graph (TDG).
//!
//! The TDG is a typed property graph. Function nodes carry their basic blocks
//! and static timing estimates; context nodes represent execution contexts
//! (startup, main, threads, async tasks, ISRs, ...). Edges are either ordinary
//! call-graph edges or concurrency-control edges such as spawn, join, await and
//! interrupt activation.
//!
//! The serialized form is deliberately boring: JSON with stable IDs, explicit
//! provenance/confidence, and no inferred data that the producer cannot
//! justify. [`Tdg::validate`] checks the cross-reference and timing invariants
//! that every producer is required to satisfy.

pub mod addr;
pub mod id;
pub mod model;
pub mod timing;
pub mod validate;

pub use addr::Addr;
pub use id::{
    BlockId, ContextId, EdgeId, FrequencyDomainId, FunctionId, LockEventId, RuntimeId, ScopeId,
    TimingModelId,
};
pub use model::*;
pub use timing::*;
pub use validate::{ValidationCode, ValidationError, ValidationIssue};

/// Schema major/minor version emitted by this crate.
///
/// Consumers should accept all `1.x` versions and reject unknown major
/// versions. New optional fields may appear in minor releases.
pub const SCHEMA_VERSION: &str = "1.3";

impl model::Tdg {
    /// Generates the JSON Schema for the TDG document format.
    ///
    /// The generated schema is checked into `schema/tdg.schema.json` and
    /// regenerated with `make schema`.
    #[must_use]
    pub fn json_schema() -> schemars::Schema {
        schemars::schema_for!(model::Tdg)
    }
}
