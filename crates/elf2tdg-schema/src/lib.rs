//! Shared data model for CFG-first binary analysis.
//!
//! This crate defines the stable IDs, cost/timing records, diagnostics, runtime
//! context records and relation types used by the analyzer and the CFG JSON
//! document. The former TDG document type and its validator have been removed;
//! program analysis metadata is owned by `elf2tdg::cfg::ProgramCfg`.

pub mod addr;
pub mod id;
pub mod model;
pub mod timing;

pub use addr::Addr;
pub use id::{
    BlockId, ContextId, EdgeId, FrequencyDomainId, FunctionId, LockEventId, RuntimeId, ScopeId,
    TimingModelId,
};
pub use model::*;
pub use timing::*;
