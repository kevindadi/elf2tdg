//! Static Task Dependency Graph extraction for embedded ELF images.

pub mod analysis;
pub mod arch;
pub mod cfg;
pub mod dwarf;
pub mod error;
pub mod loader;
pub mod origin;
pub mod output;
pub mod rules;
pub mod runtime;
pub mod timing;
