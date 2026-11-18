//! Static Task Dependency Graph extraction for embedded ELF images.

pub mod analysis;
pub mod arch;
pub mod cfg;
pub mod cfg_graph;
pub mod dwarf;
pub mod elf_view;
pub mod error;
pub mod loader;
pub mod origin;
pub mod output;
pub mod rules;
pub mod runtime;
pub mod timing;
