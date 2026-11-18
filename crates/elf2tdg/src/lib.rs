//! CFG-first static analysis for embedded ELF images.

pub mod analysis;
pub mod arch;
pub mod board_profile;
mod cache_state;
pub mod cfg;
pub mod cfg_graph;
pub mod dwarf;
pub mod elf_view;
pub mod error;
mod icache;
pub mod loader;
pub mod origin;
pub mod rules;
pub mod runtime;
pub mod timing;
