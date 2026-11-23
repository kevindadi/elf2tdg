//! CFG-first static analysis for embedded ELF images.

pub mod analysis;
pub mod arch;
pub mod board_profile;
mod branch_prediction;
mod cache_state;
pub mod cfg;
pub mod cfg_graph;
mod data_memory;
mod dcache;
pub mod dwarf;
pub mod elf_view;
pub mod error;
mod flow_facts;
mod icache;
mod ipet;
pub mod loader;
mod multicore;
pub mod origin;
pub mod passes;
pub mod rules;
pub mod runtime;
pub mod text_report;
pub mod timing;
mod wcet;
