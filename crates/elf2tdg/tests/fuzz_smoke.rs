//! Deterministic fuzz-smoke coverage for malformed ELF and CFG validation.
//!
//! The cargo-fuzz harness under `fuzz/` explores arbitrary inputs with
//! libFuzzer. This test keeps a small deterministic corpus in the normal test
//! suite so parser/analyzer panics and invariant failures are caught without a
//! nightly toolchain.

use std::path::Path;

use elf2tdg::analysis::{AnalysisOptions, analyze_with_cfg};
use elf2tdg::error::Error;
use elf2tdg::loader;

fn next_random(state: &mut u64) -> u64 {
    let mut value = *state;
    value ^= value << 13;
    value ^= value >> 7;
    value ^= value << 17;
    *state = value;
    value
}

fn analyze_bounded(image: &elf2tdg::loader::Image) {
    let options = AnalysisOptions {
        max_functions: 2_048,
        max_instructions_per_function: 20_000,
        max_diagnostics: 32,
        ..AnalysisOptions::default()
    };
    match analyze_with_cfg(image, &options) {
        Ok(analysis) => {
            analysis.cfg.ensure_valid().expect("CFG must validate");
        }
        Err(Error::CfgValidation(message)) => {
            panic!("analysis produced an invalid graph: {message}");
        }
        Err(_) => {}
    }
}

#[test]
fn random_bytes_never_panic() {
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    for _ in 0..512 {
        let len = usize::try_from(next_random(&mut state) % 1024).unwrap_or(0);
        let bytes: Vec<u8> = (0..len)
            .map(|_| u8::try_from(next_random(&mut state) & 0xff).unwrap_or(0))
            .collect();
        if let Ok(image) = loader::load_from_bytes(&bytes, "random.elf") {
            analyze_bounded(&image);
        }
    }
}

#[test]
fn mutated_fixture_never_produces_an_invalid_graph() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/rust_alloc_trait/firmware.elf");
    if !path.exists() {
        eprintln!("skipping ELF mutation smoke test: allocator fixture is absent");
        return;
    }
    let original = std::fs::read(&path).expect("fixture must be readable");
    let mut state = 0xd1b5_4a32_d192_ed03_u64;
    for _ in 0..16 {
        let mut bytes = original.clone();
        let flips = usize::try_from(next_random(&mut state) % 4 + 1).unwrap_or(1);
        for _ in 0..flips {
            let index = usize::try_from(next_random(&mut state) % bytes.len() as u64).unwrap_or(0);
            let mask = u8::try_from(next_random(&mut state) & 0xff).unwrap_or(0xff);
            bytes[index] ^= mask;
        }
        if let Ok(image) = loader::load_from_bytes(&bytes, "mutated.elf") {
            analyze_bounded(&image);
        }
    }
}
