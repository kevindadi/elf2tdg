#![no_main]

use elf2tdg::analysis::{AnalysisOptions, analyze_with_cfg};
use elf2tdg::error::Error;
use elf2tdg::loader;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 2 * 1024 * 1024 {
        return;
    }
    let Ok(image) = loader::load_from_bytes(data, "fuzz.elf") else {
        return;
    };
    let options = AnalysisOptions {
        max_functions: 4_096,
        max_instructions_per_function: 50_000,
        max_diagnostics: 64,
        ..AnalysisOptions::default()
    };
    match analyze_with_cfg(&image, &options) {
        Ok(analysis) => {
            analysis.cfg.ensure_valid().expect("CFG must validate");
        }
        Err(Error::CfgValidation(message)) => {
            panic!("analysis produced an invalid graph: {message}");
        }
        Err(_) => {}
    }
});
