//! Branch-prediction profile integration coverage.

use std::collections::BTreeMap;
use std::path::Path;

use elf2tdg::analysis::{AnalysisOptions, analyze_with_cfg};
use elf2tdg::board_profile::BoardProfile;
use elf2tdg::cfg;
use elf2tdg::loader;
use elf2tdg_schema::BlockId;

#[test]
#[allow(clippy::too_many_lines)]
fn applies_branch_misprediction_penalties() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let elf =
        manifest.join("../../examples/rust-concurrency/artifacts/rust-concurrency-analysis.elf");
    let profile_path = manifest.join("../../examples/profiles/cortex-m7-branch-prediction.toml");
    if !elf.exists() || !profile_path.exists() {
        return;
    }
    let image = loader::load(&elf).expect("example ELF must load");
    let prediction_profile = BoardProfile::load(&profile_path).expect("profile must load");
    let profile_text = std::fs::read_to_string(&profile_path).expect("profile text");
    let without_prediction = profile_text
        .split("[branch_prediction]")
        .next()
        .expect("profile prefix");
    let base_profile = BoardProfile::parse_toml(without_prediction).expect("base profile");
    let base = analyze_with_cfg(
        &image,
        &AnalysisOptions {
            board_profile: Some(base_profile),
            ..AnalysisOptions::default()
        },
    )
    .expect("base analysis");
    let predicted = analyze_with_cfg(
        &image,
        &AnalysisOptions {
            board_profile: Some(prediction_profile),
            ..AnalysisOptions::default()
        },
    )
    .expect("prediction analysis");
    base.cfg.ensure_valid().expect("base CFG");
    predicted.cfg.ensure_valid().expect("predicted CFG");

    let info = predicted
        .cfg
        .branch_prediction
        .as_ref()
        .expect("branch-prediction metadata");
    assert_eq!(info.model, "btfn");
    assert_eq!(info.mispredict_penalty, 3);
    assert!(info.initial_state.is_none());
    assert!(info.functions_analyzed > 0);
    assert_eq!(info.functions_fallback, 0);
    assert!(info.branches_analyzed > 0);
    assert_eq!(info.branches_fallback, 0);
    assert!(base.cfg.branch_prediction.is_none());

    let base_costs = block_costs(&base.cfg);
    let mut saw_mispredict = false;
    let mut saw_correct = false;
    let mut saw_taken = false;
    let mut saw_not_taken = false;
    let mut branch_blocks = 0_u32;
    for function in &predicted.cfg.functions {
        for node in function.cfg.blocks_by_address.values() {
            let block = &function.cfg.graph[*node];
            let Some(prediction) = &block.branch_prediction else {
                continue;
            };
            branch_blocks += 1;
            assert!(!prediction.fallback);
            assert_eq!(prediction.outcomes.len(), 2);
            for outcome in &prediction.outcomes {
                match outcome.actual {
                    cfg::CfgBranchDirection::Taken => saw_taken = true,
                    cfg::CfgBranchDirection::NotTaken => saw_not_taken = true,
                }
                assert_ne!(outcome.predicted, cfg::CfgBranchPredictionOutcome::Mixed);
                saw_mispredict |= outcome.mispredicts_max > 0;
                saw_correct |= outcome.mispredicts_min == 0;
            }
            let base_cycles = base_costs.get(&block.id).expect("base block");
            if let Some(cycles) = block.cycles {
                let expected_min = base_cycles.min
                    + f64::from(prediction.mispredicts_min * info.mispredict_penalty);
                let expected_max = base_cycles.max
                    + f64::from(prediction.mispredicts_max * info.mispredict_penalty);
                assert!((cycles.min - expected_min).abs() < 1e-6);
                assert!((cycles.max - expected_max).abs() < 1e-6);
            }
        }
    }
    assert_eq!(branch_blocks, info.branches_analyzed);
    assert!(saw_mispredict, "example code must contain mispredictions");
    assert!(
        saw_correct,
        "some modeled outcome must be predicted correctly"
    );
    assert!(saw_taken && saw_not_taken);

    let json = cfg::render_json(&predicted.cfg, None, false).expect("CFG JSON");
    let document: serde_json::Value = serde_json::from_str(&json).expect("CFG JSON");
    assert_eq!(document["cfg_schema_version"], cfg::CFG_SCHEMA_VERSION);
    assert_eq!(document["branch_prediction"]["model"], "btfn");
    assert_eq!(document["branch_prediction"]["mispredict_penalty"], 3);
    assert!(
        document["functions"]
            .as_array()
            .is_some_and(|functions| functions.iter().any(|function| {
                function["blocks"].as_array().is_some_and(|blocks| {
                    blocks.iter().any(|block| {
                        block["branch_prediction"].is_object()
                            && block["branch_prediction"]["outcomes"]
                                .as_array()
                                .is_some_and(|outcomes| {
                                    outcomes.len() == 2
                                        && outcomes.iter().all(|outcome| {
                                            outcome["actual"].is_string()
                                                && outcome["predicted"].is_string()
                                        })
                                })
                    })
                })
            }))
    );
}

fn block_costs(program: &cfg::ProgramCfg) -> BTreeMap<BlockId, elf2tdg_schema::CostRange> {
    let mut costs = BTreeMap::new();
    for function in &program.functions {
        for node in function.cfg.blocks_by_address.values() {
            let block = &function.cfg.graph[*node];
            if let Some(cycles) = block.cycles {
                costs.insert(block.id.clone(), cycles);
            }
        }
    }
    costs
}
