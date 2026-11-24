//! Layered system model coverage.

use std::path::Path;

use elf2tdg::analysis::{AnalysisOptions, analyze_with_cfg};
use elf2tdg::board_profile::BoardProfile;
use elf2tdg::cfg::{self, CfgWcetStatus};
use elf2tdg::loader;
use elf2tdg::text_report;

fn example_elf() -> Option<std::path::PathBuf> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/rust-concurrency/artifacts/rust-concurrency-analysis.elf");
    path.exists().then_some(path)
}

#[test]
fn builds_layered_model_from_root_wcet() {
    let Some(elf_path) = example_elf() else {
        eprintln!("skipping layered model test: example ELF is absent");
        return;
    };
    let profile_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/profiles/cortex-m7-wcet.toml");
    if !profile_path.exists() {
        eprintln!("skipping layered model test: WCET profile is absent");
        return;
    }

    let image = loader::load(&elf_path).expect("example ELF must load");
    let profile = BoardProfile::load(&profile_path).expect("profile must load");
    let analysis = analyze_with_cfg(
        &image,
        &AnalysisOptions {
            board_profile: Some(profile),
            ..AnalysisOptions::default()
        },
    )
    .expect("analysis must succeed");
    analysis.cfg.ensure_valid().expect("CFG must validate");

    let model = analysis
        .cfg
        .system_model
        .as_ref()
        .expect("layered system model");
    assert_eq!(model.model, "layered-petri-state-equation");
    assert!(!model.tasks.is_empty());
    assert_eq!(model.boot_roots, 2);
    assert_eq!(model.places.len(), 1 + 2 * model.tasks.len());
    assert_eq!(model.transitions.len(), model.tasks.len());
    assert_eq!(model.bound.tasks, u32::try_from(model.tasks.len()).unwrap());
    let petri = model.petri.as_ref().expect("state-equation solution");
    assert_eq!(petri.relaxation, "state-equation");
    assert_eq!(petri.status, "optimal");
    assert_eq!(petri.firing.len(), model.tasks.len());
    assert!(
        petri.firing.iter().all(|firing| firing.fires == 1),
        "default activation model must fire each transition once"
    );
    let objective = petri.objective.expect("finite objective");
    let bound = model.bound.cycles.expect("solver-backed bound");
    assert!((objective - bound).abs() < 1e-6);
    assert!(
        model
            .bound
            .assumptions
            .iter()
            .any(|assumption| assumption.contains("runs at most its activation bound"))
    );
    if model.bound.status == CfgWcetStatus::Bounded {
        assert!(model.bound.cycles.is_some());
    }
    assert_eq!(model.bound.tasks, u32::try_from(model.tasks.len()).unwrap());

    let json =
        cfg::render_json(&analysis.cfg, Some("sensor_task"), false).expect("CFG JSON must render");
    let value: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    assert_eq!(value["cfg_schema_version"], cfg::CFG_SCHEMA_VERSION);
    assert!(value.get("system_model").is_some());
    assert_eq!(
        value["system_model"]["bound"]["scope"],
        "analyzed-core-activation-bounds"
    );
    assert_eq!(value["system_model"]["petri"]["status"], "optimal");
    assert_eq!(
        value["system_model"]["petri"]["relaxation"],
        "state-equation"
    );

    let text = text_report::render_text(&analysis.cfg, Some("sensor_task"), false)
        .expect("text report must render");
    assert!(text.contains("layered system model"));
    assert!(text.contains("layered-petri-state-equation"));
    assert!(text.contains("petri solver"));
    assert!(text.contains("petri objective"));
    assert!(text.contains("assumption:"));
}

#[test]
fn applies_activation_and_resource_budgets() {
    let Some(elf_path) = example_elf() else {
        eprintln!("skipping activation/resource test: example ELF is absent");
        return;
    };
    let profile_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/profiles/cortex-m7-wcet.toml");
    let Ok(mut profile_text) = std::fs::read_to_string(&profile_path) else {
        eprintln!("skipping activation/resource test: WCET profile is absent");
        return;
    };
    profile_text.push_str(
        r#"

[system]

[[system.tasks]]
target = "sensor_task"
activations = 3
resources = { bus = 1 }

[[system.resources]]
name = "bus"
capacity = 4
"#,
    );
    let profile = BoardProfile::parse_toml(&profile_text).expect("valid system profile");
    let image = loader::load(&elf_path).expect("example ELF must load");
    let analysis = analyze_with_cfg(
        &image,
        &AnalysisOptions {
            board_profile: Some(profile),
            ..AnalysisOptions::default()
        },
    )
    .expect("analysis must succeed");

    let model = analysis
        .cfg
        .system_model
        .as_ref()
        .expect("layered system model");
    let sensor = model
        .tasks
        .iter()
        .find(|task| {
            task.name
                .as_deref()
                .is_some_and(|name| name.ends_with("sensor_task"))
        })
        .expect("sensor task");
    assert_eq!(sensor.activation_bound, 3);
    assert_eq!(model.bound.max_activations, 3);
    assert!(
        model
            .places
            .iter()
            .any(|place| place.id == "budget:bus" && place.tokens == 4 && place.capacity == 4)
    );
    let petri = model.petri.as_ref().expect("state-equation solution");
    assert_eq!(petri.status, "optimal");
    let firing = petri
        .firing
        .iter()
        .find(|firing| firing.transition == format!("execute:{}", sensor.id))
        .expect("sensor firing count");
    assert_eq!(firing.fires, 3);
    assert!(model.bound.cycles.expect("bound") > 1_071.0);
}
