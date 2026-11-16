#![allow(missing_docs)]

use elf2tdg_schema::{
    Addr, BlockId, Confidence, ContextId, Edge, EdgeId, FunctionId, JoinTarget, SCHEMA_VERSION,
    Scope, ScopeKind, SpawnTarget, Tdg, ValidationCode,
};

const SAMPLE: &str = include_str!("data/sample-tdg.json");

fn sample() -> Tdg {
    serde_json::from_str(SAMPLE).expect("sample fixture must deserialize")
}

#[test]
fn sample_deserializes_and_validates() {
    let tdg = sample();
    assert_eq!(tdg.schema_version, SCHEMA_VERSION);
    let issues = tdg.validate();
    assert!(issues.is_empty(), "unexpected issues: {issues:#?}");
    tdg.ensure_valid().expect("sample must be valid");
}

#[test]
fn sample_round_trips_through_json() {
    let tdg = sample();
    let json = serde_json::to_string_pretty(&tdg).expect("TDG must serialize");
    let reparsed: Tdg = serde_json::from_str(&json).expect("serialized TDG must parse");
    assert_eq!(tdg, reparsed);
}

#[test]
fn addresses_use_hex_strings_in_json() {
    let tdg = sample();
    let text = serde_json::to_string(&tdg).expect("TDG must serialize");
    assert!(text.contains("\"entry\":\"0x8000101\""));
    assert!(text.contains("\"address\":\"0x8000100\""));
}

#[test]
fn json_schema_is_generated() {
    let schema = serde_json::to_value(Tdg::json_schema()).expect("schema must serialize");
    let text = serde_json::to_string(&schema).expect("schema value must serialize");
    assert!(text.contains("schema_version"));
    assert!(text.contains("spawn"));
    assert!(text.contains("Address"));
}

#[test]
fn duplicate_function_id_is_reported() {
    let mut tdg = sample();
    let duplicate = tdg.functions[0].clone();
    tdg.functions.push(duplicate);

    let issues = tdg.validate();
    assert!(
        issues
            .iter()
            .any(|issue| issue.code == ValidationCode::DuplicateId),
        "expected DuplicateId, got {issues:#?}"
    );
}

#[test]
fn dangling_context_entry_is_reported() {
    let mut tdg = sample();
    tdg.contexts[0].entry = FunctionId::new("fn:0xdead");

    let issues = tdg.validate();
    assert!(
        issues
            .iter()
            .any(|issue| issue.code == ValidationCode::DanglingReference
                && issue.path == "/contexts/0/entry")
    );
}

#[test]
fn dangling_block_successor_is_reported() {
    let mut tdg = sample();
    tdg.functions[0].blocks[0]
        .successors
        .push(BlockId::new("bb:0xdead"));

    let issues = tdg.validate();
    assert!(
        issues
            .iter()
            .any(|issue| issue.code == ValidationCode::DanglingReference
                && issue.path.contains("/successors/0"))
    );
}

#[test]
fn cross_function_block_successor_is_reported() {
    let mut tdg = sample();
    let other_block = tdg.functions[1].blocks[0].id.clone();
    tdg.functions[0].blocks[0].successors.push(other_block);

    let issues = tdg.validate();
    assert!(
        issues
            .iter()
            .any(|issue| issue.code == ValidationCode::InvalidBlockOwner)
    );
}

#[test]
fn dangling_lock_function_is_reported() {
    let mut tdg = sample();
    tdg.locks[0].function = FunctionId::new("fn:0xdead");
    let issues = tdg.validate();
    assert!(
        issues.iter().any(|issue| {
            issue.code == ValidationCode::DanglingReference && issue.path == "/locks/0/function"
        }),
        "expected dangling lock function, got {issues:#?}"
    );
}

#[test]
fn parent_cycle_is_reported() {
    let mut tdg = sample();
    let main_id = tdg.contexts[1].id.clone();
    tdg.contexts[1].parent = Some(main_id);

    let issues = tdg.validate();
    assert!(
        issues
            .iter()
            .any(|issue| issue.code == ValidationCode::ParentCycle)
    );
}

#[test]
fn zero_frequency_is_reported() {
    let mut tdg = sample();
    tdg.timing.frequency_domains[0].hz = 0;

    let issues = tdg.validate();
    assert!(
        issues
            .iter()
            .any(|issue| issue.code == ValidationCode::InvalidFrequency)
    );
}

#[test]
fn invalid_cost_range_is_reported() {
    let mut tdg = sample();
    tdg.functions[0].blocks[0]
        .timing
        .as_mut()
        .expect("sample block has timing")
        .cycles
        .min = -1.0;

    let issues = tdg.validate();
    assert!(
        issues
            .iter()
            .any(|issue| issue.code == ValidationCode::InvalidCostRange)
    );
}

#[test]
fn spawn_entry_mismatch_is_reported() {
    let mut tdg = sample();
    let entry = tdg
        .edges
        .iter_mut()
        .find_map(|edge| match edge {
            Edge::Spawn {
                target: SpawnTarget::Context { entry, .. },
                ..
            } => Some(entry),
            _ => None,
        })
        .expect("sample has a spawn edge");
    *entry = FunctionId::new("fn:0x08000500");

    let issues = tdg.validate();
    assert!(
        issues
            .iter()
            .any(|issue| issue.code == ValidationCode::SpawnEntryMismatch)
    );
}

#[test]
fn opaque_spawn_candidate_must_exist() {
    let mut tdg = sample();
    let target = tdg
        .edges
        .iter_mut()
        .find_map(|edge| match edge {
            Edge::Spawn { target, .. } => Some(target),
            _ => None,
        })
        .expect("sample has a spawn edge");
    *target = SpawnTarget::Opaque {
        candidates: vec![FunctionId::new("fn:0xdead")],
    };

    let issues = tdg.validate();
    assert!(
        issues
            .iter()
            .any(|issue| issue.code == ValidationCode::DanglingReference
                && issue.path.contains("/target/candidates/0"))
    );
}

#[test]
fn opaque_join_candidate_must_exist() {
    let mut tdg = sample();
    let target = tdg
        .edges
        .iter_mut()
        .find_map(|edge| match edge {
            Edge::Join { target, .. } => Some(target),
            _ => None,
        })
        .expect("sample has a join edge");
    *target = JoinTarget::Opaque {
        candidates: vec![ContextId::new("ctx:dead")],
    };

    let issues = tdg.validate();
    assert!(
        issues
            .iter()
            .any(|issue| issue.code == ValidationCode::DanglingReference
                && issue.path.contains("/target/candidates/0"))
    );
}

#[test]
fn site_outside_function_is_reported() {
    let mut tdg = sample();
    let site = tdg
        .edges
        .iter_mut()
        .find_map(|edge| match edge {
            Edge::Call { site, .. } => Some(site),
            _ => None,
        })
        .expect("sample has a call edge");
    *site = Addr::new(0x0800_ffff);

    let issues = tdg.validate();
    assert!(
        issues
            .iter()
            .any(|issue| issue.code == ValidationCode::SiteOutOfRange)
    );
}

#[test]
fn non_spawn_scope_member_is_reported() {
    let mut tdg = sample();
    tdg.scopes.push(Scope {
        id: "scope:0x08000300".into(),
        kind: ScopeKind::RustThreadScope,
        entering_context: ContextId::new("ctx:main"),
        enter_site: Addr::new(0x0800_0300),
        exit_site: Some(Addr::new(0x0800_0340)),
        implicit_join: true,
        members: vec![EdgeId::new("e:call:0x08000240")],
        confidence: Confidence::Medium,
    });

    let issues = tdg.validate();
    assert!(
        issues
            .iter()
            .any(|issue| issue.code == ValidationCode::InvalidScopeMember)
    );
}

#[test]
fn unsupported_schema_version_is_reported() {
    let mut tdg = sample();
    tdg.schema_version = "2.0".to_owned();

    let issues = tdg.validate();
    assert!(
        issues
            .iter()
            .any(|issue| issue.code == ValidationCode::UnsupportedSchemaVersion)
    );
}

#[test]
#[allow(clippy::assert_is_empty)]
fn ensure_valid_returns_structured_error() {
    let mut tdg = sample();
    tdg.timing.frequency_domains[0].hz = 0;

    let error = tdg.ensure_valid().expect_err("document must be invalid");
    assert!(!error.issues.is_empty());
    assert!(error.to_string().contains("validation failed"));
}

#[test]
fn validation_limit_is_respected() {
    let mut tdg = sample();
    for _ in 0..64 {
        let duplicate = tdg.functions[0].clone();
        tdg.functions.push(duplicate);
    }

    let issues = tdg.validate_with_limit(3);
    assert_eq!(issues.len(), 3);
}
