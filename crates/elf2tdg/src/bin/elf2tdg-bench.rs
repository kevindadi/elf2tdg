//! Benchmark and regression harness for elf2tdg.
//!
//! The harness runs the normal analysis library over a declarative suite of
//! ELF/profile cases. It records deterministic cycle results, model selections
//! and fallbacks, wall-clock analysis time and optional externally produced
//! reference cycles. It does not invoke OTAWA itself.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use anyhow::{Context, Result, bail};
use clap::Parser;
use elf2tdg::analysis::{AnalysisOptions, PathAnalysis, analyze_with_cfg};
use elf2tdg::board_profile::BoardProfile;
use elf2tdg::cfg::{CfgWcetInfo, CfgWcetRoot};
use elf2tdg::loader;
use serde::{Deserialize, Serialize};

const REPORT_SCHEMA_VERSION: u32 = 1;
const SUITE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Parser)]
#[command(
    name = "elf2tdg-bench",
    about = "Run an elf2tdg analysis benchmark suite and emit JSON/Markdown reports"
)]
struct Args {
    /// Benchmark suite (TOML).
    #[arg(long, default_value = "benchmarks/suite.toml")]
    suite: PathBuf,
    /// Optional JSON report output path.
    #[arg(long)]
    json: Option<PathBuf>,
    /// Optional Markdown report output path. The report is also printed.
    #[arg(long)]
    markdown: Option<PathBuf>,
    /// Run only cases whose ID contains this string.
    #[arg(long)]
    filter: Option<String>,
    /// Exit with failure if any analysis reports an error.
    #[arg(long)]
    fail_on_error: bool,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let args = Args::parse();
    let suite = Suite::load(&args.suite)?;
    let report = run_suite(&suite, args.filter.as_deref())?;
    if let Some(path) = &args.json {
        let json = serde_json::to_string_pretty(&report).context("serialize benchmark report")?;
        write_report(path, &json)?;
    }
    let markdown = render_markdown(&report, &suite);
    if let Some(path) = &args.markdown {
        write_report(path, &markdown)?;
    }
    print!("{markdown}");
    if args.fail_on_error && report.summary.analyses_error > 0 {
        bail!(
            "{} benchmark analysis run(s) failed",
            report.summary.analyses_error
        );
    }
    Ok(())
}

fn write_report(path: &Path, contents: &str) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("create report directory {}", parent.display()))?;
    }
    fs::write(path, contents).with_context(|| format!("write report {}", path.display()))
}

#[derive(Debug)]
struct Suite {
    path: PathBuf,
    description: Option<String>,
    cases: Vec<CaseConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SuiteFile {
    #[serde(default = "default_suite_schema_version")]
    schema_version: u32,
    #[serde(default)]
    description: Option<String>,
    #[serde(default, rename = "case")]
    cases: Vec<CaseConfigFile>,
}

const fn default_suite_schema_version() -> u32 {
    SUITE_SCHEMA_VERSION
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CaseConfigFile {
    id: String,
    elf: PathBuf,
    #[serde(default)]
    profile: Option<PathBuf>,
    #[serde(default)]
    cpu: Option<String>,
    #[serde(default)]
    frequency_hz: Option<u64>,
    #[serde(default)]
    flowfacts: Vec<PathBuf>,
    #[serde(default)]
    analyses: Vec<Backend>,
    #[serde(default)]
    require_safe: bool,
    #[serde(default)]
    reference: Option<ReferenceConfig>,
}

#[derive(Clone, Debug)]
struct CaseConfig {
    id: String,
    elf: PathBuf,
    profile: Option<PathBuf>,
    cpu: Option<String>,
    frequency_hz: Option<u64>,
    flowfacts: Vec<PathBuf>,
    analyses: Vec<Backend>,
    require_safe: bool,
    reference: Option<ReferenceConfig>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReferenceConfig {
    backend: Backend,
    source: String,
    #[serde(default)]
    root: Option<String>,
    cycles: f64,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "kebab-case")]
enum Backend {
    LongestPath,
    Ipet,
}

impl Backend {
    const fn label(self) -> &'static str {
        match self {
            Self::LongestPath => "longest-path",
            Self::Ipet => "ipet",
        }
    }

    const fn path_analysis(self) -> PathAnalysis {
        match self {
            Self::LongestPath => PathAnalysis::LongestPath,
            Self::Ipet => PathAnalysis::Ipet,
        }
    }
}

impl Suite {
    fn load(path: &Path) -> Result<Self> {
        let text = fs::read_to_string(path)
            .with_context(|| format!("read benchmark suite {}", path.display()))?;
        Self::parse(&text, path)
    }

    fn parse(text: &str, path: &Path) -> Result<Self> {
        let file: SuiteFile = toml::from_str(text)
            .with_context(|| format!("parse benchmark suite {}", path.display()))?;
        if file.schema_version != SUITE_SCHEMA_VERSION {
            bail!(
                "benchmark suite schema_version {} is unsupported; expected {SUITE_SCHEMA_VERSION}",
                file.schema_version
            );
        }
        if file.cases.is_empty() {
            bail!("benchmark suite has no [[case]] entries");
        }
        let base = path.parent().unwrap_or_else(|| Path::new("."));
        let mut ids = BTreeSet::new();
        let mut cases = Vec::with_capacity(file.cases.len());
        for raw in file.cases {
            if raw.id.trim().is_empty() {
                bail!("benchmark case id must not be empty");
            }
            if !ids.insert(raw.id.clone()) {
                bail!("benchmark case id {:?} is duplicated", raw.id);
            }
            let mut analyses = if raw.analyses.is_empty() {
                vec![Backend::LongestPath, Backend::Ipet]
            } else {
                raw.analyses
            };
            analyses.sort_unstable();
            analyses.dedup();
            if let Some(reference) = &raw.reference {
                if !analyses.contains(&reference.backend) {
                    bail!(
                        "benchmark case {:?} reference backend {:?} is not in its analyses",
                        raw.id,
                        reference.backend
                    );
                }
                if reference.source.trim().is_empty() {
                    bail!(
                        "benchmark case {:?} reference source must not be empty",
                        raw.id
                    );
                }
                if !reference.cycles.is_finite() || reference.cycles <= 0.0 {
                    bail!(
                        "benchmark case {:?} reference cycles must be finite and positive",
                        raw.id
                    );
                }
                if reference
                    .root
                    .as_deref()
                    .is_some_and(|root| root.trim().is_empty())
                {
                    bail!(
                        "benchmark case {:?} reference root must not be empty",
                        raw.id
                    );
                }
            }
            cases.push(CaseConfig {
                id: raw.id,
                elf: resolve_path(base, &raw.elf),
                profile: raw.profile.as_deref().map(|path| resolve_path(base, path)),
                cpu: raw.cpu,
                frequency_hz: raw.frequency_hz,
                flowfacts: raw
                    .flowfacts
                    .iter()
                    .map(|path| resolve_path(base, path))
                    .collect(),
                analyses,
                require_safe: raw.require_safe,
                reference: raw.reference,
            });
        }
        Ok(Self {
            path: path.to_path_buf(),
            description: file.description,
            cases,
        })
    }
}

fn resolve_path(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

#[derive(Debug, Serialize)]
struct Report {
    schema_version: u32,
    suite: String,
    description: Option<String>,
    cases: Vec<CaseReport>,
    summary: Summary,
}

#[derive(Debug, Default, Serialize)]
struct Summary {
    cases: usize,
    analyses: usize,
    analyses_ok: usize,
    analyses_error: usize,
    analyses_without_wcet: usize,
    references: usize,
    references_without_measured_cycles: usize,
    total_elapsed_ms: f64,
}

#[derive(Debug, Serialize)]
struct CaseReport {
    id: String,
    elf: String,
    profile: Option<String>,
    analyses: Vec<AnalysisReport>,
}

#[derive(Debug, Serialize)]
struct AnalysisReport {
    backend: Backend,
    status: &'static str,
    elapsed_ms: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    wcet: Option<WcetMetrics>,
    #[serde(skip_serializing_if = "Option::is_none")]
    timing: Option<TimingMetrics>,
    #[serde(skip_serializing_if = "Option::is_none")]
    models: Option<ModelMetrics>,
    diagnostics: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    safe_ok: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reference: Option<ReferenceComparison>,
}

#[derive(Debug, Serialize)]
struct TimingMetrics {
    model: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    determinism: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    frequency_hz: Option<u64>,
}

#[derive(Debug, Serialize)]
struct WcetMetrics {
    model: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    solver: Option<String>,
    functions_analyzed: u32,
    functions_partial: u32,
    functions_unbounded: u32,
    functions_unknown: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_root_cycles: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_root: Option<String>,
    roots: Vec<RootMetric>,
}

#[derive(Debug, Serialize)]
struct RootMetric {
    function: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    kind: String,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    cycles: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    time_ns: Option<f64>,
}

#[derive(Debug, Default, Serialize)]
struct ModelMetrics {
    ipet_functions: u32,
    solvers: BTreeMap<String, u32>,
    solver_statuses: BTreeMap<String, u32>,
    cache_models: BTreeMap<String, u32>,
    pipeline_models: BTreeMap<String, u32>,
    branch_models: BTreeMap<String, u32>,
    btb_models: BTreeMap<String, u32>,
    ras_models: BTreeMap<String, u32>,
    partitioning_models: BTreeMap<String, u32>,
}

#[derive(Debug, Serialize)]
struct ReferenceComparison {
    backend: Backend,
    source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    requested_root: Option<String>,
    reference_cycles: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    measured_root: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    measured_cycles: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    delta_cycles: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ratio: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<String>,
}

fn run_suite(suite: &Suite, filter: Option<&str>) -> Result<Report> {
    let selected: Vec<&CaseConfig> = suite
        .cases
        .iter()
        .filter(|case| filter.is_none_or(|filter| case.id.contains(filter)))
        .collect();
    if selected.is_empty() {
        bail!("no benchmark cases matched the filter");
    }
    let mut report = Report {
        schema_version: REPORT_SCHEMA_VERSION,
        suite: suite.path.display().to_string(),
        description: suite.description.clone(),
        cases: Vec::with_capacity(selected.len()),
        summary: Summary::default(),
    };
    for case in selected {
        let case_report = run_case(case);
        update_summary(&mut report.summary, &case_report);
        report.cases.push(case_report);
    }
    Ok(report)
}

fn update_summary(summary: &mut Summary, case: &CaseReport) {
    summary.cases = summary.cases.saturating_add(1);
    for analysis in &case.analyses {
        summary.analyses = summary.analyses.saturating_add(1);
        summary.total_elapsed_ms += analysis.elapsed_ms;
        match analysis.status {
            "ok" => summary.analyses_ok = summary.analyses_ok.saturating_add(1),
            "ok-without-wcet" => {
                summary.analyses_ok = summary.analyses_ok.saturating_add(1);
                summary.analyses_without_wcet = summary.analyses_without_wcet.saturating_add(1);
            }
            _ => summary.analyses_error = summary.analyses_error.saturating_add(1),
        }
        if let Some(reference) = &analysis.reference {
            summary.references = summary.references.saturating_add(1);
            if reference.measured_cycles.is_none() {
                summary.references_without_measured_cycles =
                    summary.references_without_measured_cycles.saturating_add(1);
            }
        }
    }
}

fn run_case(case: &CaseConfig) -> CaseReport {
    let image = loader::load(&case.elf);
    let profile = case.profile.as_deref().map(BoardProfile::load).transpose();
    let setup_error = match (image, profile) {
        (Ok(image), Ok(profile)) => {
            return CaseReport {
                id: case.id.clone(),
                elf: case.elf.display().to_string(),
                profile: case.profile.as_ref().map(|path| path.display().to_string()),
                analyses: case
                    .analyses
                    .iter()
                    .map(|backend| run_analysis(case, *backend, &image, profile.as_ref()))
                    .collect(),
            };
        }
        (Err(error), _) => Some(format!("load ELF {}: {error}", case.elf.display())),
        (_, Err(error)) => Some(format!("load board profile: {error:#}")),
    };
    let message = setup_error.unwrap_or_else(|| "benchmark setup failed".to_owned());
    CaseReport {
        id: case.id.clone(),
        elf: case.elf.display().to_string(),
        profile: case.profile.as_ref().map(|path| path.display().to_string()),
        analyses: case
            .analyses
            .iter()
            .map(|backend| AnalysisReport {
                backend: *backend,
                status: "error",
                elapsed_ms: 0.0,
                error: Some(message.clone()),
                wcet: None,
                timing: None,
                models: None,
                diagnostics: 0,
                safe_ok: None,
                reference: None,
            })
            .collect(),
    }
}

fn run_analysis(
    case: &CaseConfig,
    backend: Backend,
    image: &elf2tdg::loader::Image,
    profile: Option<&BoardProfile>,
) -> AnalysisReport {
    let options = AnalysisOptions {
        cpu: case.cpu.clone(),
        board_profile: profile.cloned(),
        frequency_hz: case.frequency_hz,
        path_analysis: backend.path_analysis(),
        require_safe: case.require_safe,
        flow_fact_paths: case.flowfacts.clone(),
        ..AnalysisOptions::default()
    };
    let started = Instant::now();
    let result = analyze_with_cfg(image, &options);
    let elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;
    match result {
        Ok(output) => {
            let program = output.cfg;
            let timing = program.timing.as_ref().and_then(|timing| {
                timing.models.first().map(|model| TimingMetrics {
                    model: model.id.as_str().to_owned(),
                    determinism: enum_label(&model.determinism),
                    frequency_hz: program.wcet.as_ref().and_then(|wcet| wcet.frequency_hz),
                })
            });
            let models = Some(collect_models(&program));
            let wcet = program.wcet.as_ref().map(summarize_wcet);
            let status = if wcet.is_some() {
                "ok"
            } else {
                "ok-without-wcet"
            };
            let reference = case
                .reference
                .as_ref()
                .filter(|reference| reference.backend == backend)
                .map(|reference| compare_reference(reference, wcet.as_ref()));
            AnalysisReport {
                backend,
                status,
                elapsed_ms,
                error: None,
                wcet,
                timing,
                models,
                diagnostics: program.diagnostics.len(),
                safe_ok: case.require_safe.then_some(true),
                reference,
            }
        }
        Err(error) => AnalysisReport {
            backend,
            status: "error",
            elapsed_ms,
            error: Some(error.to_string()),
            wcet: None,
            timing: None,
            models: None,
            diagnostics: 0,
            safe_ok: case.require_safe.then_some(false),
            reference: None,
        },
    }
}

fn summarize_wcet(wcet: &CfgWcetInfo) -> WcetMetrics {
    let roots: Vec<RootMetric> = wcet.roots.iter().map(summarize_root).collect();
    let max_root = roots
        .iter()
        .filter_map(|root| root.cycles.map(|cycles| (cycles, root_label(root))))
        .max_by(|left, right| left.0.total_cmp(&right.0));
    WcetMetrics {
        model: wcet.model.clone(),
        solver: wcet.solver.clone(),
        functions_analyzed: wcet.functions_analyzed,
        functions_partial: wcet.functions_partial,
        functions_unbounded: wcet.functions_unbounded,
        functions_unknown: wcet.functions_unknown,
        max_root_cycles: max_root.as_ref().map(|(cycles, _)| *cycles),
        max_root: max_root.map(|(_, label)| label),
        roots,
    }
}

fn summarize_root(root: &CfgWcetRoot) -> RootMetric {
    RootMetric {
        function: root.function.as_str().to_owned(),
        name: root.name.clone(),
        kind: enum_label(&root.kind).unwrap_or_else(|| "unknown".to_owned()),
        status: enum_label(&root.status).unwrap_or_else(|| "unknown".to_owned()),
        cycles: root.cycles,
        time_ns: root.time_ns,
    }
}

fn enum_label<T: Serialize>(value: &T) -> Option<String> {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
}

fn root_label(root: &RootMetric) -> String {
    root.name.clone().unwrap_or_else(|| root.function.clone())
}

fn collect_models(program: &elf2tdg::cfg::ProgramCfg) -> ModelMetrics {
    let mut metrics = ModelMetrics::default();
    for function in &program.functions {
        let Some(solution) = function.wcet.as_ref().and_then(|wcet| wcet.ipet.as_ref()) else {
            continue;
        };
        metrics.ipet_functions = metrics.ipet_functions.saturating_add(1);
        increment(&mut metrics.solvers, &solution.solver);
        increment(&mut metrics.solver_statuses, &solution.status);
        increment_optional(&mut metrics.cache_models, solution.cache_model.as_deref());
        increment_optional(
            &mut metrics.pipeline_models,
            solution.pipeline_model.as_deref(),
        );
        increment_optional(&mut metrics.branch_models, solution.branch_model.as_deref());
        increment_optional(&mut metrics.btb_models, solution.btb_model.as_deref());
        increment_optional(&mut metrics.ras_models, solution.ras_model.as_deref());
        if let Some(partitioning) = &solution.partitioning {
            increment(&mut metrics.partitioning_models, &partitioning.model);
        }
    }
    metrics
}

fn increment(map: &mut BTreeMap<String, u32>, value: &str) {
    *map.entry(value.to_owned()).or_default() += 1;
}

fn increment_optional(map: &mut BTreeMap<String, u32>, value: Option<&str>) {
    if let Some(value) = value {
        increment(map, value);
    }
}

fn compare_reference(
    reference: &ReferenceConfig,
    wcet: Option<&WcetMetrics>,
) -> ReferenceComparison {
    let roots = wcet.map(|wcet| wcet.roots.as_slice()).unwrap_or_default();
    let selected = match reference.root.as_deref() {
        Some(requested) => roots
            .iter()
            .find(|root| root.name.as_deref() == Some(requested) || root.function == requested),
        None => roots
            .iter()
            .filter(|root| root.cycles.is_some())
            .max_by(|left, right| {
                left.cycles
                    .unwrap_or_default()
                    .total_cmp(&right.cycles.unwrap_or_default())
            }),
    };
    let measured_cycles = selected.and_then(|root| root.cycles);
    let note = if wcet.is_none() {
        Some("no WCET metadata".to_owned())
    } else if selected.is_none() {
        if reference.root.is_some() {
            Some("requested root was not found".to_owned())
        } else {
            Some("no finite root cycles".to_owned())
        }
    } else if measured_cycles.is_none() {
        Some("selected root has no finite cycle result".to_owned())
    } else {
        None
    };
    ReferenceComparison {
        backend: reference.backend,
        source: reference.source.clone(),
        requested_root: reference.root.clone(),
        reference_cycles: reference.cycles,
        measured_root: selected.map(root_label),
        measured_cycles,
        delta_cycles: measured_cycles.map(|cycles| cycles - reference.cycles),
        ratio: measured_cycles.map(|cycles| cycles / reference.cycles),
        note,
    }
}

fn render_markdown(report: &Report, suite: &Suite) -> String {
    let mut output = String::new();
    output.push_str("# elf2tdg benchmark report\n\n");
    if let Some(description) = &suite.description {
        output.push_str(description);
        output.push_str("\n\n");
    }
    let _ = write!(
        output,
        "- suite: `{}`\n- cases: {}\n- analyses: {} ok, {} error, {} without WCET\n- wall time: {:.3} ms\n- references: {} ({} without measured cycles)\n\n",
        suite.path.display(),
        report.summary.cases,
        report.summary.analyses_ok,
        report.summary.analyses_error,
        report.summary.analyses_without_wcet,
        report.summary.total_elapsed_ms,
        report.summary.references,
        report.summary.references_without_measured_cycles
    );
    output.push_str("| Case | Backend | Status | Max root | Cycles | Time ms | Determinism | Models | Reference | Note |\n");
    output.push_str("|---|---|---|---|---:|---:|---|---|---|---|\n");
    for case in &report.cases {
        for analysis in &case.analyses {
            let max_root = analysis
                .wcet
                .as_ref()
                .and_then(|wcet| wcet.max_root.as_deref())
                .unwrap_or("-");
            let cycles = analysis
                .wcet
                .as_ref()
                .and_then(|wcet| wcet.max_root_cycles)
                .map_or_else(|| "-".to_owned(), |cycles| format!("{cycles:.3}"));
            let determinism = analysis
                .timing
                .as_ref()
                .and_then(|timing| timing.determinism.as_deref())
                .unwrap_or("-");
            let models = analysis
                .models
                .as_ref()
                .map_or_else(|| "-".to_owned(), model_summary);
            let reference = analysis
                .reference
                .as_ref()
                .map_or_else(|| "-".to_owned(), reference_summary);
            let note = analysis
                .error
                .as_deref()
                .or_else(|| analysis.reference.as_ref().and_then(|r| r.note.as_deref()))
                .unwrap_or("-");
            let _ = writeln!(
                output,
                "| {} | {} | {} | {} | {} | {:.3} | {} | {} | {} | {} |",
                escape_markdown(&case.id),
                analysis.backend.label(),
                analysis.status,
                escape_markdown(max_root),
                cycles,
                analysis.elapsed_ms,
                escape_markdown(determinism),
                escape_markdown(&truncate(&models, 120)),
                escape_markdown(&reference),
                escape_markdown(&truncate(note, 120))
            );
        }
    }
    output
}

fn model_summary(models: &ModelMetrics) -> String {
    let mut parts = Vec::new();
    if models.ipet_functions > 0 {
        parts.push(format!("ipet={}", models.ipet_functions));
    }
    for (label, map) in [
        ("cache", &models.cache_models),
        ("pipeline", &models.pipeline_models),
        ("branch", &models.branch_models),
        ("btb", &models.btb_models),
        ("ras", &models.ras_models),
        ("partition", &models.partitioning_models),
    ] {
        if map.is_empty() {
            continue;
        }
        let entries = map
            .iter()
            .map(|(name, count)| format!("{name}={count}"))
            .collect::<Vec<_>>()
            .join(",");
        parts.push(format!("{label}:{entries}"));
    }
    if parts.is_empty() {
        "-".to_owned()
    } else {
        parts.join(" ")
    }
}

fn reference_summary(reference: &ReferenceComparison) -> String {
    let Some(measured) = reference.measured_cycles else {
        return format!(
            "{} {}: no measured cycles",
            reference.source, reference.reference_cycles
        );
    };
    let ratio = reference.ratio.unwrap_or_default();
    let delta = reference.delta_cycles.unwrap_or_default();
    format!(
        "{} {:.3} -> {:.3} ({ratio:.3}x, {delta:+.3})",
        reference.source, reference.reference_cycles, measured
    )
}

fn truncate(value: &str, limit: usize) -> String {
    if value.chars().count() <= limit {
        return value.to_owned();
    }
    let mut truncated: String = value.chars().take(limit.saturating_sub(3)).collect();
    truncated.push_str("...");
    truncated
}

fn escape_markdown(value: &str) -> String {
    value.replace('|', "\\|").replace('\n', " ")
}

#[cfg(test)]
mod tests {
    use super::{Backend, ReferenceConfig, RootMetric, Suite, compare_reference, escape_markdown};
    use std::path::Path;

    #[test]
    fn parses_defaults_and_resolves_relative_paths() {
        let suite = Suite::parse(
            r#"
schema_version = 1
description = "test"

[[case]]
id = "one"
elf = "a.elf"
profile = "p.toml"
"#,
            Path::new("/tmp/suite.toml"),
        )
        .expect("suite");
        assert_eq!(suite.cases.len(), 1);
        let case = &suite.cases[0];
        assert_eq!(case.analyses, vec![Backend::LongestPath, Backend::Ipet]);
        assert!(case.elf.ends_with("a.elf"));
        assert!(
            case.profile
                .as_ref()
                .is_some_and(|path| path.ends_with("p.toml"))
        );
    }

    #[test]
    fn rejects_duplicate_case_ids() {
        let error = Suite::parse(
            r#"
schema_version = 1

[[case]]
id = "same"
elf = "a.elf"

[[case]]
id = "same"
elf = "b.elf"
"#,
            Path::new("suite.toml"),
        )
        .expect_err("duplicate IDs");
        assert!(error.to_string().contains("duplicated"));
    }

    #[test]
    fn reference_selects_a_named_root() {
        let reference = ReferenceConfig {
            backend: Backend::Ipet,
            source: "otawa".to_owned(),
            root: Some("main".to_owned()),
            cycles: 10.0,
        };
        let roots = vec![
            RootMetric {
                function: "fn:0x1000".to_owned(),
                name: Some("main".to_owned()),
                kind: "main".to_owned(),
                status: "bounded".to_owned(),
                cycles: Some(12.0),
                time_ns: None,
            },
            RootMetric {
                function: "fn:0x2000".to_owned(),
                name: Some("isr".to_owned()),
                kind: "isr".to_owned(),
                status: "bounded".to_owned(),
                cycles: Some(3.0),
                time_ns: None,
            },
        ];
        let wcet = super::WcetMetrics {
            model: "cfg-ipet".to_owned(),
            solver: None,
            functions_analyzed: 2,
            functions_partial: 0,
            functions_unbounded: 0,
            functions_unknown: 0,
            max_root_cycles: Some(12.0),
            max_root: Some("main".to_owned()),
            roots,
        };
        let comparison = compare_reference(&reference, Some(&wcet));
        assert_eq!(comparison.measured_cycles, Some(12.0));
        assert_eq!(comparison.delta_cycles, Some(2.0));
        assert_eq!(comparison.ratio, Some(1.2));
    }

    #[test]
    fn markdown_escapes_table_delimiters() {
        assert_eq!(escape_markdown("a|b\nc"), "a\\|b c");
    }
}
