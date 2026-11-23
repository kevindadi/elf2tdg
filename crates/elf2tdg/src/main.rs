#![allow(missing_docs)]

use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use elf2tdg::analysis::{AnalysisOptions, AnalysisOutput, PathAnalysis, analyze_with_cfg};
use elf2tdg::board_profile::BoardProfile;
use elf2tdg::cfg::{self, CfgFunction, ProgramCfg};
use elf2tdg::elf_view;
use elf2tdg::loader::{self, Image};
use elf2tdg::passes;
use elf2tdg::text_report;
use elf2tdg::timing::parse_frequency;

#[derive(Debug, Parser)]
#[allow(clippy::struct_excessive_bools)]
#[command(
    name = "elf2tdg",
    version,
    about = "Extract ELF layouts and program control-flow graphs from ELF images"
)]
struct Cli {
    /// Input ELF image (keep symbols in the analysis build). Required unless
    /// --list-passes is used.
    input: Option<PathBuf>,

    /// CPU/timing model, e.g. cortex-m4, riscv32, riscv64-bounded,
    /// aarch64-bounded or x86-64. Cortex-M and generic RISC-V are auto-detected;
    /// statistical AArch64/x86-64 and bounded AArch64/RISC-V models must be
    /// requested explicitly.
    #[arg(long)]
    cpu: Option<String>,

    /// Board timing profile (TOML or JSON). Supplies the CPU model, clocks,
    /// memory fetch costs and instruction-cost overrides.
    #[arg(long, value_name = "PATH")]
    board_profile: Option<PathBuf>,

    /// External F4 `.ff` or FFX flow-fact file; may be repeated. Requires a
    /// board profile with a [wcet] section.
    #[arg(long, value_name = "PATH", action = clap::ArgAction::Append)]
    flowfacts: Vec<PathBuf>,

    /// List the compile-time analysis pass plan and exit. If --board-profile is
    /// supplied, optional passes enabled by that profile are marked as such.
    #[arg(long)]
    list_passes: bool,

    /// Core frequency, e.g. 168MHz or 168000000. Enables wall-clock times and
    /// overrides the board profile's core clock.
    #[arg(long)]
    freq: Option<String>,

    /// WCET path-analysis backend when the board profile enables [wcet].
    #[arg(long, value_enum, default_value = "longest-path")]
    path_analysis: PathAnalysisArg,

    /// Fail unless every execution root has a bounded WCET result. Use this
    /// for certification-style runs; partial and unbounded results are rejected.
    #[arg(long)]
    require_safe: bool,

    /// Output format. Defaults to json; --view elf defaults to mermaid.
    #[arg(long, value_enum)]
    format: Option<OutputFormat>,

    /// Graph view: the program CFG or the loaded ELF layout.
    #[arg(long, value_enum, default_value_t = View::Cfg)]
    view: View,

    /// Select one function for CFG output by name, symbol, task alias, or 0x
    /// address. Task names map to their task entry function.
    #[arg(long, conflicts_with = "all_functions")]
    function: Option<String>,

    /// Export CFGs for every analyzed function, including functions not
    /// reachable from any execution root.
    #[arg(long, conflicts_with = "function")]
    all_functions: bool,

    /// Export only functions reachable from ROOT through calls and spawn
    /// annotations. ROOT may be a function name, task alias, symbol, or 0x
    /// address. Without this flag the CFG uses all asynchronous execution
    /// roots: main, startup, ISR vectors, tasks and callbacks.
    #[arg(
        long,
        value_name = "NAME|0xADDR",
        conflicts_with_all = ["function", "all_functions"]
    )]
    reachable_from: Option<String>,

    /// Do not stop call-graph expansion at panic/format/compiler-builtins and
    /// drop-glue boundaries in CFG reachability.
    #[arg(long)]
    no_prune_runtime: bool,

    /// Omit concrete instructions from CFG JSON, text and DOT/Mermaid labels.
    #[arg(long)]
    no_cfg_instructions: bool,

    /// Output file. Use '-' or omit for stdout.
    #[arg(long, short)]
    output: Option<PathBuf>,

    /// Maximum diagnostics retained in the CFG (default 500).
    #[arg(long, default_value_t = 500)]
    max_diagnostics: usize,

    /// Maximum instructions rendered per executable section by --view elf
    /// (0 = unlimited).
    #[arg(
        long,
        value_name = "N",
        default_value_t = elf_view::DEFAULT_MAX_INSTRUCTIONS_PER_SECTION
    )]
    elf_max_insns: usize,

    /// Print a summary and diagnostics count to stderr.
    #[arg(long)]
    verbose: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum OutputFormat {
    Json,
    Text,
    Dot,
    Mermaid,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum PathAnalysisArg {
    LongestPath,
    Ipet,
}

impl From<PathAnalysisArg> for PathAnalysis {
    fn from(value: PathAnalysisArg) -> Self {
        match value {
            PathAnalysisArg::LongestPath => Self::LongestPath,
            PathAnalysisArg::Ipet => Self::Ipet,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum View {
    Cfg,
    #[value(alias = "loader")]
    Elf,
}

fn select_cfg_functions<'a>(
    cli: &Cli,
    program: &'a ProgramCfg,
    image: &Image,
) -> std::result::Result<Vec<&'a CfgFunction>, String> {
    if let Some(selector) = cli.function.as_deref() {
        program.select(Some(selector))
    } else if cli.all_functions {
        Ok(program.functions.iter().collect())
    } else if let Some(root) = cli.reachable_from.as_deref() {
        program.reachable_from_with_pruning(root, !cli.no_prune_runtime)
    } else {
        Ok(program.reachable_from_system(image, !cli.no_prune_runtime))
    }
}

fn render_view(
    cli: &Cli,
    analysis: &AnalysisOutput,
    cfg_functions: &[&CfgFunction],
    format: OutputFormat,
) -> Result<String> {
    let include_cfg_instructions = !cli.no_cfg_instructions;
    let rendered = match cli.view {
        View::Cfg => match format {
            OutputFormat::Json => {
                cfg::render_json_selected(&analysis.cfg, cfg_functions, include_cfg_instructions)
                    .map_err(anyhow::Error::msg)?
            }
            OutputFormat::Text => text_report::render_text_selected(
                &analysis.cfg,
                cfg_functions,
                include_cfg_instructions,
            ),
            OutputFormat::Dot => {
                cfg::render_dot_selected(&analysis.cfg, cfg_functions, include_cfg_instructions)
            }
            OutputFormat::Mermaid => {
                cfg::render_mermaid_selected(&analysis.cfg, cfg_functions, include_cfg_instructions)
            }
        },
        View::Elf => unreachable!("ELF view is rendered before analysis"),
    };
    Ok(rendered)
}

fn write_rendered(cli: &Cli, rendered: &str) -> Result<()> {
    let to_stdout = cli
        .output
        .as_deref()
        .is_none_or(|path| path == Path::new("-"));
    if to_stdout {
        let mut stdout = std::io::stdout().lock();
        stdout
            .write_all(rendered.as_bytes())
            .context("failed to write stdout")?;
        if !rendered.ends_with('\n') {
            stdout.write_all(b"\n").context("failed to write stdout")?;
        }
    } else if let Some(path) = &cli.output {
        std::fs::write(path, rendered.as_bytes())
            .with_context(|| format!("failed to write {}", path.display()))?;
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn main() -> Result<()> {
    let cli = Cli::parse();

    let board_profile = cli
        .board_profile
        .as_deref()
        .map(BoardProfile::load)
        .transpose()
        .context("failed to load board profile")?;

    let path_analysis: PathAnalysis = cli.path_analysis.into();
    if cli.list_passes {
        let rendered = passes::render_plan(&passes::plan(board_profile.as_ref(), path_analysis));
        write_rendered(&cli, &rendered)?;
        return Ok(());
    }

    let Some(input) = cli.input.as_deref() else {
        anyhow::bail!("an input ELF is required unless --list-passes is used");
    };
    let frequency_hz = cli
        .freq
        .as_deref()
        .map(parse_frequency)
        .transpose()
        .map_err(anyhow::Error::msg)?;
    let format = cli.format.unwrap_or(match cli.view {
        View::Elf => OutputFormat::Mermaid,
        View::Cfg => OutputFormat::Json,
    });
    let image =
        loader::load(input).with_context(|| format!("failed to load {}", input.display()))?;
    if cli.view != View::Cfg
        && (cli.function.is_some()
            || cli.all_functions
            || cli.reachable_from.is_some()
            || cli.no_prune_runtime
            || cli.no_cfg_instructions
            || cli.require_safe
            || !cli.flowfacts.is_empty())
    {
        anyhow::bail!(
            "--function, --all-functions, --reachable-from, --no-prune-runtime, --no-cfg-instructions, --require-safe and --flowfacts are only supported with --view cfg"
        );
    }
    if cli.view == View::Elf {
        if board_profile.is_some() {
            anyhow::bail!("--board-profile is only supported for CFG analysis");
        }
        if format != OutputFormat::Mermaid {
            anyhow::bail!("--view elf currently supports only --format mermaid");
        }
        let rendered =
            elf_view::render_mermaid(&image, cli.elf_max_insns).map_err(anyhow::Error::msg)?;
        write_rendered(&cli, &rendered)?;
        if cli.verbose {
            let destination = cli
                .output
                .as_ref()
                .map_or_else(|| "stdout".to_owned(), |path| path.display().to_string());
            eprintln!(
                "{} segments, {} sections, {} symbols -> {destination}",
                image.segments.len(),
                image
                    .sections
                    .iter()
                    .filter(|section| section.alloc)
                    .count(),
                image.symbols.len()
            );
        }
        return Ok(());
    }
    let options = AnalysisOptions {
        cpu: cli.cpu.clone(),
        board_profile,
        frequency_hz,
        max_diagnostics: cli.max_diagnostics,
        path_analysis,
        require_safe: cli.require_safe,
        flow_fact_paths: cli.flowfacts.clone(),
        ..AnalysisOptions::default()
    };
    let analysis = analyze_with_cfg(&image, &options).context("analysis failed")?;
    let cfg_functions =
        select_cfg_functions(&cli, &analysis.cfg, &image).map_err(anyhow::Error::msg)?;

    let rendered = render_view(&cli, &analysis, &cfg_functions, format)?;
    write_rendered(&cli, &rendered)?;

    if cli.verbose {
        let destination = cli
            .output
            .as_ref()
            .map_or_else(|| "stdout".to_owned(), |path| path.display().to_string());
        let blocks: usize = cfg_functions
            .iter()
            .map(|function| function.cfg.blocks_by_address.len())
            .sum();
        let selected: std::collections::BTreeSet<_> =
            cfg_functions.iter().map(|function| &function.id).collect();
        let scoped_diagnostics = analysis
            .cfg
            .diagnostics
            .iter()
            .filter(|diagnostic| {
                diagnostic
                    .function
                    .as_ref()
                    .is_none_or(|function| selected.contains(function))
            })
            .count();
        let omitted = analysis
            .cfg
            .diagnostics
            .len()
            .saturating_sub(scoped_diagnostics);
        eprintln!(
            "{} functions, {} CFG blocks, {} diagnostics ({} image-wide diagnostics omitted) -> {destination}",
            cfg_functions.len(),
            blocks,
            scoped_diagnostics,
            omitted
        );
    }
    Ok(())
}
