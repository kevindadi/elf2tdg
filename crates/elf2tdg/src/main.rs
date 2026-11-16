#![allow(missing_docs)]

use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use elf2tdg::analysis::{AnalysisOptions, AnalysisOutput, analyze_with_cfg};
use elf2tdg::cfg::{self, CfgFunction, ProgramCfg};
use elf2tdg::elf_view;
use elf2tdg::loader;
use elf2tdg::output::{self, GraphOptions};
use elf2tdg::timing::parse_frequency;
use elf2tdg_schema::Tdg;

#[derive(Debug, Parser)]
#[allow(clippy::struct_excessive_bools)]
#[command(
    name = "elf2tdg",
    version,
    about = "Extract ELF layouts, per-function CFGs and Task Dependency Graphs from ELF images"
)]
struct Cli {
    /// Input ELF image (keep symbols in the analysis build).
    input: PathBuf,

    /// CPU/timing model, e.g. cortex-m4, riscv32, aarch64 or x86-64.
    /// Cortex-M/RISC-V are auto-detected; generic AArch64/x86-64 are statistical
    /// and must be requested explicitly.
    #[arg(long)]
    cpu: Option<String>,

    /// Core frequency, e.g. 168MHz or 168000000. Enables wall-clock times.
    #[arg(long)]
    freq: Option<String>,

    /// Output format. Defaults to json; --view elf defaults to mermaid.
    #[arg(long, value_enum)]
    format: Option<OutputFormat>,

    /// Graph view: the final TDG, the intermediate per-function CFG, or the
    /// loaded ELF layout.
    #[arg(long, value_enum, default_value_t = View::Tdg)]
    view: View,

    /// Select one function for CFG output by name, symbol, or 0x address.
    #[arg(long, conflicts_with = "all_functions")]
    function: Option<String>,

    /// Export CFGs for every analyzed function, including functions not
    /// reachable from main.
    #[arg(long, conflicts_with = "function")]
    all_functions: bool,

    /// Export only functions reachable from ROOT through calls and task
    /// creation. This is the default CFG scope, with ROOT set to main.
    #[arg(
        long,
        value_name = "NAME|0xADDR",
        conflicts_with_all = ["function", "all_functions"]
    )]
    reachable_from: Option<String>,

    /// Omit concrete instructions from CFG JSON and DOT/Mermaid labels.
    #[arg(long)]
    no_cfg_instructions: bool,

    /// Graph projection for DOT/Mermaid output.
    #[arg(long, value_enum, default_value_t = ProjectionArg::Full)]
    projection: ProjectionArg,

    /// Add a node/edge legend to DOT/Mermaid output.
    #[arg(long)]
    legend: bool,

    /// Output file. Use '-' or omit for stdout.
    #[arg(long, short)]
    output: Option<PathBuf>,

    /// Include per-instruction disassembly and cycle costs (requires a timing model).
    #[arg(long)]
    instructions: bool,

    /// Maximum diagnostics retained in the TDG (default 500).
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
    Dot,
    Mermaid,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum ProjectionArg {
    Full,
    Concurrency,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum View {
    Tdg,
    Cfg,
    #[value(alias = "loader")]
    Elf,
}

impl From<ProjectionArg> for output::Projection {
    fn from(value: ProjectionArg) -> Self {
        match value {
            ProjectionArg::Full => Self::Full,
            ProjectionArg::Concurrency => Self::Concurrency,
        }
    }
}

fn select_cfg_functions<'a>(
    cli: &Cli,
    program: &'a ProgramCfg,
    tdg: &Tdg,
) -> std::result::Result<Vec<&'a CfgFunction>, String> {
    if let Some(selector) = cli.function.as_deref() {
        program.select(Some(selector))
    } else if cli.all_functions {
        Ok(program.functions.iter().collect())
    } else {
        program.reachable_from(tdg, cli.reachable_from.as_deref().unwrap_or("main"))
    }
}

fn render_view(
    cli: &Cli,
    analysis: &AnalysisOutput,
    cfg_functions: &[&CfgFunction],
    format: OutputFormat,
) -> Result<String> {
    let tdg = &analysis.tdg;
    let graph_options = GraphOptions {
        projection: cli.projection.into(),
        legend: cli.legend,
    };
    let include_cfg_instructions = !cli.no_cfg_instructions;
    let rendered = match cli.view {
        View::Tdg => match format {
            OutputFormat::Json => output::render_json(tdg)?,
            OutputFormat::Dot => output::render_dot_with(tdg, graph_options),
            OutputFormat::Mermaid => output::render_mermaid_with(tdg, graph_options),
        },
        View::Cfg => match format {
            OutputFormat::Json => cfg::render_json_selected(
                &analysis.cfg,
                tdg,
                cfg_functions,
                include_cfg_instructions,
            )
            .map_err(anyhow::Error::msg)?,
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

fn main() -> Result<()> {
    let cli = Cli::parse();

    let frequency_hz = cli
        .freq
        .as_deref()
        .map(parse_frequency)
        .transpose()
        .map_err(anyhow::Error::msg)?;

    let format = cli.format.unwrap_or(match cli.view {
        View::Elf => OutputFormat::Mermaid,
        View::Tdg | View::Cfg => OutputFormat::Json,
    });
    let image = loader::load(&cli.input)
        .with_context(|| format!("failed to load {}", cli.input.display()))?;
    if cli.view != View::Cfg
        && (cli.function.is_some()
            || cli.all_functions
            || cli.reachable_from.is_some()
            || cli.no_cfg_instructions)
    {
        anyhow::bail!(
            "--function, --all-functions, --reachable-from and --no-cfg-instructions are only supported with --view cfg"
        );
    }
    if cli.view == View::Elf {
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
        frequency_hz,
        include_instructions: cli.instructions,
        max_diagnostics: cli.max_diagnostics,
        ..AnalysisOptions::default()
    };
    let analysis = analyze_with_cfg(&image, &options).context("analysis failed")?;
    let tdg = &analysis.tdg;
    let cfg_functions = if cli.view == View::Cfg {
        select_cfg_functions(&cli, &analysis.cfg, tdg).map_err(anyhow::Error::msg)?
    } else {
        Vec::new()
    };

    let rendered = render_view(&cli, &analysis, &cfg_functions, format)?;
    write_rendered(&cli, &rendered)?;

    if cli.verbose {
        let destination = cli
            .output
            .as_ref()
            .map_or_else(|| "stdout".to_owned(), |path| path.display().to_string());
        if cli.view == View::Cfg {
            let blocks: usize = cfg_functions
                .iter()
                .map(|function| function.cfg.blocks_by_address.len())
                .sum();
            eprintln!(
                "{} functions, {} CFG blocks, {} diagnostics -> {destination}",
                cfg_functions.len(),
                blocks,
                tdg.diagnostics.len()
            );
        } else {
            eprintln!(
                "{} functions, {} contexts, {} edges, {} diagnostics -> {destination}",
                tdg.functions.len(),
                tdg.contexts.len(),
                tdg.edges.len(),
                tdg.diagnostics.len()
            );
        }
    }
    Ok(())
}
