#![allow(missing_docs)]

use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use elf2tdg::analysis::{AnalysisOptions, analyze};
use elf2tdg::loader;
use elf2tdg::output::{self, GraphOptions};
use elf2tdg::timing::parse_frequency;

#[derive(Debug, Parser)]
#[command(
    name = "elf2tdg",
    version,
    about = "Extract a Task Dependency Graph from an embedded ELF image"
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

    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Json)]
    format: OutputFormat,

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

impl From<ProjectionArg> for output::Projection {
    fn from(value: ProjectionArg) -> Self {
        match value {
            ProjectionArg::Full => Self::Full,
            ProjectionArg::Concurrency => Self::Concurrency,
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let frequency_hz = cli
        .freq
        .as_deref()
        .map(parse_frequency)
        .transpose()
        .map_err(anyhow::Error::msg)?;

    let image = loader::load(&cli.input)
        .with_context(|| format!("failed to load {}", cli.input.display()))?;
    let options = AnalysisOptions {
        cpu: cli.cpu,
        frequency_hz,
        include_instructions: cli.instructions,
        max_diagnostics: cli.max_diagnostics,
        ..AnalysisOptions::default()
    };
    let tdg = analyze(&image, &options).context("analysis failed")?;

    let graph_options = GraphOptions {
        projection: cli.projection.into(),
        legend: cli.legend,
    };
    let rendered = match cli.format {
        OutputFormat::Json => output::render_json(&tdg)?,
        OutputFormat::Dot => output::render_dot_with(&tdg, graph_options),
        OutputFormat::Mermaid => output::render_mermaid_with(&tdg, graph_options),
    };

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

    if cli.verbose {
        eprintln!(
            "{} functions, {} contexts, {} edges, {} diagnostics -> {}",
            tdg.functions.len(),
            tdg.contexts.len(),
            tdg.edges.len(),
            tdg.diagnostics.len(),
            cli.output
                .as_ref()
                .map_or_else(|| "stdout".to_owned(), |path| path.display().to_string())
        );
    }
    Ok(())
}
