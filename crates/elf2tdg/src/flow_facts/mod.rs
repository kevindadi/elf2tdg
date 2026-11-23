//! Flow facts consumed by IPET and the longest-path analysis.
//!
//! Facts come from the board profile's `[wcet]` section and from external F4
//! (`.ff`) or FFX (`.ffx`) files. F4/FFX facts are parsed into a symbolic
//! document first and resolved against the recovered `ProgramCfg`, so a fact
//! can name a loop by address, by function + offset, or by source file/line.

mod f4;
mod ffx;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use elf2tdg_schema::Addr;

use crate::board_profile::WcetProfile;
use crate::cfg::{CfgFlowFactsInfo, CfgFunction, CfgLoopBoundInfo, ProgramCfg};
use crate::rules::normalize_crate_hashes;

#[derive(Clone, Debug)]
struct LoopBound {
    bound: u32,
    source: String,
}

/// Bounds and assumptions used by the WCET analyses for one analysis run.
#[derive(Clone, Debug, Default)]
pub(crate) struct FlowFacts {
    source: String,
    default_loop_bound: Option<u32>,
    bound_nonterminating_loops: bool,
    loop_bounds: BTreeMap<u64, LoopBound>,
    warnings: Vec<String>,
}

impl FlowFacts {
    /// Builds flow facts from the board profile's `[wcet]` section.
    pub(crate) fn from_wcet_profile(profile: &WcetProfile) -> Self {
        Self {
            source: "board-profile [wcet]".to_owned(),
            default_loop_bound: profile.default_loop_bound(),
            bound_nonterminating_loops: profile.bound_nonterminating_loops(),
            loop_bounds: profile
                .loop_bounds()
                .map(|(header, bound)| {
                    (
                        header,
                        LoopBound {
                            bound,
                            source: "board-profile [wcet]".to_owned(),
                        },
                    )
                })
                .collect(),
            warnings: Vec::new(),
        }
    }

    /// Human-readable source summary.
    pub(crate) fn source(&self) -> &str {
        &self.source
    }

    /// Default loop bound applied to loops without an explicit entry.
    pub(crate) fn default_loop_bound(&self) -> Option<u32> {
        self.default_loop_bound
    }

    /// Whether loops without a static exit are explicitly bounded.
    pub(crate) fn bound_nonterminating_loops(&self) -> bool {
        self.bound_nonterminating_loops
    }

    /// Returns the bound for a loop header, preferring an explicit entry.
    pub(crate) fn bound_for(&self, header: u64) -> Option<u32> {
        self.loop_bounds
            .get(&header)
            .map(|entry| entry.bound)
            .or(self.default_loop_bound)
    }

    /// Explicit loop bounds keyed by header address, with provenance.
    pub(crate) fn loops(&self) -> impl Iterator<Item = (u64, u32, &str)> + '_ {
        self.loop_bounds
            .iter()
            .map(|(header, entry)| (*header, entry.bound, entry.source.as_str()))
    }

    /// Warnings collected while importing flow facts.
    pub(crate) fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// Builds the JSON metadata object for the WCET document.
    pub(crate) fn info(&self) -> CfgFlowFactsInfo {
        CfgFlowFactsInfo {
            source: self.source().to_owned(),
            default_loop_bound: self.default_loop_bound,
            bound_nonterminating_loops: self.bound_nonterminating_loops,
            loops: self
                .loops()
                .map(|(header, bound, source)| CfgLoopBoundInfo {
                    header: Addr::new(header),
                    bound,
                    source: source.to_owned(),
                })
                .collect(),
        }
    }

    /// Parses and applies F4/FFX files in order.
    pub(crate) fn apply_paths(
        &mut self,
        paths: &[PathBuf],
        program: &ProgramCfg,
    ) -> Result<(), String> {
        for path in paths {
            let document = FlowFactDocument::parse_file(path)?;
            self.apply_document(document, program)?;
        }
        Ok(())
    }

    /// Resolves and merges one parsed flow-fact document.
    ///
    /// Conflicting bounds for the same loop keep the larger value, which is
    /// conservative. Context-specific facts are applied context-insensitively
    /// and produce a warning.
    pub(crate) fn apply_document(
        &mut self,
        document: FlowFactDocument,
        program: &ProgramCfg,
    ) -> Result<(), String> {
        if document.checksum.is_some() {
            self.warnings.push(format!(
                "{}: checksum was parsed but not verified",
                document.origin
            ));
        }
        if self.source.is_empty() {
            self.source.clone_from(&document.origin);
        } else if !self.source.contains(&document.origin) {
            self.source = format!("{} + {}", self.source, document.origin);
        }
        self.warnings.extend(document.warnings);
        for fact in &document.loops {
            if !fact.context.is_empty() {
                self.warnings.push(format!(
                    "{}: context-specific flow fact [{}] is applied context-insensitively",
                    document.origin,
                    fact.context.join(" / ")
                ));
            }
            let header = resolve_target(program, &fact.target, &document.origin)?;
            let candidate = LoopBound {
                bound: fact.max,
                source: document.origin.clone(),
            };
            match self.loop_bounds.get_mut(&header) {
                Some(existing) => {
                    if candidate.bound > existing.bound {
                        self.warnings.push(format!(
                            "{}: loop 0x{header:x} bound {} replaces {} from {}; using the larger bound",
                            document.origin, candidate.bound, existing.bound, existing.source
                        ));
                        *existing = candidate;
                    } else if candidate.bound < existing.bound {
                        self.warnings.push(format!(
                            "{}: loop 0x{header:x} bound {} is below {} from {}; keeping the larger bound",
                            document.origin, candidate.bound, existing.bound, existing.source
                        ));
                    } else if !existing.source.contains(&document.origin) {
                        existing.source = format!("{} + {}", existing.source, document.origin);
                    }
                }
                None => {
                    self.loop_bounds.insert(header, candidate);
                }
            }
        }
        Ok(())
    }
}

/// Parsed flow-fact file before resolution against a `ProgramCfg`.
#[derive(Clone, Debug)]
pub(crate) struct FlowFactDocument {
    origin: String,
    checksum: Option<String>,
    loops: Vec<LoopFact>,
    warnings: Vec<String>,
}

impl FlowFactDocument {
    /// Parses a file, detecting FFX XML by content (and F4 otherwise).
    pub(crate) fn parse_file(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|error| {
            format!("failed to read flow-fact file {}: {error}", path.display())
        })?;
        let origin = path.display().to_string();
        let is_ffx = text.trim_start().starts_with('<')
            || path
                .extension()
                .and_then(std::ffi::OsStr::to_str)
                .is_some_and(|extension| {
                    extension.eq_ignore_ascii_case("ffx") || extension.eq_ignore_ascii_case("xml")
                });
        if is_ffx {
            ffx::parse(&text, &origin)
        } else {
            f4::parse(&text, &origin)
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct LoopFact {
    target: LoopTarget,
    max: u32,
    context: Vec<String>,
}

#[derive(Clone, Debug)]
pub(crate) enum LoopTarget {
    Address(u64),
    FunctionOffset {
        function: String,
        offset: u64,
    },
    SourceLine {
        function: Option<String>,
        file: String,
        line: u32,
    },
}

fn resolve_target(program: &ProgramCfg, target: &LoopTarget, origin: &str) -> Result<u64, String> {
    match target {
        LoopTarget::Address(address) => {
            if block_exists(program, *address) {
                Ok(*address)
            } else {
                Err(format!(
                    "{origin}: loop header 0x{address:x} is not a CFG block"
                ))
            }
        }
        LoopTarget::FunctionOffset { function, offset } => {
            let function = find_function(program, function, origin)?;
            let address = function
                .address
                .checked_add(*offset)
                .ok_or_else(|| format!("{origin}: loop offset overflows the address space"))?;
            if function.cfg.blocks_by_address.contains_key(&address) {
                Ok(address)
            } else {
                Err(format!(
                    "{origin}: function {:?} has no block at 0x{address:x}",
                    function.primary_name
                ))
            }
        }
        LoopTarget::SourceLine {
            function,
            file,
            line,
        } => resolve_source_loop(program, function.as_deref(), file, *line, origin),
    }
}

fn block_exists(program: &ProgramCfg, address: u64) -> bool {
    program
        .functions
        .iter()
        .any(|function| function.cfg.blocks_by_address.contains_key(&address))
}

fn find_function<'a>(
    program: &'a ProgramCfg,
    name: &str,
    origin: &str,
) -> Result<&'a CfgFunction, String> {
    let candidates: Vec<&CfgFunction> = program
        .functions
        .iter()
        .filter(|function| function_matches(function, name))
        .collect();
    match candidates.as_slice() {
        [function] => Ok(function),
        [] => Err(format!("{origin}: function {name:?} was not found")),
        _ => Err(format!(
            "{origin}: function {name:?} is ambiguous ({} matches)",
            candidates.len()
        )),
    }
}

fn function_matches(function: &CfgFunction, name: &str) -> bool {
    fn matches(candidate: &str, name: &str) -> bool {
        let candidate = normalize_crate_hashes(candidate);
        candidate == name
            || candidate
                .rsplit("::")
                .next()
                .is_some_and(|last| last == name)
    }
    matches(&function.primary_name, name)
        || function
            .demangled_name
            .as_deref()
            .is_some_and(|demangled| matches(demangled, name))
        || function
            .symbols
            .iter()
            .any(|symbol| symbol == name || matches(symbol, name))
}

fn resolve_source_loop(
    program: &ProgramCfg,
    function_name: Option<&str>,
    file: &str,
    line: u32,
    origin: &str,
) -> Result<u64, String> {
    let functions: Vec<&CfgFunction> = match function_name {
        Some(name) => vec![find_function(program, name, origin)?],
        None => program.functions.iter().collect(),
    };
    let mut matches = BTreeSet::new();
    for function in functions {
        let analysis = crate::cfg_graph::analyze(&function.cfg);
        for loop_ in &analysis.loops {
            let Some(node) = function
                .cfg
                .blocks_by_address
                .values()
                .copied()
                .find(|node| function.cfg.graph[*node].id == loop_.header)
            else {
                continue;
            };
            let block = &function.cfg.graph[node];
            if block.instructions.iter().any(|instruction| {
                instruction
                    .source
                    .as_ref()
                    .is_some_and(|source| source.line == line && file_matches(file, &source.file))
            }) {
                matches.insert(block.address);
            }
        }
    }
    match matches.len() {
        1 => matches
            .first()
            .copied()
            .ok_or_else(|| format!("{origin}: internal error resolving loop source")),
        0 => Err(format!(
            "{origin}: no natural loop header matches source {file}:{line}"
        )),
        _ => Err(format!(
            "{origin}: source {file}:{line} matches multiple loops (0x{:x}..)",
            matches.first().copied().unwrap_or(0)
        )),
    }
}

fn file_matches(expected: &str, actual: &str) -> bool {
    let expected = expected.trim_start_matches("./");
    let actual = actual.trim_start_matches("./");
    if actual == expected || actual.ends_with(expected) {
        return true;
    }
    let expected_name = Path::new(expected)
        .file_name()
        .and_then(std::ffi::OsStr::to_str);
    let actual_name = Path::new(actual)
        .file_name()
        .and_then(std::ffi::OsStr::to_str);
    expected_name.is_some() && expected_name == actual_name
}

#[cfg(test)]
mod tests {
    use super::FlowFacts;
    use crate::board_profile::BoardProfile;

    fn profile(text: &str) -> BoardProfile {
        BoardProfile::parse_toml(text).expect("valid profile")
    }

    #[test]
    fn reads_default_and_explicit_loop_bounds() {
        let board = profile(
            r#"
schema_version = 2
id = "board:flow-test"
arch = "thumb"
cpu = "cortex-m7"

[clocks.core]
hz = 1_000_000

[wcet]
default_loop_bound = 4
bound_nonterminating_loops = true

[[wcet.loop_bounds]]
header = 0x1000
bound = 12
"#,
        );
        let wcet = board.wcet().expect("wcet section");
        let facts = FlowFacts::from_wcet_profile(wcet);
        assert_eq!(facts.default_loop_bound(), Some(4));
        assert!(facts.bound_nonterminating_loops());
        assert_eq!(facts.bound_for(0x1000), Some(12));
        assert_eq!(facts.bound_for(0x2000), Some(4));
        assert_eq!(
            facts
                .loops()
                .map(|(header, bound, _)| (header, bound))
                .collect::<Vec<_>>(),
            vec![(0x1000, 12)]
        );
    }

    #[test]
    fn explicit_bound_wins_over_default() {
        let board = profile(
            r#"
schema_version = 2
id = "board:flow-test"
arch = "thumb"
cpu = "cortex-m7"

[clocks.core]
hz = 1_000_000

[wcet]
default_loop_bound = 2

[[wcet.loop_bounds]]
header = 0x400
bound = 7
"#,
        );
        let facts = FlowFacts::from_wcet_profile(board.wcet().expect("wcet section"));
        assert_eq!(facts.bound_for(0x400), Some(7));
        assert_eq!(facts.bound_for(0x800), Some(2));
        assert!(!facts.bound_nonterminating_loops());
    }
}
