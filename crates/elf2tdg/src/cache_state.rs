//! Shared concrete LRU cache state and access simulation used by
//! instruction- and data-cache analysis and by cache-aware IPET.

use std::collections::BTreeMap;

use crate::cfg::{CfgBlock, CfgMemoryAccessKind};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct CacheState {
    sets: Vec<Vec<u64>>,
}

/// One modeled cache access.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CacheAccessKind {
    Fetch,
    Read,
    Write,
    ReadWrite,
}

impl From<CfgMemoryAccessKind> for CacheAccessKind {
    fn from(kind: CfgMemoryAccessKind) -> Self {
        match kind {
            CfgMemoryAccessKind::Read => Self::Read,
            CfgMemoryAccessKind::Write => Self::Write,
            CfgMemoryAccessKind::ReadWrite => Self::ReadWrite,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CacheAccess {
    pub(crate) line: u64,
    pub(crate) kind: CacheAccessKind,
}

/// Geometry of one modeled LRU cache.
#[derive(Clone, Copy, Debug)]
pub(crate) struct CacheGeometry {
    pub(crate) line_bytes: u64,
    pub(crate) sets: u64,
    pub(crate) ways: usize,
}

impl CacheGeometry {
    pub(crate) fn line_of(self, address: u64) -> u64 {
        address / self.line_bytes
    }

    pub(crate) fn line_address(self, line: u64) -> u64 {
        line.saturating_mul(self.line_bytes)
    }

    pub(crate) fn cold(self) -> CacheState {
        CacheState::cold(usize::try_from(self.sets).unwrap_or(usize::MAX))
    }
}

/// Result of applying a block's access sequence to one cache entry state.
#[derive(Clone, Debug)]
pub(crate) struct CacheSimulation {
    pub(crate) state: CacheState,
    pub(crate) misses: u32,
    pub(crate) hits_by_line: BTreeMap<u64, u32>,
}

/// Instruction-fetch line accesses in block execution order.
pub(crate) fn instruction_accesses(block: &CfgBlock, geometry: CacheGeometry) -> Vec<CacheAccess> {
    let mut accesses = Vec::new();
    for instruction in &block.instructions {
        if instruction.size == 0 {
            continue;
        }
        let first = geometry.line_of(instruction.address);
        let last = geometry.line_of(
            instruction
                .address
                .saturating_add(u64::from(instruction.size).saturating_sub(1)),
        );
        for line in first..=last {
            accesses.push(CacheAccess {
                line,
                kind: CacheAccessKind::Fetch,
            });
        }
    }
    accesses
}

/// Statically resolved data-line accesses in block execution order.
pub(crate) fn data_accesses(block: &CfgBlock, geometry: CacheGeometry) -> Vec<CacheAccess> {
    let mut accesses = Vec::new();
    for instruction in &block.instructions {
        for access in &instruction.memory_accesses {
            let Some(address) = access.address else {
                continue;
            };
            let width = u64::from(access.width.max(1));
            let first = geometry.line_of(address.get());
            let last = geometry.line_of(address.get().saturating_add(width.saturating_sub(1)));
            for line in first..=last {
                accesses.push(CacheAccess {
                    line,
                    kind: access.kind.into(),
                });
            }
        }
    }
    accesses
}

/// Applies an access sequence to `state` and reports modeled misses and hits.
pub(crate) fn simulate(
    accesses: &[CacheAccess],
    state: &CacheState,
    geometry: CacheGeometry,
    write_allocate: bool,
) -> CacheSimulation {
    let mut state = state.clone();
    let mut misses = 0_u32;
    let mut hits_by_line = BTreeMap::new();
    for access in accesses {
        let hit = match access.kind {
            CacheAccessKind::Fetch | CacheAccessKind::Read | CacheAccessKind::ReadWrite => {
                state.access(access.line, geometry.ways, geometry.sets)
            }
            CacheAccessKind::Write if write_allocate => {
                state.access(access.line, geometry.ways, geometry.sets)
            }
            CacheAccessKind::Write => state.write_no_allocate(access.line, geometry.sets),
        };
        if hit {
            *hits_by_line.entry(access.line).or_insert(0) += 1;
        } else {
            misses = misses.saturating_add(1);
        }
    }
    CacheSimulation {
        state,
        misses,
        hits_by_line,
    }
}

impl CacheState {
    pub(crate) fn cold(set_count: usize) -> Self {
        Self {
            sets: vec![Vec::new(); set_count],
        }
    }

    /// Accesses `line`, inserting on a miss and refreshing LRU order on a hit.
    pub(crate) fn access(&mut self, line: u64, ways: usize, set_count: u64) -> bool {
        let set = usize::try_from(line % set_count).unwrap_or(0);
        let lines = &mut self.sets[set];
        if let Some(position) = lines.iter().position(|cached| *cached == line) {
            lines.remove(position);
            lines.insert(0, line);
            true
        } else {
            lines.insert(0, line);
            lines.truncate(ways);
            false
        }
    }

    /// Accesses `line` for a write that does not allocate on a miss.
    ///
    /// A hit refreshes LRU order and returns `true`; a miss leaves the state
    /// unchanged and returns `false`.
    pub(crate) fn write_no_allocate(&mut self, line: u64, set_count: u64) -> bool {
        let set = usize::try_from(line % set_count).unwrap_or(0);
        let lines = &mut self.sets[set];
        if let Some(position) = lines.iter().position(|cached| *cached == line) {
            lines.remove(position);
            lines.insert(0, line);
            true
        } else {
            false
        }
    }
}
