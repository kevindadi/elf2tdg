//! Shared concrete LRU cache state used by instruction- and data-cache
//! analysis.

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct CacheState {
    sets: Vec<Vec<u64>>,
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
