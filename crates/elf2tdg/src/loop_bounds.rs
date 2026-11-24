//! Conservative automatic loop-bound inference.
//!
//! The inference recognizes canonical counted loops only. It never guesses a
//! bound from source names or heuristics: it requires a constant initialization
//! that dominates the loop, exactly one constant self-update, one conditional
//! exit, and no calls or other writes to the induction register on the relevant
//! paths. Any missing or ambiguous fact leaves the loop unbounded.
//!
//! The inferred value bounds loop-header visits, not the exact backedge count,
//! and includes a conservative margin.

use std::collections::{BTreeMap, BTreeSet};

use capstone::RegId;
use capstone::arch::riscv;
use elf2tdg_schema::{BlockId, FunctionId};
use petgraph::Direction;
use petgraph::stable_graph::NodeIndex;
use petgraph::visit::{EdgeRef, IntoEdgeReferences};

use crate::arch::{DecodedInsn, ValueSource, normalize_register};
use crate::cfg::{CfgEdgeKind, CfgTerminator, FunctionCfg, ProgramCfg};
use crate::cfg_graph::{self, CfgGraphAnalysis, CfgLoop};
use crate::loader::ArchKind;

/// One automatically inferred loop bound.
#[derive(Clone, Debug)]
pub(crate) struct InferredLoopBound {
    /// Owning function.
    pub(crate) function: FunctionId,
    /// Loop header block address.
    pub(crate) header: u64,
    /// Maximum loop-header visits per external entry.
    pub(crate) bound: u32,
    /// Human-readable derivation.
    pub(crate) detail: String,
}

/// Infers loop bounds for every function in `program`.
pub(crate) fn infer_program(
    program: &ProgramCfg,
    decoded_by_function: &BTreeMap<u64, Vec<DecodedInsn>>,
    arch: ArchKind,
) -> Vec<InferredLoopBound> {
    if matches!(arch, ArchKind::X86_64 | ArchKind::Arm) {
        // A32 conditional execution and x86 flag semantics are not modeled by
        // the counted-loop recognizer.
        return Vec::new();
    }
    let mut bounds = Vec::new();
    for function in &program.functions {
        let Some(decoded) = decoded_by_function.get(&function.address) else {
            continue;
        };
        let instructions: BTreeMap<u64, &DecodedInsn> =
            decoded.iter().map(|insn| (insn.address, insn)).collect();
        let analysis = cfg_graph::analyze(&function.cfg);
        if analysis.blocked_by_unresolved || analysis.loops.is_empty() {
            continue;
        }
        let context = LoopAnalysis::new(&function.cfg, &analysis, &instructions, arch);
        if !context.all_instructions_decoded() {
            continue;
        }
        for loop_ in &analysis.loops {
            if let Some((header, bound, detail)) = context.infer_loop(loop_) {
                bounds.push(InferredLoopBound {
                    function: function.id.clone(),
                    header,
                    bound,
                    detail,
                });
            }
        }
    }
    bounds
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Relation {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

impl Relation {
    const fn negate(self) -> Self {
        match self {
            Self::Eq => Self::Ne,
            Self::Ne => Self::Eq,
            Self::Lt => Self::Ge,
            Self::Le => Self::Gt,
            Self::Gt => Self::Le,
            Self::Ge => Self::Lt,
        }
    }

    const fn reverse(self) -> Self {
        match self {
            Self::Eq => Self::Eq,
            Self::Ne => Self::Ne,
            Self::Lt => Self::Gt,
            Self::Le => Self::Ge,
            Self::Gt => Self::Lt,
            Self::Ge => Self::Le,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Eq => "eq",
            Self::Ne => "ne",
            Self::Lt => "lt",
            Self::Le => "le",
            Self::Gt => "gt",
            Self::Ge => "ge",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EvalOrder {
    /// The exit test runs before the induction update in each iteration.
    BranchFirst,
    /// The induction update runs before the exit test.
    UpdateFirst,
}

struct LoopAnalysis<'a> {
    cfg: &'a FunctionCfg,
    analysis: &'a CfgGraphAnalysis,
    instructions: &'a BTreeMap<u64, &'a DecodedInsn>,
    arch: ArchKind,
    node_by_id: BTreeMap<BlockId, NodeIndex>,
    predecessors: BTreeMap<NodeIndex, Vec<NodeIndex>>,
    successors: BTreeMap<NodeIndex, Vec<NodeIndex>>,
}

impl<'a> LoopAnalysis<'a> {
    fn new(
        cfg: &'a FunctionCfg,
        analysis: &'a CfgGraphAnalysis,
        instructions: &'a BTreeMap<u64, &'a DecodedInsn>,
        arch: ArchKind,
    ) -> Self {
        let node_by_id = cfg
            .blocks_by_address
            .values()
            .map(|node| (cfg.graph[*node].id.clone(), *node))
            .collect();
        let mut predecessors: BTreeMap<NodeIndex, Vec<NodeIndex>> = BTreeMap::new();
        let mut successors: BTreeMap<NodeIndex, Vec<NodeIndex>> = BTreeMap::new();
        for edge in cfg.graph.edge_references() {
            predecessors
                .entry(edge.target())
                .or_default()
                .push(edge.source());
            successors
                .entry(edge.source())
                .or_default()
                .push(edge.target());
        }
        Self {
            cfg,
            analysis,
            instructions,
            arch,
            node_by_id,
            predecessors,
            successors,
        }
    }

    fn all_instructions_decoded(&self) -> bool {
        self.cfg.graph.node_indices().all(|node| {
            self.cfg.graph[node]
                .instructions
                .iter()
                .all(|insn| self.instructions.contains_key(&insn.address))
        })
    }

    fn infer_loop(&self, loop_: &CfgLoop) -> Option<(u64, u32, String)> {
        if loop_.backedges.len() != 1 {
            return None;
        }
        let header_node = *self.node_by_id.get(&loop_.header)?;
        let header_address = self.cfg.graph[header_node].address;
        let latch_id = &loop_.backedges[0].from;
        let latch_node = *self.node_by_id.get(latch_id)?;
        let loop_nodes: BTreeSet<NodeIndex> = loop_
            .blocks
            .iter()
            .filter_map(|block| self.node_by_id.get(block))
            .copied()
            .collect();
        if loop_nodes.len() != loop_.blocks.len() || !loop_nodes.contains(&latch_node) {
            return None;
        }

        let (branch_node, exit_kind) = self.single_exit(&loop_nodes)?;
        let branch_block = &self.cfg.graph[branch_node];
        if branch_block.terminator != CfgTerminator::Branch {
            return None;
        }
        let mut inside_edges = self
            .cfg
            .graph
            .edges_directed(branch_node, Direction::Outgoing)
            .filter(|edge| loop_nodes.contains(&edge.target()))
            .map(|edge| (edge.target(), edge.weight().kind))
            .collect::<Vec<_>>();
        if inside_edges.len() != 1 {
            return None;
        }
        let (continue_node, continue_kind) = inside_edges.pop()?;
        if continue_kind == exit_kind
            || !matches!(
                continue_kind,
                CfgEdgeKind::Branch | CfgEdgeKind::Fallthrough
            )
            || !loop_nodes.contains(&continue_node)
        {
            return None;
        }

        let branch_insn = branch_block.instructions.last()?;
        let branch = *self.instructions.get(&branch_insn.address)?;
        if !branch.is_conditional || !branch.is_jump {
            return None;
        }
        let branch_relation = relation_for_branch(self.arch, &branch.mnemonic)?;
        let exit_taken = exit_kind == CfgEdgeKind::Branch;

        let (update_node, update_address, counter, step) = self.update(&loop_nodes)?;
        let order = self.loop_order(latch_id, update_node, branch_node)?;

        let (limit, comparison_relation) = self.comparison(
            branch_node,
            branch,
            branch_relation,
            update_address,
            counter,
        )?;
        let continue_relation = if exit_taken {
            comparison_relation.negate()
        } else {
            comparison_relation
        };
        let initial = self.initializer(header_node, &loop_nodes, counter)?;
        let bound = trip_bound(initial, limit, step, continue_relation, order)?;
        let detail = format!(
            "auto counted loop: init={initial} limit={limit} step={step} continue={} bound={bound}",
            continue_relation.name()
        );
        Some((header_address, bound, detail))
    }

    fn single_exit(&self, loop_nodes: &BTreeSet<NodeIndex>) -> Option<(NodeIndex, CfgEdgeKind)> {
        let mut exits = Vec::new();
        for &node in loop_nodes {
            for edge in self.cfg.graph.edges_directed(node, Direction::Outgoing) {
                if !loop_nodes.contains(&edge.target()) {
                    exits.push((node, edge.weight().kind));
                }
            }
        }
        if exits.len() != 1 {
            return None;
        }
        let (node, kind) = exits[0];
        matches!(kind, CfgEdgeKind::Branch | CfgEdgeKind::Fallthrough).then_some((node, kind))
    }

    fn update(&self, loop_nodes: &BTreeSet<NodeIndex>) -> Option<(NodeIndex, u64, RegId, i64)> {
        let mut updates = Vec::new();
        for &node in loop_nodes {
            for insn in &self.cfg.graph[node].instructions {
                let decoded = self.instructions.get(&insn.address)?;
                if decoded.is_call || decoded.mnemonic.to_ascii_lowercase().starts_with("it") {
                    return None;
                }
                let Some(effect) = decoded.value else {
                    continue;
                };
                let dest = normalize_register(self.arch, effect.dest);
                if let ValueSource::AddImmediate { base, imm } = effect.source
                    && normalize_register(self.arch, base) == dest
                    && imm != 0
                {
                    if has_shifted_operand(&decoded.operands) {
                        return None;
                    }
                    updates.push((node, insn.address, dest, imm));
                }
            }
        }
        if updates.len() != 1 {
            return None;
        }
        let (node, address, counter, step) = updates[0];
        for &loop_node in loop_nodes {
            for insn in &self.cfg.graph[loop_node].instructions {
                let decoded = self.instructions.get(&insn.address)?;
                if insn.address != address
                    && decoded
                        .regs_write
                        .iter()
                        .any(|register| normalize_register(self.arch, *register) == counter)
                {
                    return None;
                }
            }
        }
        Some((node, address, counter, step))
    }

    fn loop_order(
        &self,
        latch_id: &BlockId,
        update_node: NodeIndex,
        branch_node: NodeIndex,
    ) -> Option<EvalOrder> {
        let latch_dominators = self.analysis.dominators.get(latch_id)?;
        let branch_id = &self.cfg.graph[branch_node].id;
        let update_id = &self.cfg.graph[update_node].id;
        if !latch_dominators.contains(branch_id) || !latch_dominators.contains(update_id) {
            return None;
        }
        if branch_id == update_id || self.dominates(update_id, branch_id) {
            Some(EvalOrder::UpdateFirst)
        } else if self.dominates(branch_id, update_id) {
            Some(EvalOrder::BranchFirst)
        } else {
            None
        }
    }

    fn dominates(&self, dominator: &BlockId, dominated: &BlockId) -> bool {
        self.analysis
            .dominators
            .get(dominated)
            .is_some_and(|set| set.contains(dominator))
    }

    fn comparison(
        &self,
        branch_node: NodeIndex,
        branch: &DecodedInsn,
        branch_relation: Relation,
        update_address: u64,
        counter: RegId,
    ) -> Option<(u64, Relation)> {
        let branch_block = &self.cfg.graph[branch_node];
        let branch_index = branch_block.instructions.len().checked_sub(1)?;
        match self.arch {
            ArchKind::Thumb | ArchKind::Arm | ArchKind::Aarch64 => {
                if let Some(index) = branch_index.checked_sub(1) {
                    let previous = &branch_block.instructions[index];
                    let decoded = *self.instructions.get(&previous.address)?;
                    if decoded.compare.is_some() && has_shifted_operand(&decoded.operands) {
                        return None;
                    }
                    if let Some((register, limit)) = decoded.compare
                        && normalize_register(self.arch, register) == counter
                    {
                        return Some((limit, branch_relation));
                    }
                    if previous.address == update_address
                        && is_flag_setting_add_or_sub(&decoded.mnemonic)
                    {
                        if !matches!(branch_relation, Relation::Eq | Relation::Ne) {
                            return None;
                        }
                        return Some((0, branch_relation));
                    }
                }
                None
            }
            ArchKind::Riscv32 | ArchKind::Riscv64 => {
                let zero = RegId(u16::try_from(riscv::RiscVReg::RISCV_REG_ZERO).ok()?);
                if let Some((left, right)) = branch.branch_registers {
                    let left = normalize_register(self.arch, left);
                    let right = normalize_register(self.arch, right);
                    if left == counter && right == zero {
                        Some((0, branch_relation))
                    } else if right == counter && left == zero {
                        Some((0, branch_relation.reverse()))
                    } else {
                        None
                    }
                } else {
                    let mut registers = branch
                        .regs_read
                        .iter()
                        .map(|register| normalize_register(self.arch, *register));
                    let register = registers.next()?;
                    if registers.next().is_some() || register != counter {
                        return None;
                    }
                    Some((0, branch_relation))
                }
            }
            ArchKind::X86_64 => None,
        }
    }

    fn initializer(
        &self,
        header_node: NodeIndex,
        loop_nodes: &BTreeSet<NodeIndex>,
        counter: RegId,
    ) -> Option<u64> {
        let header_id = &self.cfg.graph[header_node].id;
        let ancestors = reachable(header_node, &self.predecessors);
        let mut initializers = Vec::new();
        for &node in &ancestors {
            if loop_nodes.contains(&node) {
                continue;
            }
            for insn in &self.cfg.graph[node].instructions {
                let decoded = *self.instructions.get(&insn.address)?;
                if decoded.mnemonic.to_ascii_lowercase().starts_with("it") {
                    return None;
                }
                if !decoded
                    .regs_write
                    .iter()
                    .any(|register| normalize_register(self.arch, *register) == counter)
                {
                    continue;
                }
                let effect = decoded.value?;
                if normalize_register(self.arch, effect.dest) != counter {
                    return None;
                }
                let ValueSource::Immediate(value) = effect.source else {
                    return None;
                };
                if has_shifted_operand(&decoded.operands) {
                    return None;
                }
                initializers.push((node, value));
            }
        }
        if initializers.len() != 1 {
            return None;
        }
        let (init_node, value) = initializers[0];
        if !self.dominates(&self.cfg.graph[init_node].id, header_id) {
            return None;
        }
        let descendants = reachable(init_node, &self.successors);
        for node in descendants.intersection(&ancestors).copied() {
            for insn in &self.cfg.graph[node].instructions {
                let decoded = *self.instructions.get(&insn.address)?;
                if decoded.is_call {
                    return None;
                }
            }
        }
        Some(value)
    }
}

fn reachable(start: NodeIndex, edges: &BTreeMap<NodeIndex, Vec<NodeIndex>>) -> BTreeSet<NodeIndex> {
    let mut seen = BTreeSet::new();
    let mut stack = vec![start];
    while let Some(node) = stack.pop() {
        if !seen.insert(node) {
            continue;
        }
        if let Some(next) = edges.get(&node) {
            stack.extend(next.iter().copied());
        }
    }
    seen
}

fn has_shifted_operand(operands: &str) -> bool {
    let operands = operands.to_ascii_lowercase();
    ["lsl", "lsr", "asr", "ror", "rrx"]
        .iter()
        .any(|shift| operands.contains(shift))
}

fn is_flag_setting_add_or_sub(mnemonic: &str) -> bool {
    let mnemonic = mnemonic
        .strip_suffix(".w")
        .or_else(|| mnemonic.strip_suffix(".n"))
        .unwrap_or(mnemonic);
    matches!(mnemonic, "subs" | "adds")
}

fn relation_for_branch(arch: ArchKind, mnemonic: &str) -> Option<Relation> {
    let mnemonic = mnemonic.to_ascii_lowercase();
    match arch {
        ArchKind::Thumb | ArchKind::Arm => {
            let mnemonic = mnemonic
                .strip_suffix(".w")
                .or_else(|| mnemonic.strip_suffix(".n"))
                .unwrap_or(&mnemonic);
            match mnemonic {
                "beq" => Some(Relation::Eq),
                "bne" => Some(Relation::Ne),
                "blt" | "blo" | "bcc" => Some(Relation::Lt),
                "ble" | "bls" => Some(Relation::Le),
                "bgt" | "bhi" => Some(Relation::Gt),
                "bge" | "bhs" | "bcs" => Some(Relation::Ge),
                _ => None,
            }
        }
        ArchKind::Aarch64 => {
            let condition = mnemonic.strip_prefix("b.")?;
            match condition {
                "eq" => Some(Relation::Eq),
                "ne" => Some(Relation::Ne),
                "lt" | "lo" => Some(Relation::Lt),
                "le" | "ls" => Some(Relation::Le),
                "gt" | "hi" => Some(Relation::Gt),
                "ge" | "hs" => Some(Relation::Ge),
                _ => None,
            }
        }
        ArchKind::Riscv32 | ArchKind::Riscv64 => {
            let mnemonic = mnemonic.strip_prefix("c.").unwrap_or(&mnemonic);
            match mnemonic {
                "beq" | "beqz" => Some(Relation::Eq),
                "bne" | "bnez" => Some(Relation::Ne),
                "blt" | "bltu" | "bltz" => Some(Relation::Lt),
                "ble" | "bleu" | "blez" => Some(Relation::Le),
                "bgt" | "bgtu" | "bgtz" => Some(Relation::Gt),
                "bge" | "bgeu" | "bgez" => Some(Relation::Ge),
                _ => None,
            }
        }
        ArchKind::X86_64 => None,
    }
}

fn trip_bound(
    initial: u64,
    limit: u64,
    step: i64,
    continue_relation: Relation,
    order: EvalOrder,
) -> Option<u32> {
    // Keep the induction variable inside a positive signed-32-bit range. This
    // rules out 32-bit wrap semantics that the arithmetic model does not see.
    if initial > i32::MAX as u64
        || limit > i32::MAX as u64
        || step == 0
        || step.unsigned_abs() > i32::MAX as u64
    {
        return None;
    }
    let initial = i128::from(initial);
    let limit = i128::from(limit);
    let step = i128::from(step);
    let (tested_value, leading_updates) = match order {
        EvalOrder::BranchFirst => (initial, 0_i128),
        EvalOrder::UpdateFirst => (initial.checked_add(step)?, 1_i128),
    };
    if !(0..=i128::from(i32::MAX)).contains(&tested_value) {
        return None;
    }
    let updates_after_test = trip_updates(tested_value, limit, step, continue_relation)?;
    let updates = leading_updates.checked_add(updates_after_test)?;
    let final_value = initial + updates.checked_mul(step)?;
    if !(0..=i128::from(i32::MAX)).contains(&final_value) {
        return None;
    }
    let bound = updates.checked_add(1)?;
    u32::try_from(bound).ok()
}

fn trip_updates(
    initial: i128,
    limit: i128,
    step: i128,
    continue_relation: Relation,
) -> Option<i128> {
    match continue_relation {
        Relation::Eq => {
            if initial == limit {
                Some(1)
            } else {
                Some(0)
            }
        }
        Relation::Ne => {
            if initial == limit {
                Some(0)
            } else {
                let delta = limit - initial;
                if delta % step != 0 || delta / step < 0 {
                    return None;
                }
                Some(delta / step)
            }
        }
        Relation::Lt => {
            if limit <= initial {
                Some(0)
            } else if step <= 0 {
                None
            } else {
                Some((limit - initial + step - 1) / step)
            }
        }
        Relation::Le => {
            if limit < initial {
                Some(0)
            } else if step <= 0 {
                None
            } else {
                Some((limit - initial) / step + 1)
            }
        }
        Relation::Gt => {
            if limit >= initial {
                Some(0)
            } else if step >= 0 {
                None
            } else {
                let stride = -step;
                Some((initial - limit + stride - 1) / stride)
            }
        }
        Relation::Ge => {
            if limit > initial {
                Some(0)
            } else if step >= 0 {
                None
            } else {
                let stride = -step;
                Some((initial - limit) / stride + 1)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use capstone::RegId;
    use capstone::arch::riscv;
    use elf2tdg_schema::{CostRange, FunctionId};

    use super::{EvalOrder, LoopAnalysis, Relation, infer_program, trip_bound};
    use crate::arch::{DecodedInsn, ValueEffect, ValueSource};
    use crate::cfg::{
        CfgBlockDraft, CfgEdgeDraft, CfgEdgeKind, CfgInstruction, CfgTerminator, FunctionCfg,
        ProgramCfg,
    };
    use crate::cfg_graph;
    use crate::loader::ArchKind;

    const R0: RegId = RegId(1);
    const R1: RegId = RegId(2);

    fn decoded(address: u64, mnemonic: &str) -> DecodedInsn {
        DecodedInsn {
            address,
            size: 2,
            mnemonic: mnemonic.to_owned(),
            operands: String::new(),
            is_call: false,
            is_jump: false,
            is_return: false,
            is_conditional: false,
            direct_target: None,
            value: None,
            memory_write: None,
            memory_accesses: Vec::new(),
            indirect: None,
            regs_read: Vec::new(),
            regs_write: Vec::new(),
            compare: None,
            branch_registers: None,
            compare_registers: None,
        }
    }

    fn cfg_insn(address: u64, mnemonic: &str) -> CfgInstruction {
        CfgInstruction {
            address,
            size: 2,
            bytes: vec![0; 2],
            mnemonic: mnemonic.to_owned(),
            operands: String::new(),
            text: mnemonic.to_owned(),
            is_call: false,
            is_jump: false,
            is_return: false,
            is_conditional: false,
            direct_target: None,
            indirect: None,
            memory_accesses: Vec::new(),
            cycles: Some(CostRange::exact(1.0)),
            source: None,
        }
    }

    fn block(
        address: u64,
        instructions: Vec<CfgInstruction>,
        terminator: CfgTerminator,
    ) -> CfgBlockDraft {
        CfgBlockDraft {
            address,
            size: 4,
            instructions,
            calls: Vec::new(),
            cycles: Some(CostRange::exact(1.0)),
            terminator,
        }
    }

    fn edge(from: u64, to: u64, kind: CfgEdgeKind) -> CfgEdgeDraft {
        CfgEdgeDraft {
            from,
            to,
            kind,
            site: from,
            conditional: kind == CfgEdgeKind::Branch,
        }
    }

    fn check_inferred(
        cfg: &FunctionCfg,
        decoded_instructions: &[DecodedInsn],
        arch: ArchKind,
    ) -> Option<u32> {
        let analysis = cfg_graph::analyze(cfg);
        let instructions: BTreeMap<u64, &DecodedInsn> = decoded_instructions
            .iter()
            .map(|insn| (insn.address, insn))
            .collect();
        let context = LoopAnalysis::new(cfg, &analysis, &instructions, arch);
        let loop_ = analysis.loops.first()?;
        context.infer_loop(loop_).map(|(_, bound, _)| bound)
    }

    #[test]
    fn infers_incrementing_compare_loop() {
        let cfg = FunctionCfg::build(
            vec![
                block(
                    0x1000,
                    vec![cfg_insn(0x1000, "movs")],
                    CfgTerminator::Fallthrough,
                ),
                block(
                    0x1002,
                    vec![cfg_insn(0x1002, "cmp"), cfg_insn(0x1004, "bne")],
                    CfgTerminator::Branch,
                ),
                block(
                    0x1006,
                    vec![cfg_insn(0x1006, "adds"), cfg_insn(0x1008, "b")],
                    CfgTerminator::Jump,
                ),
                block(0x100a, vec![cfg_insn(0x100a, "bx")], CfgTerminator::Return),
            ],
            vec![
                edge(0x1000, 0x1002, CfgEdgeKind::Fallthrough),
                edge(0x1002, 0x1006, CfgEdgeKind::Branch),
                edge(0x1002, 0x100a, CfgEdgeKind::Fallthrough),
                edge(0x1006, 0x1002, CfgEdgeKind::Jump),
            ],
            Some(0x1000),
        );

        let mut init = decoded(0x1000, "movs");
        init.value = Some(ValueEffect {
            dest: R0,
            source: ValueSource::Immediate(0),
        });
        init.regs_write = vec![R0];

        let mut cmp = decoded(0x1002, "cmp");
        cmp.regs_read = vec![R0];
        cmp.compare = Some((R0, 4));

        let mut branch = decoded(0x1004, "bne");
        branch.is_jump = true;
        branch.is_conditional = true;
        branch.direct_target = Some(0x1006);

        let mut update = decoded(0x1006, "adds");
        update.value = Some(ValueEffect {
            dest: R0,
            source: ValueSource::AddImmediate { base: R0, imm: 1 },
        });
        update.regs_write = vec![R0];

        let mut jump = decoded(0x1008, "b");
        jump.is_jump = true;
        jump.direct_target = Some(0x1002);

        assert_eq!(
            check_inferred(&cfg, &[init, cmp, branch, update, jump], ArchKind::Thumb),
            Some(5)
        );
    }

    #[test]
    fn infers_flag_setting_countdown_loop() {
        let cfg = FunctionCfg::build(
            vec![
                block(
                    0x2000,
                    vec![cfg_insn(0x2000, "movs")],
                    CfgTerminator::Fallthrough,
                ),
                block(
                    0x2002,
                    vec![cfg_insn(0x2002, "subs"), cfg_insn(0x2004, "bne")],
                    CfgTerminator::Branch,
                ),
                block(0x2006, vec![cfg_insn(0x2006, "bx")], CfgTerminator::Return),
            ],
            vec![
                edge(0x2000, 0x2002, CfgEdgeKind::Fallthrough),
                edge(0x2002, 0x2002, CfgEdgeKind::Branch),
                edge(0x2002, 0x2006, CfgEdgeKind::Fallthrough),
            ],
            Some(0x2000),
        );

        let mut init = decoded(0x2000, "movs");
        init.value = Some(ValueEffect {
            dest: R1,
            source: ValueSource::Immediate(4),
        });
        init.regs_write = vec![R1];

        let mut update = decoded(0x2002, "subs");
        update.value = Some(ValueEffect {
            dest: R1,
            source: ValueSource::AddImmediate { base: R1, imm: -1 },
        });
        update.regs_write = vec![R1];

        let mut branch = decoded(0x2004, "bne");
        branch.is_jump = true;
        branch.is_conditional = true;
        branch.direct_target = Some(0x2002);

        assert_eq!(
            check_inferred(&cfg, &[init, update, branch], ArchKind::Thumb),
            Some(5)
        );
    }

    #[test]
    fn infers_riscv_zero_compare_countdown() {
        let cfg = FunctionCfg::build(
            vec![
                block(
                    0x4000,
                    vec![cfg_insn(0x4000, "li")],
                    CfgTerminator::Fallthrough,
                ),
                block(
                    0x4002,
                    vec![cfg_insn(0x4002, "addi"), cfg_insn(0x4004, "bne")],
                    CfgTerminator::Branch,
                ),
                block(0x4006, vec![cfg_insn(0x4006, "ret")], CfgTerminator::Return),
            ],
            vec![
                edge(0x4000, 0x4002, CfgEdgeKind::Fallthrough),
                edge(0x4002, 0x4002, CfgEdgeKind::Branch),
                edge(0x4002, 0x4006, CfgEdgeKind::Fallthrough),
            ],
            Some(0x4000),
        );

        let mut init = decoded(0x4000, "li");
        init.value = Some(ValueEffect {
            dest: R0,
            source: ValueSource::Immediate(3),
        });
        init.regs_write = vec![R0];

        let mut update = decoded(0x4002, "addi");
        update.value = Some(ValueEffect {
            dest: R0,
            source: ValueSource::AddImmediate { base: R0, imm: -1 },
        });
        update.regs_write = vec![R0];

        let zero = RegId(u16::try_from(riscv::RiscVReg::RISCV_REG_ZERO).unwrap());
        let mut branch = decoded(0x4004, "bne");
        branch.is_jump = true;
        branch.is_conditional = true;
        branch.direct_target = Some(0x4002);
        branch.branch_registers = Some((R0, zero));

        assert_eq!(
            check_inferred(&cfg, &[init, update, branch], ArchKind::Riscv64),
            Some(4)
        );
    }

    #[test]
    fn rejects_loop_without_constant_initializer() {
        let cfg = FunctionCfg::build(
            vec![
                block(
                    0x3000,
                    vec![cfg_insn(0x3000, "cmp"), cfg_insn(0x3002, "bne")],
                    CfgTerminator::Branch,
                ),
                block(
                    0x3004,
                    vec![cfg_insn(0x3004, "adds"), cfg_insn(0x3006, "b")],
                    CfgTerminator::Jump,
                ),
                block(0x3008, vec![cfg_insn(0x3008, "bx")], CfgTerminator::Return),
            ],
            vec![
                edge(0x3000, 0x3004, CfgEdgeKind::Branch),
                edge(0x3000, 0x3008, CfgEdgeKind::Fallthrough),
                edge(0x3004, 0x3000, CfgEdgeKind::Jump),
            ],
            Some(0x3000),
        );
        let mut cmp = decoded(0x3000, "cmp");
        cmp.compare = Some((R0, 4));
        let mut branch = decoded(0x3002, "bne");
        branch.is_jump = true;
        branch.is_conditional = true;
        branch.direct_target = Some(0x3004);
        let mut update = decoded(0x3004, "adds");
        update.value = Some(ValueEffect {
            dest: R0,
            source: ValueSource::AddImmediate { base: R0, imm: 1 },
        });
        update.regs_write = vec![R0];
        let mut jump = decoded(0x3006, "b");
        jump.is_jump = true;
        jump.direct_target = Some(0x3000);
        assert_eq!(
            check_inferred(&cfg, &[cmp, branch, update, jump], ArchKind::Thumb),
            None
        );
    }

    #[test]
    fn trip_bound_handles_relation_margins() {
        let first = EvalOrder::BranchFirst;
        assert_eq!(trip_bound(0, 10, 1, Relation::Lt, first), Some(11));
        assert_eq!(trip_bound(0, 10, 1, Relation::Le, first), Some(12));
        assert_eq!(trip_bound(0, 10, 1, Relation::Ne, first), Some(11));
        assert_eq!(trip_bound(10, 0, -1, Relation::Gt, first), Some(11));
        // Crossing below zero is not modeled because the register width and
        // signedness are not visible here.
        assert_eq!(trip_bound(10, 0, -1, Relation::Ge, first), None);
        assert_eq!(trip_bound(10, 0, 1, Relation::Lt, first), Some(1));
        assert_eq!(trip_bound(0, 10, -1, Relation::Lt, first), None);
        assert_eq!(trip_bound(0, 10, 0, Relation::Lt, first), None);

        let update_first = EvalOrder::UpdateFirst;
        // The equality test sees the post-update value, so this exits after the
        // second update rather than before the loop body.
        assert_eq!(trip_bound(0, 1, 1, Relation::Eq, update_first), Some(3));
        assert_eq!(trip_bound(4, 0, -1, Relation::Ne, update_first), Some(5));
    }

    #[test]
    fn infer_program_requires_function_metadata() {
        let program = ProgramCfg::new(Vec::new());
        assert!(infer_program(&program, &BTreeMap::new(), ArchKind::Thumb).is_empty());
        let _ = FunctionId::new("fn:0x0");
    }
}
