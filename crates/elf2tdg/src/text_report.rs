//! Human-readable CFG and WCET reports.
//!
//! The text report is intentionally structured like a static-analysis report,
//! not like a debug log: program metadata, roots, analysis models, call graph,
//! diagnostics, then one section per function with blocks, edges, calls and
//! WCET results. It is deterministic and safe to diff.

use std::collections::BTreeSet;
use std::fmt::Write as _;

use elf2tdg_schema::{Addr, CostRange, Diagnostic, FunctionId, SourceLoc};
use petgraph::visit::EdgeRef;

use crate::cfg::{
    CFG_SCHEMA_VERSION, CfgBlock, CfgBranchPredictionInfo, CfgCacheInfo, CfgCallEdge, CfgCallSite,
    CfgConcurrencyKind, CfgDataCacheInfo, CfgDataMemoryInfo, CfgFunction, CfgFunctionWcet,
    CfgInstruction, CfgLockEvent, CfgMulticoreInfo, CfgRoot, CfgSystemModelInfo, CfgWcetInfo,
    CfgWcetRoot, CfgWcetStatus, FunctionCfg, ProgramCfg,
};
use crate::rules::normalize_crate_hashes;

/// Renders the selected function CFGs and program metadata as a readable text
/// report.
///
/// # Errors
///
/// Returns an error when the function selector matches nothing or is ambiguous.
pub fn render_text(
    program: &ProgramCfg,
    selector: Option<&str>,
    include_instructions: bool,
) -> Result<String, String> {
    let selected = program.select(selector)?;
    Ok(render_text_selected(
        program,
        &selected,
        include_instructions,
    ))
}

/// Renders an explicitly selected set of function CFGs as a readable text
/// report.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn render_text_selected(
    program: &ProgramCfg,
    selected: &[&CfgFunction],
    include_instructions: bool,
) -> String {
    let mut out = String::new();
    render_header(&mut out, program);
    render_program_summary(&mut out, program, selected);
    render_roots(&mut out, program);
    render_timing(&mut out, program);
    render_analysis_models(&mut out, program);
    render_wcet(&mut out, program);
    if program.system_model.is_some() {
        render_system_model(&mut out, program.system_model.as_ref());
    }
    render_calls(&mut out, program, selected);
    render_concurrency(&mut out, program, selected);
    render_locks(&mut out, program, selected);
    render_diagnostics(&mut out, program, selected);
    for function in selected {
        render_function(&mut out, program, function, include_instructions);
    }
    out
}

fn render_header(out: &mut String, program: &ProgramCfg) {
    heading(out, "elf2tdg CFG report", '=');
    let Some(image) = program.image.as_ref() else {
        let _ = writeln!(out, "(image metadata unavailable)\n");
        return;
    };
    kv(out, "image", image.path.as_deref().unwrap_or("(in-memory)"));
    kv(
        out,
        "architecture",
        &format!("{} ({})", image.arch, serde_name(&image.endianness)),
    );
    kv(out, "entry", &image.entry.to_string());
    kv(out, "elf type", &serde_name(&image.elf_type));
    kv(out, "symbols", yes_no(image.has_symbols));
    kv(out, "debug info", yes_no(image.has_debug_info));
    kv(out, "relocations", yes_no(image.has_relocations));
    kv(out, "cfg schema", CFG_SCHEMA_VERSION);
    out.push('\n');
}

fn render_program_summary(out: &mut String, program: &ProgramCfg, selected: &[&CfgFunction]) {
    section(out, "program");
    let selected_ids: BTreeSet<&FunctionId> =
        selected.iter().map(|function| &function.id).collect();
    let blocks: usize = selected
        .iter()
        .map(|function| function.cfg.blocks_by_address.len())
        .sum();
    let edges: usize = selected
        .iter()
        .map(|function| function.cfg.graph.edge_count())
        .sum();
    let calls = program
        .calls
        .iter()
        .filter(|call| selected_ids.contains(&call.caller))
        .count();
    let diagnostics = scoped_diagnostics(program, &selected_ids).count();
    kv(
        out,
        "functions",
        &format!(
            "{} selected / {} total",
            selected.len(),
            program.functions.len()
        ),
    );
    kv(out, "blocks", &blocks.to_string());
    kv(out, "edges", &edges.to_string());
    kv(
        out,
        "calls",
        &format!("{calls} selected / {} total", program.calls.len()),
    );
    kv(
        out,
        "roots",
        &format!("{} execution root(s)", program.roots.len()),
    );
    kv(
        out,
        "concurrency",
        &format!(
            "{} site(s) selected / {} total",
            program
                .concurrency
                .iter()
                .filter(|site| selected_ids.contains(&site.function))
                .count(),
            program.concurrency.len()
        ),
    );
    kv(
        out,
        "locks",
        &format!(
            "{} event(s) selected / {} total",
            program
                .locks
                .iter()
                .filter(|lock| selected_ids.contains(&lock.function))
                .count(),
            program.locks.len()
        ),
    );
    kv(out, "diagnostics", &diagnostics.to_string());
    out.push('\n');
}

fn render_roots(out: &mut String, program: &ProgramCfg) {
    section(out, "execution roots");
    if program.roots.is_empty() {
        let _ = writeln!(out, "  (none)\n");
        return;
    }
    for root in &program.roots {
        render_root(out, program, root);
    }
    out.push('\n');
}

fn render_root(out: &mut String, program: &ProgramCfg, root: &CfgRoot) {
    let name = root
        .name
        .as_deref()
        .map_or_else(|| function_name(program, &root.function), ToOwned::to_owned);
    let _ = writeln!(out, "* {}  {name}", serde_name(&root.kind));
    kv_indent(out, "function", root.function.as_str());
    if let Some(function) = program.function(&root.function) {
        kv_indent(out, "address", &address(function.address));
    }
    if let Some(vector) = root.vector {
        let value = root
            .irq
            .map_or_else(|| vector.to_string(), |irq| format!("{vector} (IRQ {irq})"));
        kv_indent(out, "vector", &value);
    }
    kv_indent(out, "confidence", &serde_name(&root.confidence));
}

fn render_timing(out: &mut String, program: &ProgramCfg) {
    section(out, "timing");
    let Some(timing) = program.timing.as_ref() else {
        let _ = writeln!(out, "  (no timing metadata)\n");
        return;
    };
    if timing.models.is_empty() {
        let _ = writeln!(out, "  (no instruction timing model)");
    }
    for model in &timing.models {
        let core = model.core.as_deref().unwrap_or("unknown core");
        let _ = writeln!(out, "* {} ({core})", model.id);
        kv_indent(out, "arch", &model.arch);
        kv_indent(out, "determinism", &serde_name(&model.determinism));
        kv_indent(out, "cost table", &model.table_version);
        if let Some(wait_states) = model.params.flash_wait_states {
            kv_indent(out, "flash wait", &format!("{wait_states} cycle(s)"));
        }
        if let Some(branch_prediction) = model.params.branch_prediction {
            kv_indent(out, "branch model", yes_no(branch_prediction));
        }
        if let Some(dual_issue) = model.params.dual_issue {
            kv_indent(out, "dual issue", yes_no(dual_issue));
        }
        for (key, value) in &model.params.extras {
            kv_indent(out, key, value);
        }
        for caveat in &model.caveats {
            let _ = writeln!(out, "    caveat: {caveat}");
        }
    }
    for domain in &timing.frequency_domains {
        let _ = writeln!(out, "* clock {} ({})", domain.id, domain.name);
        kv_indent(out, "frequency", &format!("{} Hz", domain.hz));
        kv_indent(out, "source", &serde_name(&domain.source));
        kv_indent(out, "confidence", &serde_name(&domain.confidence));
    }
    for caveat in &timing.caveats {
        let _ = writeln!(out, "  caveat: {caveat}");
    }
    out.push('\n');
}

fn render_analysis_models(out: &mut String, program: &ProgramCfg) {
    section(out, "analysis models");
    let mut any = false;
    any |= render_instruction_cache(out, program.cache.as_ref());
    any |= render_data_cache(out, program.data_cache.as_ref());
    any |= render_branch_prediction(out, program.branch_prediction.as_ref());
    any |= render_data_memory(out, program.data_memory.as_ref());
    any |= render_multicore(out, program.multicore.as_ref());
    if !any {
        let _ = writeln!(
            out,
            "  (no optional microarchitecture model is enabled; pass --board-profile to enable one)"
        );
    }
    out.push('\n');
}

fn render_instruction_cache(out: &mut String, cache: Option<&CfgCacheInfo>) -> bool {
    let Some(cache) = cache else {
        return false;
    };
    let _ = writeln!(out, "* instruction cache: {}", cache.model);
    kv_indent(
        out,
        "geometry",
        &format!(
            "{} bytes, {} bytes/line, {} way(s), {} set(s)",
            cache.size, cache.line_bytes, cache.ways, cache.sets
        ),
    );
    kv_indent(
        out,
        "miss penalty",
        &format!("{} cycle(s)", cache.miss_penalty),
    );
    kv_indent(out, "entry state", &cache.entry_state);
    kv_indent(out, "invalidate on call", yes_no(cache.invalidate_on_call));
    kv_indent(
        out,
        "coverage",
        &format!(
            "{} function(s) analyzed, {} fallback; {} block(s) analyzed, {} fallback",
            cache.functions_analyzed,
            cache.functions_fallback,
            cache.blocks_analyzed,
            cache.blocks_fallback
        ),
    );
    for caveat in &cache.caveats {
        let _ = writeln!(out, "    caveat: {caveat}");
    }
    true
}

fn render_data_cache(out: &mut String, cache: Option<&CfgDataCacheInfo>) -> bool {
    let Some(cache) = cache else {
        return false;
    };
    let _ = writeln!(out, "* data cache: {}", cache.model);
    kv_indent(
        out,
        "geometry",
        &format!(
            "{} bytes, {} bytes/line, {} way(s), {} set(s)",
            cache.size, cache.line_bytes, cache.ways, cache.sets
        ),
    );
    kv_indent(
        out,
        "miss penalty",
        &format!("{} cycle(s)", cache.miss_penalty),
    );
    kv_indent(out, "write allocate", yes_no(cache.write_allocate));
    kv_indent(out, "entry state", &cache.entry_state);
    kv_indent(out, "invalidate on call", yes_no(cache.invalidate_on_call));
    kv_indent(
        out,
        "accesses",
        &format!(
            "{} decoded, {} resolved, {} unresolved, {} line access(es)",
            cache.memory_accesses,
            cache.resolved_memory_accesses,
            cache.unresolved_memory_accesses,
            cache.line_accesses
        ),
    );
    kv_indent(
        out,
        "coverage",
        &format!(
            "{} function(s) analyzed, {} fallback; {} block(s) analyzed, {} fallback",
            cache.functions_analyzed,
            cache.functions_fallback,
            cache.blocks_analyzed,
            cache.blocks_fallback
        ),
    );
    for caveat in &cache.caveats {
        let _ = writeln!(out, "    caveat: {caveat}");
    }
    true
}

fn render_branch_prediction(
    out: &mut String,
    prediction: Option<&CfgBranchPredictionInfo>,
) -> bool {
    let Some(prediction) = prediction else {
        return false;
    };
    let _ = writeln!(out, "* branch prediction: {}", prediction.model);
    kv_indent(
        out,
        "mispredict",
        &format!("{} cycle(s)", prediction.mispredict_penalty),
    );
    kv_indent(out, "max states", &prediction.max_states.to_string());
    if let Some(initial) = &prediction.initial_state {
        kv_indent(out, "initial state", initial);
    }
    kv_indent(
        out,
        "coverage",
        &format!(
            "{} function(s) analyzed, {} fallback; {} branch(es) analyzed, {} fallback",
            prediction.functions_analyzed,
            prediction.functions_fallback,
            prediction.branches_analyzed,
            prediction.branches_fallback
        ),
    );
    for caveat in &prediction.caveats {
        let _ = writeln!(out, "    caveat: {caveat}");
    }
    true
}

fn render_multicore(out: &mut String, info: Option<&CfgMulticoreInfo>) -> bool {
    let Some(info) = info else {
        return false;
    };
    let _ = writeln!(out, "* multicore interference: {}", info.model);
    kv_indent(
        out,
        "topology",
        &format!("{} core(s), this is core {}", info.cores, info.core_id),
    );
    if let Some(confidence) = &info.confidence {
        kv_indent(out, "confidence", &serde_name(confidence));
    }
    kv_indent(
        out,
        "budgets",
        &format!(
            "{} read, {} write, {} fetch cycle(s) per event",
            info.data_read_interference_cycles,
            info.data_write_interference_cycles,
            info.instruction_fetch_interference_cycles
        ),
    );
    kv_indent(
        out,
        "events",
        &format!(
            "{} read(s), {} write(s), {} fetch(es)",
            info.data_read_accesses, info.data_write_accesses, info.instruction_fetches
        ),
    );
    kv_indent(
        out,
        "coverage",
        &format!(
            "{} function(s), {} block(s)",
            info.functions_analyzed, info.blocks_analyzed
        ),
    );
    kv_indent(
        out,
        "interference",
        &format!("{} cycle(s)", info.interference_cycles),
    );
    for caveat in &info.caveats {
        let _ = writeln!(out, "    caveat: {caveat}");
    }
    true
}

fn render_data_memory(out: &mut String, memory: Option<&CfgDataMemoryInfo>) -> bool {
    let Some(memory) = memory else {
        return false;
    };
    let _ = writeln!(out, "* data memory: {}", memory.model);
    kv_indent(
        out,
        "accesses",
        &format!(
            "{} decoded, {} resolved, {} unresolved, {} mapped, {} unmapped",
            memory.accesses,
            memory.resolved_accesses,
            memory.unresolved_accesses,
            memory.mapped_accesses,
            memory.unmapped_accesses
        ),
    );
    kv_indent(
        out,
        "wait cycles",
        &format!(
            "{} total ({} read, {} write)",
            memory.wait_cycles, memory.read_wait_cycles, memory.write_wait_cycles
        ),
    );
    kv_indent(
        out,
        "coverage",
        &format!(
            "{} function(s), {} block(s)",
            memory.functions_analyzed, memory.blocks_analyzed
        ),
    );
    for caveat in &memory.caveats {
        let _ = writeln!(out, "    caveat: {caveat}");
    }
    true
}

fn render_wcet(out: &mut String, program: &ProgramCfg) {
    section(out, "wcet");
    let Some(wcet) = program.wcet.as_ref() else {
        let _ = writeln!(
            out,
            "  (not analyzed; add a [wcet] section to a --board-profile to enable it)\n"
        );
        return;
    };
    render_wcet_info(out, wcet);
    if !wcet.roots.is_empty() {
        let _ = writeln!(out, "  root estimates:");
        for root in &wcet.roots {
            render_wcet_root(out, program, root);
        }
    }
    let _ = writeln!(
        out,
        "  per-function results are shown in each function section below."
    );
    for caveat in &wcet.caveats {
        let _ = writeln!(out, "  caveat: {caveat}");
    }
    out.push('\n');
}

fn render_wcet_info(out: &mut String, wcet: &CfgWcetInfo) {
    kv_indent(out, "model", &wcet.model);
    if let Some(solver) = &wcet.solver {
        kv_indent(out, "solver", solver);
    }
    if let Some(bound) = wcet.default_loop_bound {
        kv_indent(out, "default loop bound", &bound.to_string());
    }
    if wcet.max_states > 0 {
        kv_indent(out, "max states", &wcet.max_states.to_string());
    }
    if let Some(frequency) = wcet.frequency_hz {
        kv_indent(out, "frequency", &format!("{frequency} Hz"));
    }
    if let Some(facts) = &wcet.flow_facts {
        kv_indent(
            out,
            "flow facts",
            &format!(
                "source {}, nonterminating loops bounded {}",
                facts.source,
                yes_no(facts.bound_nonterminating_loops)
            ),
        );
        for loop_ in &facts.loops {
            kv_indent(
                out,
                "loop bound",
                &format!("{} = {} ({})", loop_.header, loop_.bound, loop_.source),
            );
        }
    }
    kv_indent(
        out,
        "results",
        &format!(
            "{} bounded, {} partial, {} unbounded, {} unknown",
            wcet.functions_analyzed,
            wcet.functions_partial,
            wcet.functions_unbounded,
            wcet.functions_unknown
        ),
    );
}

fn render_wcet_root(out: &mut String, program: &ProgramCfg, root: &CfgWcetRoot) {
    let name = root
        .name
        .as_deref()
        .map_or_else(|| function_name(program, &root.function), ToOwned::to_owned);
    let cost = wcet_cost(root.status, root.cycles, root.time_ns);
    let _ = writeln!(out, "  * {}  {name}: {cost}", serde_name(&root.kind));
    if !root.path.is_empty() {
        let _ = writeln!(out, "      path: {}", join_block_path(&root.path));
    }
}

#[allow(clippy::too_many_lines)]
fn render_system_model(out: &mut String, model: Option<&CfgSystemModelInfo>) {
    section(out, "layered system model");
    let Some(model) = model else {
        let _ = writeln!(out, "  (not analyzed)\n");
        return;
    };
    kv(out, "model", &model.model);
    kv(out, "scope", &model.bound.scope);
    kv(out, "status", &serde_name(&model.bound.status));
    kv(
        out,
        "topology",
        &format!("{} core(s), analyzed core {}", model.cores, model.core_id),
    );
    if let Some(cycles) = model.bound.cycles {
        kv(out, "cycles", &format!("{cycles:.1} cycle(s)"));
    }
    if let Some(time) = model.bound.time_ns {
        kv(out, "time", &format!("{time:.1} ns"));
    }
    kv(
        out,
        "max activations",
        &model.bound.max_activations.to_string(),
    );
    if let Some(horizon) = model.horizon_ns {
        kv(out, "horizon", &format!("{horizon} ns"));
    }
    for place in model.places.iter().filter(|place| place.kind == "budget") {
        let _ = writeln!(
            out,
            "  * resource budget {} {}/{} unit(s)",
            place.id, place.tokens, place.capacity
        );
    }
    kv(
        out,
        "model size",
        &format!(
            "{} task(s), {} place(s), {} transition(s), {} dependency(ies), {} link(s)",
            model.tasks.len(),
            model.places.len(),
            model.transitions.len(),
            model.dependencies.len(),
            model.links.len()
        ),
    );
    for link in &model.links {
        let _ = writeln!(
            out,
            "  * link {} {} -> {} x{}",
            link.kind, link.from, link.to, link.count
        );
    }
    if let Some(petri) = &model.petri {
        kv(out, "petri solver", &petri.solver);
        kv(out, "petri relaxation", &petri.relaxation);
        kv(out, "petri status", &petri.status);
        if let Some(objective) = petri.objective {
            kv(out, "petri objective", &format!("{objective:.1} cycle(s)"));
        }
        for firing in petri.firing.iter().take(16) {
            let _ = writeln!(out, "  * fire {} x{}", firing.transition, firing.fires);
        }
        if petri.firing.len() > 16 {
            let _ = writeln!(
                out,
                "  ... {} more firing count(s)",
                petri.firing.len().saturating_sub(16)
            );
        }
    }
    kv(out, "response model", &model.response.model);
    for response in model.response.tasks.iter().take(16) {
        let deadline = response
            .deadline_ns
            .map_or_else(|| "none".to_owned(), |deadline| format!("{deadline} ns"));
        let time = response
            .time_ns
            .map_or_else(|| "-".to_owned(), |time| format!("{time:.1} ns"));
        let missed = if response.deadline_missed {
            " DEADLINE-MISS"
        } else {
            ""
        };
        let _ = writeln!(
            out,
            "  * response {} {} time {time}, deadline {deadline}{missed}",
            response.task, response.status
        );
        if let Some(reason) = &response.reason {
            let _ = writeln!(out, "    reason: {reason}");
        }
    }
    if model.response.tasks.len() > 16 {
        let _ = writeln!(
            out,
            "  ... {} more response result(s)",
            model.response.tasks.len().saturating_sub(16)
        );
    }
    for caveat in &model.response.caveats {
        let _ = writeln!(out, "    caveat: {caveat}");
    }
    if let Some(timed) = &model.timed {
        kv(out, "timed model", &timed.model);
        kv(out, "timed slot", &format!("{} ns", timed.slot_ns));
        kv(
            out,
            "timed horizon",
            &format!("{} slot(s)", timed.horizon_slots),
        );
        kv(out, "timed status", &timed.status);
        kv(
            out,
            "timed size",
            &format!(
                "{} activation(s), {} execution slot(s), {} variable(s)",
                timed.activations, timed.execution_slots, timed.variables
            ),
        );
        for caveat in &timed.caveats {
            let _ = writeln!(out, "    caveat: {caveat}");
        }
    }
    for task in model.tasks.iter().take(16) {
        let name = task
            .name
            .as_deref()
            .unwrap_or_else(|| task.function.as_str());
        let _ = writeln!(
            out,
            "  * task {} {} [{}] x{} {}",
            task.id,
            name,
            serde_name(&task.kind),
            task.activation_bound,
            wcet_cost(task.status, task.cycles, task.time_ns)
        );
        if let Some(period) = task.period_ns {
            let offset = task.release_offset_ns.unwrap_or(0);
            let jitter = task.release_jitter_ns.unwrap_or(0);
            let _ = writeln!(
                out,
                "    period {period} ns, offset {offset} ns, jitter {jitter} ns"
            );
        }
    }
    if model.tasks.len() > 16 {
        let _ = writeln!(
            out,
            "  ... {} more task(s)",
            model.tasks.len().saturating_sub(16)
        );
    }
    for assumption in &model.bound.assumptions {
        let _ = writeln!(out, "  assumption: {assumption}");
    }
    for caveat in &model.caveats {
        let _ = writeln!(out, "  caveat: {caveat}");
    }
    out.push('\n');
}

fn render_calls(out: &mut String, program: &ProgramCfg, selected: &[&CfgFunction]) {
    section(out, "interprocedural call graph");
    let selected_ids: BTreeSet<&FunctionId> =
        selected.iter().map(|function| &function.id).collect();
    let calls: Vec<_> = program
        .calls
        .iter()
        .filter(|call| selected_ids.contains(&call.caller))
        .collect();
    if calls.is_empty() {
        let _ = writeln!(out, "  (none)\n");
        return;
    }
    for call in calls {
        let caller = function_name(program, &call.caller);
        let target_name = call
            .callee
            .as_ref()
            .map_or_else(|| "???".to_owned(), |target| function_name(program, target));
        let flags = call_flags(call);
        let _ = writeln!(
            out,
            "  {caller} -> {target_name} @ {}  [{flags}]",
            address(call.site.get())
        );
        if !call.candidates.is_empty() {
            let candidates: Vec<String> = call
                .candidates
                .iter()
                .map(|candidate| function_name(program, candidate))
                .collect();
            let _ = writeln!(out, "      candidates: {}", candidates.join(", "));
        }
    }
    out.push('\n');
}

fn render_concurrency(out: &mut String, program: &ProgramCfg, selected: &[&CfgFunction]) {
    section(out, "concurrency annotations");
    let selected_ids: BTreeSet<&FunctionId> =
        selected.iter().map(|function| &function.id).collect();
    let sites: Vec<_> = program
        .concurrency
        .iter()
        .filter(|site| selected_ids.contains(&site.function))
        .collect();
    if sites.is_empty() {
        let _ = writeln!(out, "  (none)\n");
        return;
    }
    for site in sites {
        let function = function_name(program, &site.function);
        let _ = writeln!(
            out,
            "  {function} @ {}: {}  [confidence {}]",
            address(site.site.get()),
            describe_concurrency(program, &site.operation),
            serde_name(&site.confidence)
        );
    }
    out.push('\n');
}

fn render_locks(out: &mut String, program: &ProgramCfg, selected: &[&CfgFunction]) {
    section(out, "lock events");
    let selected_ids: BTreeSet<&FunctionId> =
        selected.iter().map(|function| &function.id).collect();
    let locks: Vec<_> = program
        .locks
        .iter()
        .filter(|lock| selected_ids.contains(&lock.function))
        .collect();
    if locks.is_empty() {
        let _ = writeln!(out, "  (none)\n");
        return;
    }
    for lock in locks {
        render_lock(out, program, lock);
    }
    out.push('\n');
}

fn render_lock(out: &mut String, program: &ProgramCfg, lock: &CfgLockEvent) {
    let function = function_name(program, &lock.function);
    let inline = if lock.inlined { ", inlined" } else { "" };
    let _ = writeln!(
        out,
        "  {function} @ {}: {} {} via {}::{}{inline}  [confidence {}]",
        address(lock.site.get()),
        serde_name(&lock.operation),
        serde_name(&lock.lock_kind),
        lock.runtime,
        lock.api,
        serde_name(&lock.confidence)
    );
    if let Some(extent) = lock.extent {
        kv_indent(
            out,
            "extent",
            &format!("{}..{}", address(lock.site.get()), extent),
        );
    }
    if let Some(call_site) = &lock.call_site {
        kv_indent(out, "call site", &format_source(call_site));
    }
}

fn render_diagnostics(out: &mut String, program: &ProgramCfg, selected: &[&CfgFunction]) {
    section(out, "diagnostics");
    let selected_ids: BTreeSet<&FunctionId> =
        selected.iter().map(|function| &function.id).collect();
    let diagnostics: Vec<&Diagnostic> = scoped_diagnostics(program, &selected_ids).collect();
    let omitted = program.diagnostics.len().saturating_sub(diagnostics.len());
    if diagnostics.is_empty() {
        let _ = writeln!(out, "  (none)");
    }
    for diagnostic in &diagnostics {
        let location = diagnostic.function.as_ref().map_or_else(
            || {
                diagnostic
                    .site
                    .map_or_else(String::new, |site| format!(" @ {site}"))
            },
            |function| format!(" in {}", function_name(program, function)),
        );
        let _ = writeln!(
            out,
            "  [{}] {}{location}: {}",
            serde_name(&diagnostic.severity),
            diagnostic.code,
            diagnostic.message
        );
    }
    if omitted > 0 {
        let _ = writeln!(
            out,
            "  ({omitted} diagnostic(s) outside the selected functions omitted)"
        );
    }
    out.push('\n');
}

fn render_function(
    out: &mut String,
    program: &ProgramCfg,
    function: &CfgFunction,
    include_instructions: bool,
) {
    let name = function_name(program, &function.id);
    let short_name = shorten_text(&name, 80);
    heading(out, &format!("function {short_name}"), '-');
    if short_name != name {
        kv(out, "name", &name);
    }
    kv(out, "id", function.id.as_str());
    kv(
        out,
        "address",
        &format!("{} ({} bytes)", address(function.address), function.size),
    );
    if !function.section.is_empty() {
        kv(out, "section", &function.section);
    }
    if let Some(source) = &function.source {
        kv(out, "source", &format_source(source));
    }
    kv(out, "language", &serde_name(&function.language));
    kv(out, "kind", &serde_name(&function.kind));
    if let Some(reason) = function.noreturn {
        kv(out, "noreturn", &serde_name(&reason));
    }
    if !function.symbols.is_empty() {
        kv(out, "symbols", &function.symbols.join(", "));
    }
    if !function.inline_frames.is_empty() {
        kv(
            out,
            "inline frames",
            &function.inline_frames.len().to_string(),
        );
    }
    let cfg = &function.cfg;
    let entry = cfg.entry.map(|entry| cfg.graph[entry].id.to_string());
    kv(out, "entry", entry.as_deref().unwrap_or("(not analyzed)"));
    kv(out, "blocks", &cfg.blocks_by_address.len().to_string());
    kv(out, "edges", &cfg.graph.edge_count().to_string());
    let calls = cfg
        .blocks_by_address
        .values()
        .map(|node| cfg.graph[*node].calls.len())
        .sum::<usize>();
    kv(out, "call sites", &calls.to_string());
    render_function_wcet(out, function, program.wcet.is_some());
    if cfg.blocks_by_address.is_empty() {
        let _ = writeln!(
            out,
            "\n  (no machine code in this image; external import or logical task entry)\n"
        );
        return;
    }
    out.push('\n');
    for node in cfg.blocks_by_address.values() {
        render_block(out, program, cfg, *node, include_instructions);
    }
}

fn render_function_wcet(out: &mut String, function: &CfgFunction, analysis_enabled: bool) {
    let Some(wcet) = function.wcet.as_ref() else {
        let message = if analysis_enabled {
            "not available (function has no local code or was excluded from WCET analysis)"
        } else {
            "not analyzed (requires a [wcet] board profile)"
        };
        kv(out, "wcet", message);
        return;
    };
    kv(out, "wcet", &format_wcet_summary(wcet));
    if !wcet.path.is_empty() {
        kv(out, "wcet path", &join_block_path(&wcet.path));
    }
    if let Some(reason) = &wcet.reason {
        kv(out, "wcet reason", reason);
    }
    if wcet.unresolved_calls > 0 || wcet.external_calls > 0 {
        kv(
            out,
            "wcet unknowns",
            &format!(
                "{} unresolved call site(s), {} external call(s)",
                wcet.unresolved_calls, wcet.external_calls
            ),
        );
    }
    if let Some(ipet) = &wcet.ipet {
        kv(out, "ipet solver", &ipet.solver);
        kv(out, "ipet status", &ipet.status);
        kv(
            out,
            "ipet objective",
            &format!("{:.1} cycle(s)", ipet.objective),
        );
        if !ipet.blocks.is_empty() {
            let _ = writeln!(out, "ipet block counts:");
            for block in ipet.blocks.iter().take(32) {
                let _ = writeln!(out, "  {} x{}", block.block, block.executions);
            }
            if ipet.blocks.len() > 32 {
                let _ = writeln!(out, "  ... {} more block count(s)", ipet.blocks.len() - 32);
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn render_block(
    out: &mut String,
    program: &ProgramCfg,
    cfg: &FunctionCfg,
    node: petgraph::stable_graph::NodeIndex,
    include_instructions: bool,
) {
    let block = &cfg.graph[node];
    let _ = writeln!(
        out,
        "  block {}  {}  {}B  cycles {}  terminator={}",
        block.id,
        address(block.address),
        block.size,
        format_cost(block.cycles),
        serde_name(&block.terminator)
    );
    if include_instructions {
        if block.instructions.is_empty() {
            let _ = writeln!(out, "    instructions: (none decoded)");
        } else {
            let _ = writeln!(out, "    instructions:");
            for instruction in &block.instructions {
                let source = instruction
                    .source
                    .as_ref()
                    .map_or_else(String::new, |source| {
                        format!("  [{}]", format_source(source))
                    });
                let flags = instruction_flags(instruction);
                let flags = if flags.is_empty() {
                    String::new()
                } else {
                    format!("  [{flags}]")
                };
                let _ = writeln!(
                    out,
                    "      {}  {}B  {}{flags}{source}",
                    address(instruction.address),
                    instruction.size,
                    instruction.text
                );
            }
        }
    } else {
        let _ = writeln!(
            out,
            "    instructions: {} decoded (omitted by --no-cfg-instructions)",
            block.instructions.len()
        );
    }
    if !block.calls.is_empty() {
        let _ = writeln!(out, "    calls:");
        for call in &block.calls {
            render_call_site(out, program, call);
        }
    }
    let edges = sorted_edges(cfg, node);
    if !edges.is_empty() {
        let _ = writeln!(out, "    edges:");
        for edge in edges {
            let target = &cfg.graph[edge.target()];
            let weight = edge.weight();
            let conditional = if weight.conditional {
                ", conditional"
            } else {
                ""
            };
            let _ = writeln!(
                out,
                "      -> {} {}  @{}{conditional}",
                target.id,
                serde_name(&weight.kind),
                address(weight.site)
            );
        }
    }
    render_block_annotations(out, block);
}

fn render_call_site(out: &mut String, program: &ProgramCfg, call: &CfgCallSite) {
    let target = call_target(program, call);
    let flags = call_site_flags(call);
    let _ = writeln!(out, "      @{} -> {target}  [{flags}]", address(call.site));
}

fn render_block_annotations(out: &mut String, block: &CfgBlock) {
    if let Some(cache) = block.cache.as_ref() {
        let fallback = if cache.fallback { ", fallback" } else { "" };
        let _ = writeln!(
            out,
            "    icache: {} fetch(es), misses {}..{}, {} state(s){fallback}",
            cache.fetches, cache.misses_min, cache.misses_max, cache.entry_states
        );
    }
    if let Some(cache) = block.data_cache.as_ref() {
        let fallback = if cache.fallback { ", fallback" } else { "" };
        let _ = writeln!(
            out,
            "    dcache: {} access(es), {} resolved, {} unresolved, misses {}..{}, {} state(s){fallback}",
            cache.memory_accesses,
            cache.resolved_memory_accesses,
            cache.unresolved_memory_accesses,
            cache.misses_min,
            cache.misses_max,
            cache.entry_states
        );
    }
    if let Some(prediction) = block.branch_prediction.as_ref() {
        let fallback = if prediction.fallback {
            ", fallback"
        } else {
            ""
        };
        let _ = writeln!(
            out,
            "    branch: @{}, mispredicts {}..{}, {} state(s){fallback}",
            address(prediction.site.get()),
            prediction.mispredicts_min,
            prediction.mispredicts_max,
            prediction.entry_states
        );
    }
    if let Some(memory) = block.data_memory.as_ref() {
        let _ = writeln!(
            out,
            "    data-memory: {} access(es), {} mapped, {} unmapped, {} wait cycle(s)",
            memory.accesses, memory.mapped_accesses, memory.unmapped_accesses, memory.wait_cycles
        );
    }
    if let Some(multicore) = block.multicore.as_ref() {
        let _ = writeln!(
            out,
            "    multicore: {} read(s), {} write(s), {} fetch(es), {} interference cycle(s)",
            multicore.data_read_accesses,
            multicore.data_write_accesses,
            multicore.instruction_fetches,
            multicore.interference_cycles
        );
    }
}

fn sorted_edges(
    cfg: &FunctionCfg,
    node: petgraph::stable_graph::NodeIndex,
) -> Vec<petgraph::stable_graph::EdgeReference<'_, crate::cfg::CfgEdge>> {
    let mut edges: Vec<_> = cfg.graph.edges(node).collect();
    edges.sort_by_key(|edge| {
        (
            cfg.graph[edge.target()].address,
            edge.weight().site,
            serde_name(&edge.weight().kind),
        )
    });
    edges
}

fn describe_concurrency(program: &ProgramCfg, operation: &CfgConcurrencyKind) -> String {
    match operation {
        CfgConcurrencyKind::Spawn {
            runtime,
            api,
            name,
            entry,
            candidates,
            spawn_kind,
        } => {
            let mut text = format!("spawn {} via {runtime}::{api}", serde_name(spawn_kind));
            if let Some(name) = name {
                let _ = write!(text, " name={name}");
            }
            if let Some(entry) = entry {
                let _ = write!(text, " entry={}", function_name(program, entry));
            }
            if !candidates.is_empty() {
                let names: Vec<String> = candidates
                    .iter()
                    .map(|candidate| function_name(program, candidate))
                    .collect();
                let _ = write!(text, " candidates=[{}]", names.join(", "));
            }
            text
        }
        CfgConcurrencyKind::Join {
            join_kind,
            entry,
            candidates,
        } => {
            let mut text = format!("join {}", serde_name(join_kind));
            if let Some(entry) = entry {
                let _ = write!(text, " entry={}", function_name(program, entry));
            }
            if !candidates.is_empty() {
                let names: Vec<String> = candidates
                    .iter()
                    .map(|candidate| function_name(program, candidate))
                    .collect();
                let _ = write!(text, " candidates=[{}]", names.join(", "));
            }
            text
        }
        CfgConcurrencyKind::Await {
            await_kind,
            target,
            candidates,
        } => {
            let mut text = format!("await {}", serde_name(await_kind));
            if let Some(target) = target {
                let _ = write!(text, " target={}", function_name(program, target));
            }
            if !candidates.is_empty() {
                let names: Vec<String> = candidates
                    .iter()
                    .map(|candidate| function_name(program, candidate))
                    .collect();
                let _ = write!(text, " candidates=[{}]", names.join(", "));
            }
            text
        }
        CfgConcurrencyKind::CallbackBind {
            callback,
            runtime,
            api,
        } => format!(
            "callback bind via {runtime}::{api} -> {}",
            function_name(program, callback)
        ),
        CfgConcurrencyKind::ScopeEnter {
            scope_kind,
            implicit_join,
        } => format!(
            "scope enter {} (implicit_join={})",
            serde_name(scope_kind),
            yes_no(*implicit_join)
        ),
        CfgConcurrencyKind::ScopeExit { scope_kind } => {
            format!("scope exit {}", serde_name(scope_kind))
        }
    }
}

fn scoped_diagnostics<'a>(
    program: &'a ProgramCfg,
    selected_ids: &'a BTreeSet<&FunctionId>,
) -> impl Iterator<Item = &'a Diagnostic> + 'a {
    program.diagnostics.iter().filter(move |diagnostic| {
        diagnostic
            .function
            .as_ref()
            .is_none_or(|function| selected_ids.contains(function))
    })
}

fn call_target(program: &ProgramCfg, call: &CfgCallSite) -> String {
    if call.null_target {
        return "null target".to_owned();
    }
    if call.unresolved && call.target.is_none() && call.candidates.is_empty() {
        return "???".to_owned();
    }
    if let Some(target) = call.target_function.as_ref() {
        return function_name(program, target);
    }
    if !call.candidates.is_empty() {
        let names: Vec<String> = call
            .candidates
            .iter()
            .map(|candidate| {
                candidate.target_function.as_ref().map_or_else(
                    || address(candidate.target),
                    |target| function_name(program, target),
                )
            })
            .collect();
        return format!("{{{}}}", names.join(", "));
    }
    call.target.map_or_else(|| "???".to_owned(), address)
}

fn call_site_flags(call: &CfgCallSite) -> String {
    let mut flags = Vec::new();
    if call.direct {
        flags.push("direct");
    }
    if call.tail {
        flags.push("tail");
    }
    if call.conditional {
        flags.push("conditional");
    }
    if call.heuristic {
        flags.push("heuristic");
    }
    if call.unresolved {
        flags.push("unresolved");
    }
    if call.null_target {
        flags.push("null-target");
    }
    if call.noreturn {
        flags.push("noreturn");
    }
    if flags.is_empty() {
        "no flags".to_owned()
    } else {
        flags.join(", ")
    }
}

fn call_flags(call: &CfgCallEdge) -> String {
    let confidence = serde_name(&call.confidence);
    let mut flags: Vec<&str> = Vec::new();
    if call.direct {
        flags.push("direct");
    }
    if call.tail {
        flags.push("tail");
    }
    if call.conditional {
        flags.push("conditional");
    }
    if call.heuristic {
        flags.push("heuristic");
    }
    if call.unresolved {
        flags.push("unresolved");
    }
    flags.push(&confidence);
    flags.join(", ")
}

fn instruction_flags(instruction: &CfgInstruction) -> String {
    let mut flags = Vec::new();
    if instruction.is_call {
        flags.push("call");
    }
    if instruction.is_jump {
        flags.push("jump");
    }
    if instruction.is_return {
        flags.push("return");
    }
    if instruction.is_conditional {
        flags.push("conditional");
    }
    flags.join(", ")
}

fn format_wcet_summary(wcet: &CfgFunctionWcet) -> String {
    let status = serde_name(&wcet.status);
    let cycles = wcet.cycles.map_or_else(
        || "unbounded".to_owned(),
        |cycles| format!("{cycles:.1} cycle(s)"),
    );
    let time = wcet
        .time_ns
        .map_or_else(String::new, |time| format!(", {time:.1} ns"));
    let reason = wcet
        .reason
        .as_ref()
        .map_or_else(String::new, |reason| format!(" ({reason})"));
    format!("{status}, {cycles}{time}{reason}")
}

fn wcet_cost(status: CfgWcetStatus, cycles: Option<f64>, time_ns: Option<f64>) -> String {
    let status = serde_name(&status);
    match (cycles, time_ns) {
        (Some(cycles), Some(time)) => format!("{status}, {cycles:.1} cycle(s), {time:.1} ns"),
        (Some(cycles), None) => format!("{status}, {cycles:.1} cycle(s)"),
        (None, _) => status,
    }
}

fn join_block_path(path: &[elf2tdg_schema::BlockId]) -> String {
    path.iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(" -> ")
}

fn format_cost(cycles: Option<CostRange>) -> String {
    match cycles {
        Some(range) if (range.min - range.max).abs() < f64::EPSILON => format_number(range.min),
        Some(range) => format!("{}..{}", format_number(range.min), format_number(range.max)),
        None => "?".to_owned(),
    }
}

fn format_number(value: f64) -> String {
    if (value.fract()).abs() < f64::EPSILON {
        format!("{value:.0}")
    } else {
        format!("{value:.1}")
    }
}

fn format_source(source: &SourceLoc) -> String {
    source.column.map_or_else(
        || format!("{}:{}", source.file, source.line),
        |column| format!("{}:{}:{}", source.file, source.line, column),
    )
}

fn function_name(program: &ProgramCfg, id: &FunctionId) -> String {
    program.function(id).map_or_else(
        || id.to_string(),
        |function| normalize_crate_hashes(&function.primary_name),
    )
}

fn address(value: u64) -> String {
    Addr::new(value).to_string()
}

fn serde_name<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
        .unwrap_or_else(|| "unknown".to_owned())
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn heading(out: &mut String, title: &str, underline: char) {
    let _ = writeln!(out, "{title}");
    let width = title.chars().count().min(100);
    let _ = writeln!(out, "{}", underline.to_string().repeat(width));
    out.push('\n');
}

fn shorten_text(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_owned();
    }
    let mut shortened: String = value.chars().take(max_chars.saturating_sub(3)).collect();
    shortened.push_str("...");
    shortened
}

fn section(out: &mut String, title: &str) {
    let _ = writeln!(out, "{title}");
    let _ = writeln!(out, "{}", "-".repeat(title.chars().count()));
}

fn kv(out: &mut String, key: &str, value: &str) {
    let _ = writeln!(out, "{key:<16} {value}");
}

fn kv_indent(out: &mut String, key: &str, value: &str) {
    let _ = writeln!(out, "  {key:<14} {value}");
}

#[cfg(test)]
mod tests {
    use super::{format_cost, format_number, heading};
    use elf2tdg_schema::CostRange;

    #[test]
    fn cost_ranges_are_rendered_compactly() {
        assert_eq!(format_cost(Some(CostRange::exact(2.0))), "2");
        assert_eq!(format_cost(Some(CostRange::new(1.0, 3.0))), "1..3");
        assert_eq!(format_cost(None), "?");
    }

    #[test]
    fn numbers_drop_zero_fraction() {
        assert_eq!(format_number(3.0), "3");
        assert_eq!(format_number(3.25), "3.2");
    }

    #[test]
    fn headings_use_the_title_width() {
        let mut out = String::new();
        heading(&mut out, "abc", '-');
        assert_eq!(out, "abc\n---\n\n");
    }
}
