//! Human- and machine-readable TDG renderers.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use elf2tdg_schema::{
    AwaitTarget, Confidence, Context, ContextKind, Edge, Function, FunctionKind, JoinTarget,
    ScopeKind, SpawnTarget, Tdg,
};

use crate::error::{Error, Result};
use crate::rules::normalize_crate_hashes;

/// Which graph projection a renderer should emit.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Projection {
    /// The complete call graph plus all concurrency-control relations.
    #[default]
    Full,
    /// Contexts, scopes and concurrency-control edges; ordinary calls are
    /// omitted so the diagram remains readable for large Rust binaries.
    Concurrency,
}

/// Options shared by the graph renderers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GraphOptions {
    /// Graph projection.
    pub projection: Projection,
    /// Append a node/edge legend.
    pub legend: bool,
}

impl GraphOptions {
    /// Concurrency projection with a legend; the documented example view.
    #[must_use]
    pub const fn concurrency_with_legend() -> Self {
        Self {
            projection: Projection::Concurrency,
            legend: true,
        }
    }
}

#[derive(Debug)]
struct Visible<'a> {
    projection: Projection,
    functions: BTreeSet<&'a str>,
}

impl<'a> Visible<'a> {
    fn build(tdg: &'a Tdg, projection: Projection) -> Self {
        let mut functions = BTreeSet::new();
        if projection == Projection::Concurrency {
            for context in &tdg.contexts {
                functions.insert(context.entry.as_str());
            }
            for edge in &tdg.edges {
                match edge {
                    Edge::Spawn { from_function, .. } | Edge::Join { from_function, .. } => {
                        functions.insert(from_function.as_str());
                    }
                    Edge::Await {
                        target: AwaitTarget::Function { function },
                        ..
                    } => {
                        functions.insert(function.as_str());
                    }
                    Edge::CallbackBind {
                        from_function,
                        callback,
                        ..
                    } => {
                        functions.insert(from_function.as_str());
                        functions.insert(callback.as_str());
                    }
                    Edge::Call { .. }
                    | Edge::Await { .. }
                    | Edge::IsrActivate { .. }
                    | Edge::Preempts { .. } => {}
                }
            }
            for event in &tdg.locks {
                functions.insert(event.function.as_str());
            }
        }
        Self {
            projection,
            functions,
        }
    }

    fn function_visible(&self, function: &elf2tdg_schema::FunctionId) -> bool {
        self.projection == Projection::Full || self.functions.contains(function.as_str())
    }

    fn edge_visible(&self, edge: &Edge) -> bool {
        self.projection == Projection::Full || !matches!(edge, Edge::Call { .. })
    }
}

/// Serializes a TDG as pretty JSON.
///
/// # Errors
///
/// Returns an error if serialization fails.
pub fn render_json(tdg: &Tdg) -> Result<String> {
    serde_json::to_string_pretty(tdg).map_err(|error| Error::Serialize(error.to_string()))
}

/// Renders a Graphviz DOT graph combining the call graph and concurrency
/// edges.
#[must_use]
pub fn render_dot(tdg: &Tdg) -> String {
    render_dot_with(tdg, GraphOptions::default())
}

/// Renders a Graphviz DOT graph with an explicit projection and legend.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn render_dot_with(tdg: &Tdg, options: GraphOptions) -> String {
    let visible = Visible::build(tdg, options.projection);
    let label = match options.projection {
        Projection::Full => "elf2tdg TDG",
        Projection::Concurrency => "elf2tdg TDG (concurrency projection)",
    };
    let mut out = String::new();
    let _ = writeln!(out, "digraph tdg {{");
    let _ = writeln!(out, "  rankdir=LR;");
    let _ = writeln!(
        out,
        "  graph [fontname=\"Helvetica\", label=\"{label}\", labelloc=t];"
    );
    let _ = writeln!(
        out,
        "  node [fontname=\"Helvetica\", fontsize=10, shape=box, style=\"rounded,filled\", fillcolor=\"#ffffff\", color=\"#555555\"];"
    );
    let _ = writeln!(out, "  edge [fontname=\"Helvetica\", fontsize=9];");

    for function in &tdg.functions {
        if !visible.function_visible(&function.id) {
            continue;
        }
        let (color, border, style) = match function.kind {
            FunctionKind::Entry => ("#dff3df", "#555555", "rounded,filled"),
            FunctionKind::Isr => ("#fff1c9", "#555555", "rounded,filled"),
            FunctionKind::Kernel => ("#e8e0f5", "#555555", "rounded,filled"),
            FunctionKind::TaskEntry => ("#f4ecf7", "#7d3c98", "rounded,filled,dashed"),
            _ => ("#ffffff", "#555555", "rounded,filled"),
        };
        let _ = writeln!(
            out,
            "  \"{}\" [label=\"{}\", fillcolor=\"{}\", color=\"{}\", style=\"{}\"];",
            dot_escape(function.id.as_str()),
            dot_escape(&function_label(function)),
            color,
            border,
            style
        );
    }
    for context in &tdg.contexts {
        let inferred = context
            .ext
            .get("elf2tdg.logical_task")
            .is_some_and(|value| value.as_bool() == Some(true))
            || context
                .ext
                .get("elf2tdg.orphan_spawn_api")
                .is_some_and(|value| value.as_str().is_some());
        let (style, border) = if inferred {
            ("filled,dashed", "#7d3c98")
        } else {
            ("filled", "#444444")
        };
        let _ = writeln!(
            out,
            "  \"{}\" [label=\"{}\", shape=box, style=\"{style}\", fillcolor=\"{}\", color=\"{border}\"];",
            dot_escape(context.id.as_str()),
            dot_escape(&context_label(context)),
            context_color(context.kind)
        );
        let _ = writeln!(
            out,
            "  \"{}\" -> \"{}\" [label=\"entry\", style=dotted, color=\"#4a6fa5\", fontcolor=\"#4a6fa5\"];",
            dot_escape(context.id.as_str()),
            dot_escape(context.entry.as_str())
        );
    }

    let edge_by_id: BTreeMap<String, &Edge> = tdg
        .edges
        .iter()
        .map(|edge| (edge.id().as_str().to_owned(), edge))
        .collect();
    for scope in &tdg.scopes {
        let _ = writeln!(
            out,
            "  \"{}\" [label=\"{} scope\\n0x{:x}\\n{} members\", shape=ellipse, style=\"dashed,filled\", fillcolor=\"#eafaf1\", color=\"#1e8449\"];",
            dot_escape(scope.id.as_str()),
            scope_kind_name(scope.kind),
            scope.enter_site.get(),
            scope.members.len()
        );
        let _ = writeln!(
            out,
            "  \"{}\" -> \"{}\" [label=\"in\", style=dotted, color=\"#1e8449\", fontcolor=\"#1e8449\"];",
            dot_escape(scope.id.as_str()),
            dot_escape(scope.entering_context.as_str())
        );
        for member in &scope.members {
            let Some(Edge::Spawn {
                target: SpawnTarget::Context { context, .. },
                ..
            }) = edge_by_id.get(member.as_str())
            else {
                continue;
            };
            let _ = writeln!(
                out,
                "  \"{}\" -> \"{}\" [label=\"member\", style=dotted, color=\"#1e8449\"];",
                dot_escape(scope.id.as_str()),
                dot_escape(context.as_str())
            );
        }
    }

    for edge in &tdg.edges {
        if !visible.edge_visible(edge) {
            continue;
        }
        match edge {
            Edge::Call {
                caller,
                callee,
                tail,
                ..
            } => {
                let _ = writeln!(
                    out,
                    "  \"{}\" -> \"{}\" [label=\"{}\", color=\"#777777\", style=\"{}\"];",
                    dot_escape(caller.as_str()),
                    dot_escape(callee.as_str()),
                    if *tail { "tail" } else { "call" },
                    if *tail { "dashed" } else { "solid" }
                );
            }
            Edge::Spawn {
                id,
                from_function,
                target,
                spawn_kind,
                confidence,
                ..
            } => {
                let (node, label) = match target {
                    SpawnTarget::Context { context, .. } => (
                        dot_escape(context.as_str()),
                        format!("spawn ({spawn_kind:?}){}", confidence_suffix(*confidence)),
                    ),
                    SpawnTarget::Opaque { candidates } => {
                        opaque_node(&mut out, id.as_str(), "spawn", candidates.len());
                        (
                            dot_escape(&format!("opaque:{}", id.as_str())),
                            "spawn?".to_owned(),
                        )
                    }
                };
                let _ = writeln!(
                    out,
                    "  \"{}\" -> \"{node}\" [label=\"{label}\", color=\"#c0392b\", fontcolor=\"#c0392b\", style=\"{}\"];",
                    dot_escape(from_function.as_str()),
                    confidence_style(*confidence)
                );
            }
            Edge::Join {
                id,
                from_function,
                target,
                join_kind,
                confidence,
                ..
            } => {
                let (node, label) = match target {
                    JoinTarget::Context { context } => (
                        dot_escape(context.as_str()),
                        format!("{join_kind:?}{}", confidence_suffix(*confidence)),
                    ),
                    JoinTarget::Opaque { candidates } => {
                        opaque_node(&mut out, id.as_str(), "join", candidates.len());
                        (
                            dot_escape(&format!("opaque:{}", id.as_str())),
                            format!("{join_kind:?}?"),
                        )
                    }
                };
                let _ = writeln!(
                    out,
                    "  \"{}\" -> \"{node}\" [label=\"{label}\", color=\"#2471a3\", fontcolor=\"#2471a3\", style=\"{}\"];",
                    dot_escape(from_function.as_str()),
                    confidence_style(*confidence)
                );
            }
            Edge::Await {
                id,
                from_context,
                target,
                await_kind,
                confidence,
                ..
            } => {
                let (node, label) = match target {
                    AwaitTarget::Context { context } => (
                        dot_escape(context.as_str()),
                        format!("{await_kind:?}{}", confidence_suffix(*confidence)),
                    ),
                    AwaitTarget::Function { function } => (
                        dot_escape(function.as_str()),
                        format!("{await_kind:?}{}", confidence_suffix(*confidence)),
                    ),
                    AwaitTarget::Opaque { candidates } => {
                        opaque_node(&mut out, id.as_str(), "await", candidates.len());
                        (
                            dot_escape(&format!("opaque:{}", id.as_str())),
                            format!("{await_kind:?}?"),
                        )
                    }
                };
                let _ = writeln!(
                    out,
                    "  \"{}\" -> \"{node}\" [label=\"{label}\", color=\"#7d3c98\", fontcolor=\"#7d3c98\", style=\"{}\"];",
                    dot_escape(from_context.as_str()),
                    confidence_style(*confidence)
                );
            }
            Edge::CallbackBind {
                from_function,
                callback,
                api,
                ..
            } => {
                let _ = writeln!(
                    out,
                    "  \"{}\" -> \"{}\" [label=\"callback {}\", color=\"#117a65\", fontcolor=\"#117a65\", style=dashed];",
                    dot_escape(from_function.as_str()),
                    dot_escape(callback.as_str()),
                    dot_escape(api)
                );
            }
            Edge::IsrActivate {
                to_context,
                vector,
                irq,
                ..
            } => {
                let vector_node = format!("vector:{vector}");
                let _ = writeln!(
                    out,
                    "  \"{vector_node}\" [label=\"vector {vector}\", shape=diamond, style=\"filled\", fillcolor=\"#fdebd0\", color=\"#b9770e\"];"
                );
                let label =
                    irq.map_or_else(|| format!("vector {vector}"), |irq| format!("IRQ {irq}"));
                let _ = writeln!(
                    out,
                    "  \"{vector_node}\" -> \"{}\" [label=\"{label}\", color=\"#b9770e\", fontcolor=\"#b9770e\", style=dashed];",
                    dot_escape(to_context.as_str())
                );
            }
            Edge::Preempts {
                from_context,
                to_context,
                ..
            } => {
                let _ = writeln!(
                    out,
                    "  \"{}\" -> \"{}\" [label=\"preempts\", color=\"#d68910\", fontcolor=\"#d68910\", style=dotted];",
                    dot_escape(from_context.as_str()),
                    dot_escape(to_context.as_str())
                );
            }
        }
    }

    for event in &tdg.locks {
        if !visible.function_visible(&event.function) {
            continue;
        }
        let node = format!("lock-node:{}", event.id.as_str());
        let label = format!(
            "lock {:?}\\n{}\\n0x{:x}",
            event.operation,
            event.api,
            event.site.get()
        );
        let _ = writeln!(
            out,
            "  \"{}\" [label=\"{}\", shape=note, style=\"filled\", fillcolor=\"#fef9e7\", color=\"#b7950b\"];",
            dot_escape(&node),
            dot_escape(&label)
        );
        let _ = writeln!(
            out,
            "  \"{}\" -> \"{}\" [label=\"lock\", style=dotted, color=\"#b7950b\", fontcolor=\"#b7950b\"];",
            dot_escape(event.function.as_str()),
            dot_escape(&node)
        );
    }

    if options.legend {
        write_dot_legend(&mut out, options.projection);
    }
    let _ = writeln!(out, "}}");
    out
}

fn write_dot_legend(out: &mut String, projection: Projection) {
    let _ = writeln!(out, "  subgraph cluster_legend {{");
    let _ = writeln!(
        out,
        "    label=\"Legend\"; labeljust=\"l\"; fontname=\"Helvetica\"; fontsize=11; style=\"rounded,dashed\"; color=\"#999999\";"
    );
    let _ = writeln!(
        out,
        "    legend_function [label=\"function\", fillcolor=\"#ffffff\"];"
    );
    let _ = writeln!(
        out,
        "    legend_context [label=\"context\", shape=box, style=\"filled\", fillcolor=\"#eaf2f8\", color=\"#444444\"];"
    );
    let _ = writeln!(
        out,
        "    legend_scope [label=\"scope\", shape=ellipse, style=\"dashed,filled\", fillcolor=\"#eafaf1\", color=\"#1e8449\"];"
    );
    let _ = writeln!(
        out,
        "    legend_opaque [label=\"opaque target\", shape=note, style=\"dashed,filled\", fillcolor=\"#f4f6f7\", color=\"#999999\"];"
    );
    let _ = writeln!(
        out,
        "    legend_vector [label=\"vector / IRQ\", shape=diamond, style=\"filled\", fillcolor=\"#fdebd0\", color=\"#b9770e\"];"
    );
    let _ = writeln!(
        out,
        "    legend_lock [label=\"lock event\", shape=note, style=\"filled\", fillcolor=\"#fef9e7\", color=\"#b7950b\"];"
    );
    let _ = writeln!(
        out,
        "    legend_function -> legend_lock [label=\"lock\", style=dotted, color=\"#b7950b\", fontcolor=\"#b7950b\"];"
    );
    let _ = writeln!(
        out,
        "    legend_note [label=\"contexts: startup green, main blue, thread purple,\\nISR orange, async lavender\\ndashed border = synthesized logical/orphan task\\nspawn/join/await: bold = high/medium confidence,\\ndashed = low/unknown, ? = low/unknown or unresolved\", shape=plaintext, fontsize=9];"
    );
    let _ = writeln!(
        out,
        "    legend_function -> legend_context [label=\"spawn\", color=\"#c0392b\", fontcolor=\"#c0392b\", style=bold];"
    );
    let _ = writeln!(
        out,
        "    legend_function -> legend_context [label=\"join\", color=\"#2471a3\", fontcolor=\"#2471a3\", style=bold];"
    );
    let _ = writeln!(
        out,
        "    legend_context -> legend_function [label=\"entry\", style=dotted, color=\"#4a6fa5\", fontcolor=\"#4a6fa5\"];"
    );
    let _ = writeln!(
        out,
        "    legend_scope -> legend_context [label=\"member\", style=dotted, color=\"#1e8449\", fontcolor=\"#1e8449\"];"
    );
    let _ = writeln!(
        out,
        "    legend_vector -> legend_context [label=\"ISR\", style=dashed, color=\"#b9770e\", fontcolor=\"#b9770e\"];"
    );
    if projection == Projection::Full {
        let _ = writeln!(
            out,
            "    legend_function -> legend_call_target [label=\"call\", style=solid, color=\"#777777\", fontcolor=\"#777777\"];"
        );
        let _ = writeln!(
            out,
            "    legend_call_target [label=\"function\", fillcolor=\"#ffffff\"];"
        );
    }
    let _ = writeln!(
        out,
        "    legend_context -> legend_opaque [label=\"await? / spawn?\", style=\"bold,dashed\", color=\"#7d3c98\", fontcolor=\"#7d3c98\"];"
    );
    let _ = writeln!(out, "  }}");
}

fn opaque_node(out: &mut String, edge_id: &str, kind: &str, candidate_count: usize) {
    let id = format!("opaque:{edge_id}");
    let label = if candidate_count == 0 {
        format!("{kind} opaque")
    } else {
        format!("{kind} opaque ({candidate_count} candidates)")
    };
    let _ = writeln!(
        out,
        "  \"{}\" [label=\"{}\", shape=note, style=\"dashed,filled\", fillcolor=\"#f4f6f7\", color=\"#999999\"];",
        dot_escape(&id),
        dot_escape(&label)
    );
}

fn dot_escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn function_label(function: &Function) -> String {
    let name = normalize_crate_hashes(&function.primary_name);
    let mut label = format!("{}\n{}", shorten(&name, 72), function.address);
    if let Some(timing) = &function.timing {
        let _ = write!(
            label,
            "\n{:.0}-{:.0} cyc",
            timing.static_block_sum_cycles.min, timing.static_block_sum_cycles.max
        );
    }
    label
}

fn context_label(context: &Context) -> String {
    let name = normalize_crate_hashes(&context.name);
    let shortened = shorten(&name, 72);
    let kind = context_kind_name(context.kind);
    if shortened == kind {
        shortened
    } else {
        format!("{shortened}\n{kind}")
    }
}

fn shorten(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_owned();
    }
    let mut shortened: String = value.chars().take(max_chars.saturating_sub(1)).collect();
    shortened.push_str("...");
    shortened
}

fn context_kind_name(kind: ContextKind) -> &'static str {
    match kind {
        ContextKind::Startup => "startup",
        ContextKind::Main => "main",
        ContextKind::Thread => "thread",
        ContextKind::ScopedThread => "scoped-thread",
        ContextKind::AsyncTask => "async-task",
        ContextKind::Executor => "executor",
        ContextKind::Isr => "isr",
        ContextKind::TimerCallback => "timer-callback",
        ContextKind::SystemWorkqueue => "system-workqueue",
        ContextKind::KernelThread => "kernel-thread",
        ContextKind::Unknown => "unknown",
    }
}

fn scope_kind_name(kind: ScopeKind) -> &'static str {
    match kind {
        ScopeKind::RustThreadScope => "thread",
        ScopeKind::RayonScope => "rayon",
        ScopeKind::RayonJoin => "rayon-join",
        ScopeKind::CrossbeamScope => "crossbeam",
        ScopeKind::OpenMpParallel => "openmp",
        ScopeKind::TbbTaskGroup => "tbb",
        ScopeKind::Unknown => "structured",
    }
}

fn confidence_suffix(confidence: Confidence) -> &'static str {
    match confidence {
        Confidence::Low | Confidence::Unknown => "?",
        Confidence::High | Confidence::Medium => "",
    }
}

fn confidence_style(confidence: Confidence) -> &'static str {
    match confidence {
        Confidence::Low | Confidence::Unknown => "bold,dashed",
        Confidence::High | Confidence::Medium => "bold",
    }
}

fn context_color(kind: ContextKind) -> &'static str {
    match kind {
        ContextKind::Startup => "#e8f6ef",
        ContextKind::Main => "#eaf2f8",
        ContextKind::Thread | ContextKind::ScopedThread => "#f4ecf7",
        ContextKind::AsyncTask | ContextKind::Executor => "#e8daef",
        ContextKind::Isr => "#fdebd0",
        ContextKind::TimerCallback => "#fcf3cf",
        ContextKind::SystemWorkqueue | ContextKind::KernelThread => "#e5e7e9",
        ContextKind::Unknown => "#f2f3f4",
    }
}

/// Renders a Mermaid flowchart of the TDG.
#[must_use]
pub fn render_mermaid(tdg: &Tdg) -> String {
    render_mermaid_with(tdg, GraphOptions::default())
}

/// Renders a Mermaid flowchart with an explicit projection and legend.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn render_mermaid_with(tdg: &Tdg, options: GraphOptions) -> String {
    let visible = Visible::build(tdg, options.projection);
    let mut ids = MermaidIds::default();
    let mut out = String::new();
    let _ = writeln!(out, "flowchart LR");
    if options.projection == Projection::Concurrency {
        let _ = writeln!(out, "  %% concurrency projection: call edges are omitted");
    }

    for function in &tdg.functions {
        if !visible.function_visible(&function.id) {
            continue;
        }
        let id = ids.id_for(function.id.as_str());
        let label = mermaid_escape(&function_label(function));
        let _ = writeln!(out, "  {id}[\"{label}\"]");
    }
    for context in &tdg.contexts {
        let id = ids.id_for(context.id.as_str());
        let label = mermaid_escape(&context_label(context));
        let _ = writeln!(out, "  {id}([\"{label}\"])");
    }
    for scope in &tdg.scopes {
        let id = ids.id_for(scope.id.as_str());
        let label = format!(
            "{} scope<br/>{} members",
            scope_kind_name(scope.kind),
            scope.members.len()
        );
        let _ = writeln!(out, "  {id}{{{{\"{label}\"}}}}");
        let _ = writeln!(
            out,
            "  {id} -.->|in| {}",
            ids.id_for(scope.entering_context.as_str())
        );
    }
    let edge_by_id: BTreeMap<String, &Edge> = tdg
        .edges
        .iter()
        .map(|edge| (edge.id().as_str().to_owned(), edge))
        .collect();
    for scope in &tdg.scopes {
        let scope_id = ids.id_for(scope.id.as_str());
        for member in &scope.members {
            let Some(Edge::Spawn {
                target: SpawnTarget::Context { context, .. },
                ..
            }) = edge_by_id.get(member.as_str())
            else {
                continue;
            };
            let _ = writeln!(
                out,
                "  {scope_id} -.->|member| {}",
                ids.id_for(context.as_str())
            );
        }
    }

    for context in &tdg.contexts {
        let _ = writeln!(
            out,
            "  {} -.->|entry| {}",
            ids.id_for(context.id.as_str()),
            ids.id_for(context.entry.as_str())
        );
    }

    for edge in &tdg.edges {
        if !visible.edge_visible(edge) {
            continue;
        }
        match edge {
            Edge::Call {
                caller,
                callee,
                tail,
                ..
            } => {
                let _ = writeln!(
                    out,
                    "  {} -->|{}| {}",
                    ids.id_for(caller.as_str()),
                    if *tail { "tail" } else { "call" },
                    ids.id_for(callee.as_str())
                );
            }
            Edge::Spawn {
                id,
                from_function,
                target,
                confidence,
                ..
            } => {
                let target_id = match target {
                    SpawnTarget::Context { context, .. } => ids.id_for(context.as_str()),
                    SpawnTarget::Opaque { candidates } => {
                        mermaid_opaque(&mut ids, &mut out, id.as_str(), "spawn", candidates.len())
                    }
                };
                let _ = writeln!(
                    out,
                    "  {} ==>|spawn{}| {target_id}",
                    ids.id_for(from_function.as_str()),
                    confidence_suffix(*confidence)
                );
            }
            Edge::Join {
                id,
                from_function,
                target,
                join_kind,
                confidence,
                ..
            } => {
                let target_id = match target {
                    JoinTarget::Context { context } => ids.id_for(context.as_str()),
                    JoinTarget::Opaque { candidates } => {
                        mermaid_opaque(&mut ids, &mut out, id.as_str(), "join", candidates.len())
                    }
                };
                let _ = writeln!(
                    out,
                    "  {} ==>|{join_kind:?}{}| {target_id}",
                    ids.id_for(from_function.as_str()),
                    confidence_suffix(*confidence)
                );
            }
            Edge::Await {
                id,
                from_context,
                target,
                await_kind,
                confidence,
                ..
            } => {
                let target_id = match target {
                    AwaitTarget::Context { context } => ids.id_for(context.as_str()),
                    AwaitTarget::Function { function } => ids.id_for(function.as_str()),
                    AwaitTarget::Opaque { candidates } => {
                        mermaid_opaque(&mut ids, &mut out, id.as_str(), "await", candidates.len())
                    }
                };
                let _ = writeln!(
                    out,
                    "  {} -.->|{await_kind:?}{}| {target_id}",
                    ids.id_for(from_context.as_str()),
                    confidence_suffix(*confidence)
                );
            }
            Edge::CallbackBind {
                from_function,
                callback,
                ..
            } => {
                let _ = writeln!(
                    out,
                    "  {} -.->|callback| {}",
                    ids.id_for(from_function.as_str()),
                    ids.id_for(callback.as_str())
                );
            }
            Edge::IsrActivate {
                to_context,
                vector,
                irq,
                ..
            } => {
                let vector_id = ids.id_for(&format!("vector:{vector}"));
                let label =
                    irq.map_or_else(|| format!("vector {vector}"), |irq| format!("IRQ {irq}"));
                let _ = writeln!(
                    out,
                    "  {vector_id}{{{{\"{label}\"}}}} -.->|ISR| {}",
                    ids.id_for(to_context.as_str())
                );
            }
            Edge::Preempts {
                from_context,
                to_context,
                ..
            } => {
                let _ = writeln!(
                    out,
                    "  {} -.->|preempts| {}",
                    ids.id_for(from_context.as_str()),
                    ids.id_for(to_context.as_str())
                );
            }
        }
    }
    for event in &tdg.locks {
        if !visible.function_visible(&event.function) {
            continue;
        }
        let key = format!("lock-node:{}", event.id.as_str());
        let is_new = !ids.ids.contains_key(&key);
        let node = ids.id_for(&key);
        if is_new {
            let label = mermaid_escape(&format!(
                "lock {:?}<br/>{}<br/>0x{:x}",
                event.operation,
                event.api,
                event.site.get()
            ));
            let _ = writeln!(out, "  {node}[\"{label}\"]");
        }
        let _ = writeln!(
            out,
            "  {} -.->|lock| {node}",
            ids.id_for(event.function.as_str())
        );
    }
    if options.legend {
        write_mermaid_legend(&mut out, options.projection);
    }
    out
}

fn write_mermaid_legend(out: &mut String, projection: Projection) {
    let _ = writeln!(out, "  subgraph Legend");
    let _ = writeln!(out, "    direction LR");
    let _ = writeln!(out, "    legend_function[\"function\"]");
    let _ = writeln!(out, "    legend_context([\"context\"])");
    let _ = writeln!(out, "    legend_scope{{{{\"scope\"}}}}");
    let _ = writeln!(out, "    legend_opaque{{{{\"opaque target\"}}}}");
    let _ = writeln!(out, "    legend_vector{{{{\"vector / IRQ\"}}}}");
    let _ = writeln!(out, "    legend_lock[\"lock event\"]");
    let _ = writeln!(out, "    legend_function -.->|lock| legend_lock");
    let _ = writeln!(out, "    legend_function ==>|spawn| legend_context");
    let _ = writeln!(out, "    legend_function ==>|join| legend_context");
    let _ = writeln!(out, "    legend_context -.->|entry| legend_function");
    let _ = writeln!(out, "    legend_scope -.->|member| legend_context");
    let _ = writeln!(out, "    legend_vector -.->|ISR| legend_context");
    let _ = writeln!(out, "    legend_context -.->|opaque| legend_opaque");
    if projection == Projection::Full {
        let _ = writeln!(out, "    legend_callee[\"function\"]");
        let _ = writeln!(out, "    legend_function -->|call| legend_callee");
    }
    let _ = writeln!(
        out,
        "    legend_note[\"bold = high/medium confidence<br/>dashed = low/unknown, ? = low/unknown or unresolved\"]"
    );
    let _ = writeln!(out, "  end");
}

#[derive(Default)]
struct MermaidIds {
    ids: BTreeMap<String, String>,
    next: usize,
}

impl MermaidIds {
    fn id_for(&mut self, key: &str) -> String {
        if let Some(id) = self.ids.get(key) {
            return id.clone();
        }
        let id = format!("n{}", self.next);
        self.next += 1;
        self.ids.insert(key.to_owned(), id.clone());
        id
    }
}

fn mermaid_opaque(
    ids: &mut MermaidIds,
    out: &mut String,
    edge_id: &str,
    kind: &str,
    candidates: usize,
) -> String {
    let key = format!("opaque:{edge_id}");
    let is_new = !ids.ids.contains_key(&key);
    let id = ids.id_for(&key);
    if is_new {
        let label = if candidates == 0 {
            format!("{kind} opaque")
        } else {
            format!("{kind} opaque ({candidates})")
        };
        let _ = writeln!(out, "  {id}{{{{\"{label}\"}}}}");
    }
    id
}

fn mermaid_escape(value: &str) -> String {
    value
        .replace('\n', "<br/>")
        .replace('"', "'")
        .replace('[', "(")
        .replace(']', ")")
        .replace('{', "(")
        .replace('}', ")")
        .replace('|', "/")
}

#[cfg(test)]
mod tests {
    use super::{
        GraphOptions, Projection, dot_escape, mermaid_escape, render_dot_with, render_mermaid_with,
    };
    use elf2tdg_schema::Tdg;

    fn sample_tdg() -> Tdg {
        serde_json::from_str(include_str!(
            "../../elf2tdg-schema/tests/data/sample-tdg.json"
        ))
        .expect("sample TDG must parse")
    }

    #[test]
    fn escapes_dot_labels() {
        assert_eq!(dot_escape("a\"b\\c\nd"), "a\\\"b\\\\c\\nd");
    }

    #[test]
    fn escapes_mermaid_labels() {
        assert_eq!(mermaid_escape("a\nb\"c[d]"), "a<br/>b'c(d)");
    }

    #[test]
    fn mermaid_output_uses_only_mermaid_syntax() {
        let mermaid = render_mermaid_with(
            &sample_tdg(),
            GraphOptions {
                projection: Projection::Full,
                legend: true,
            },
        );
        assert!(mermaid.starts_with("flowchart LR"));
        assert!(mermaid.contains("subgraph Legend"));
        assert!(!mermaid.contains("fillcolor"), "{mermaid}");
        assert!(!mermaid.contains("[label="), "{mermaid}");
        assert!(!mermaid.contains("shape="), "{mermaid}");
    }

    #[test]
    fn concurrency_projection_omits_call_edges() {
        let dot = render_dot_with(
            &sample_tdg(),
            GraphOptions {
                projection: Projection::Concurrency,
                legend: true,
            },
        );
        assert!(dot.contains("concurrency projection"));
        assert!(dot.contains("cluster_legend"));
        assert!(dot.contains("spawn"));
        assert!(dot.contains("ISR"));
        assert!(dot.contains("pthread_mutex_lock"));
        assert!(!dot.contains("[label=\"call\""), "{dot}");
        assert!(!dot.contains("[label=\"tail\""), "{dot}");
    }

    #[test]
    fn concurrency_mermaid_has_a_legend_and_no_dot_syntax() {
        let mermaid = render_mermaid_with(
            &sample_tdg(),
            GraphOptions {
                projection: Projection::Concurrency,
                legend: true,
            },
        );
        assert!(mermaid.contains("concurrency projection"));
        assert!(mermaid.contains("subgraph Legend"));
        assert!(mermaid.contains("==>|spawn|"));
        assert!(mermaid.contains("|lock|"));
        assert!(!mermaid.contains("fillcolor"), "{mermaid}");
        assert!(!mermaid.contains("[label="), "{mermaid}");
    }
}
