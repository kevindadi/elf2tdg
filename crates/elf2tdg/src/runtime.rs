//! Runtime API rule application.
//!
//! This pass turns resolved call edges into concurrency-control edges. Rust
//! closure types are recovered from monomorphized symbols so that resolved
//! `spawn` calls can point at the actual closure body and produce thread/task
//! contexts. APIs whose entry cannot be recovered are still emitted as opaque
//! spawn/join edges at the call site.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use elf2tdg_schema::{
    Addr, AwaitTarget, Confidence, Context, ContextId, ContextKind, Diagnostic, Edge, EdgeId,
    FrequencyDomainId, Function, FunctionId, JoinTarget, Scheduling, Scope, ScopeId, Severity,
    SpawnKind, SpawnTarget,
};

use crate::arch::DecodedInsn;
use crate::loader::Image;
use crate::origin;
use crate::rules::{self, Rule, RuleOp};

/// Applies runtime rules to an otherwise complete function/call graph.
///
/// New contexts, edges, scopes and diagnostics are appended in place.
#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::single_match_else
)]
pub fn apply(
    functions: &[Function],
    contexts: &mut Vec<Context>,
    edges: &mut Vec<Edge>,
    scopes: &mut Vec<Scope>,
    diagnostics: &mut Vec<Diagnostic>,
    max_diagnostics: usize,
    frequency_domain: Option<&FrequencyDomainId>,
    decoded_by_function: &BTreeMap<u64, Vec<DecodedInsn>>,
    image: &Image,
) -> Vec<Function> {
    let function_by_id: BTreeMap<&FunctionId, &Function> = functions
        .iter()
        .map(|function| (&function.id, function))
        .collect();
    let normalized_index = build_normalized_index(functions);
    let adjacency = build_adjacency(edges);
    let callers_by_function = build_callers(edges);
    let mut hits = collect_hits(edges, &function_by_id);
    hits.extend(collect_inline_hits(image, functions));
    dedup_closure_hits(&mut hits);
    hits.sort_by(|left, right| {
        (left.site, left.rule.api, left.caller.as_str()).cmp(&(
            right.site,
            right.rule.api,
            right.caller.as_str(),
        ))
    });
    hits.dedup_by(|left, right| {
        left.site == right.site && left.rule.api == right.rule.api && left.caller == right.caller
    });
    let mut sink = DiagnosticSink {
        diagnostics,
        keys: BTreeSet::new(),
        max: max_diagnostics,
    };

    let mut spawn_by_caller: BTreeMap<FunctionId, Vec<(ContextId, Addr)>> = BTreeMap::new();
    let mut pending_parents: Vec<(ContextId, FunctionId)> = Vec::new();
    let mut used_edge_ids: BTreeSet<String> = BTreeSet::new();
    let mut new_contexts: Vec<Context> = Vec::new();
    let mut logical_functions: Vec<Function> = Vec::new();

    for hit in hits.iter().filter(|hit| hit.rule.op == RuleOp::Spawn) {
        let mut resolution = hit
            .generic
            .as_deref()
            .map_or_else(Resolution::default, |candidate| {
                resolve_candidate(candidate, &normalized_index)
            });
        let mut entry_heuristic = false;
        let mut forwarded_sites: Vec<(FunctionId, Addr)> = Vec::new();
        if resolution.chosen.is_none()
            && hit.rule.runtime == "cpp-std"
            && let Some(callee) = hit
                .callee
                .as_ref()
                .and_then(|callee| function_by_id.get(callee).copied())
            && let Some(marker) = std::iter::once(callee.primary_name.as_str())
                .chain(callee.symbols.iter().map(String::as_str))
                .find_map(rules::cpp_callable_marker)
                .map(str::to_owned)
        {
            let mut candidates: Vec<&Function> = functions
                .iter()
                .filter(|function| function.id != callee.id)
                .filter(|function| {
                    let has_run = function.primary_name.contains("_M_run")
                        || function.symbols.iter().any(|name| name.contains("_M_run"));
                    let has_marker = function.primary_name.contains(&marker)
                        || function.symbols.iter().any(|name| name.contains(&marker));
                    has_run && has_marker
                })
                .collect();
            candidates.sort_by(|left, right| left.id.as_str().cmp(right.id.as_str()));
            candidates.dedup_by(|left, right| left.id == right.id);
            if candidates.len() == 1 {
                resolution.chosen = Some(candidates[0]);
                entry_heuristic = true;
                sink.push(
                    Severity::Info,
                    "cpp-callable-entry",
                    format!(
                        "recovered a conservative C++ thread entry from the {} callable marker",
                        hit.rule.api
                    ),
                    Some(&hit.caller),
                    Some(hit.site),
                );
            } else if candidates.len() > 1 {
                sink.push(
                    Severity::Info,
                    "cpp-callable-ambiguous",
                    format!(
                        "found {} candidate _M_run functions for {}; keeping the spawn target opaque",
                        candidates.len(),
                        hit.rule.api
                    ),
                    Some(&hit.caller),
                    Some(hit.site),
                );
            }
            if !candidates.is_empty() {
                resolution.candidates = candidates;
            }
        }
        if resolution.chosen.is_none()
            && let Some(entry_arg) = hit.rule.entry_arg
            && let Some(caller) = function_by_id.get(&hit.caller).copied()
            && let Some(decoded) = decoded_by_function.get(&caller.address.get())
            && let Some(target) =
                origin::resolve_argument_pointer(image, decoded, hit.site.get(), entry_arg)
            && let Some(function) = function_at_address(functions, target)
        {
            resolution.chosen = Some(function);
            resolution.candidates = vec![function];
            entry_heuristic = true;
        }
        if resolution.chosen.is_none()
            && let Some(entry_arg) = hit.rule.entry_arg
            && let Some(wrapper) = function_by_id.get(&hit.caller).copied()
            && let Some(decoded) = decoded_by_function.get(&wrapper.address.get())
            && let Some(forwarded) =
                origin::forwarded_argument_index(image, decoded, hit.site.get(), entry_arg)
            && let Some(sites) = callers_by_function.get(&hit.caller)
        {
            let mut candidates: Vec<(&Function, FunctionId, Addr)> = Vec::new();
            for (caller_id, call_site) in sites {
                let Some(caller) = function_by_id.get(caller_id).copied() else {
                    continue;
                };
                let Some(caller_decoded) = decoded_by_function.get(&caller.address.get()) else {
                    continue;
                };
                let Some(target) = origin::resolve_argument_pointer(
                    image,
                    caller_decoded,
                    call_site.get(),
                    forwarded,
                ) else {
                    continue;
                };
                let Some(function) = function_at_address(functions, target) else {
                    continue;
                };
                candidates.push((function, caller_id.clone(), *call_site));
            }
            let unique: BTreeSet<&FunctionId> = candidates
                .iter()
                .map(|(function, _, _)| &function.id)
                .collect();
            if unique.len() == 1 {
                let function = candidates[0].0;
                resolution.chosen = Some(function);
                resolution.candidates = vec![function];
                forwarded_sites = candidates
                    .iter()
                    .map(|(_, caller, site)| (caller.clone(), *site))
                    .collect();
                entry_heuristic = true;
                sink.push(
                    Severity::Info,
                    "forwarded-spawn-entry",
                    format!(
                        "recovered {} entry through wrapper argument {forwarded} from {} caller site(s)",
                        hit.rule.api,
                        forwarded_sites.len()
                    ),
                    Some(&hit.caller),
                    Some(hit.site),
                );
            } else if unique.len() > 1 {
                sink.push(
                    Severity::Info,
                    "forwarded-spawn-ambiguous",
                    format!(
                        "{} wrapper forwards argument {forwarded} with {} possible entries; keeping the spawn target opaque",
                        hit.rule.api,
                        unique.len()
                    ),
                    Some(&hit.caller),
                    Some(hit.site),
                );
                let mut seen = BTreeSet::new();
                resolution.candidates = candidates
                    .into_iter()
                    .filter_map(|(function, _, _)| {
                        seen.insert(function.id.clone()).then_some(function)
                    })
                    .collect();
            }
        }
        let mut confidence = if resolution.chosen.is_some() {
            if entry_heuristic {
                Confidence::Medium
            } else {
                hit.rule.confidence
            }
        } else {
            Confidence::Medium
        };
        if hit.heuristic {
            confidence = Confidence::Low;
        }
        let edge_id = unique_edge_id(
            format!("e:spawn:0x{:x}", hit.site.get()),
            &mut used_edge_ids,
        );
        let task_label = hit.generic.clone().or_else(|| {
            resolution
                .chosen
                .map(|entry| rules::normalize_crate_hashes(&entry.primary_name))
        });
        match resolution.chosen {
            Some(entry) => {
                let context_id = ContextId::new(format!(
                    "ctx:{}:0x{:x}",
                    context_tag(hit.rule.spawn_kind),
                    hit.site.get()
                ));
                if new_contexts.iter().any(|context| context.id == context_id)
                    || contexts.iter().any(|context| context.id == context_id)
                {
                    continue;
                }
                let name = rules::normalize_crate_hashes(&entry.primary_name);
                let context = Context {
                    id: context_id.clone(),
                    name,
                    kind: context_kind(hit.rule.spawn_kind),
                    entry: entry.id.clone(),
                    parent: None,
                    scheduling: context_scheduling(hit.rule.spawn_kind),
                    priority: None,
                    core: None,
                    frequency_domain: frequency_domain.cloned(),
                    spawn_edge: Some(edge_id.clone()),
                    ext: BTreeMap::new(),
                };
                new_contexts.push(context);
                spawn_by_caller
                    .entry(hit.caller.clone())
                    .or_default()
                    .push((context_id.clone(), hit.site));
                for (caller, site) in &forwarded_sites {
                    spawn_by_caller
                        .entry(caller.clone())
                        .or_default()
                        .push((context_id.clone(), *site));
                }
                pending_parents.push((context_id.clone(), hit.caller.clone()));
                edges.push(Edge::Spawn {
                    id: edge_id,
                    from_function: hit.caller.clone(),
                    target: SpawnTarget::Context {
                        context: context_id,
                        entry: entry.id.clone(),
                    },
                    site: hit.site,
                    runtime: elf2tdg_schema::RuntimeId::new(hit.rule.runtime),
                    api: hit.rule.api.to_owned(),
                    name: task_label.clone(),
                    spawn_kind: hit.rule.spawn_kind,
                    priority: None,
                    confidence,
                });
            }
            None => {
                if let Some(label) = task_label.clone() {
                    let function_id = FunctionId::new(format!("fn:task:0x{:x}", hit.site.get()));
                    let context_id = ContextId::new(format!(
                        "ctx:{}:0x{:x}",
                        context_tag(hit.rule.spawn_kind),
                        hit.site.get()
                    ));
                    if !logical_functions
                        .iter()
                        .any(|function| function.id == function_id)
                        && !new_contexts.iter().any(|context| context.id == context_id)
                        && !contexts.iter().any(|context| context.id == context_id)
                    {
                        let mut ext = BTreeMap::new();
                        ext.insert(
                            "elf2tdg.logical_task".to_owned(),
                            serde_json::Value::Bool(true),
                        );
                        let context_ext = ext.clone();
                        logical_functions.push(Function {
                            id: function_id.clone(),
                            primary_name: label.clone(),
                            demangled_name: Some(label.clone()),
                            symbols: Vec::new(),
                            language: elf2tdg_schema::Language::Rust,
                            address: hit.site,
                            size: 0,
                            section: None,
                            kind: elf2tdg_schema::FunctionKind::TaskEntry,
                            blocks: Vec::new(),
                            timing: None,
                            source: None,
                            inline_sites: Vec::new(),
                            ext,
                        });
                        new_contexts.push(Context {
                            id: context_id.clone(),
                            name: label.clone(),
                            kind: context_kind(hit.rule.spawn_kind),
                            entry: function_id.clone(),
                            parent: None,
                            scheduling: context_scheduling(hit.rule.spawn_kind),
                            priority: None,
                            core: None,
                            frequency_domain: frequency_domain.cloned(),
                            spawn_edge: Some(edge_id.clone()),
                            ext: context_ext,
                        });
                        spawn_by_caller
                            .entry(hit.caller.clone())
                            .or_default()
                            .push((context_id.clone(), hit.site));
                        pending_parents.push((context_id.clone(), hit.caller.clone()));
                        sink.push(
                            Severity::Info,
                            "logical-task-context",
                            format!(
                                "{} at 0x{:x} has no concrete entry function; created a logical task context for {}",
                                hit.rule.api,
                                hit.site.get(),
                                label
                            ),
                            Some(&hit.caller),
                            Some(hit.site),
                        );
                        edges.push(Edge::Spawn {
                            id: edge_id,
                            from_function: hit.caller.clone(),
                            target: SpawnTarget::Context {
                                context: context_id,
                                entry: function_id,
                            },
                            site: hit.site,
                            runtime: elf2tdg_schema::RuntimeId::new(hit.rule.runtime),
                            api: hit.rule.api.to_owned(),
                            name: Some(label),
                            spawn_kind: hit.rule.spawn_kind,
                            priority: None,
                            confidence: if hit.heuristic {
                                Confidence::Low
                            } else {
                                Confidence::Medium
                            },
                        });
                        continue;
                    }
                }
                let candidates = resolution
                    .candidates
                    .iter()
                    .map(|function| function.id.clone())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect();
                sink.push(
                    Severity::Info,
                    "opaque-spawn-target",
                    format!(
                        "{} spawn at 0x{:x} has no resolved entry function; recorded as opaque",
                        hit.rule.api,
                        hit.site.get()
                    ),
                    Some(&hit.caller),
                    Some(hit.site),
                );
                edges.push(Edge::Spawn {
                    id: edge_id,
                    from_function: hit.caller.clone(),
                    target: SpawnTarget::Opaque { candidates },
                    site: hit.site,
                    runtime: elf2tdg_schema::RuntimeId::new(hit.rule.runtime),
                    api: hit.rule.api.to_owned(),
                    name: task_label,
                    spawn_kind: hit.rule.spawn_kind,
                    priority: None,
                    confidence,
                });
            }
        }
    }
    add_orphan_spawn_contexts(
        functions,
        contexts,
        &mut new_contexts,
        &hits,
        &normalized_index,
        frequency_domain,
        &mut sink,
    );
    contexts.extend(new_contexts);

    let membership = compute_membership(functions, contexts, &adjacency);

    for (context_id, caller) in pending_parents {
        let Some(parent) = membership.get(&caller).cloned() else {
            continue;
        };
        if parent == context_id {
            continue;
        }
        if let Some(context) = contexts.iter_mut().find(|context| context.id == context_id) {
            context.parent = Some(parent);
        }
    }
    break_parent_cycles(contexts, &mut sink);
    add_parallel_scopes(edges, &membership, scopes);

    for hit in hits.iter().filter(|hit| hit.rule.op == RuleOp::Join) {
        let spawned = spawn_by_caller
            .get(&hit.caller)
            .cloned()
            .unwrap_or_default();
        let preceding: Vec<(ContextId, Addr)> = spawned
            .iter()
            .filter(|(_, site)| *site <= hit.site)
            .cloned()
            .collect();
        let candidates = if preceding.is_empty() {
            spawned
        } else {
            preceding
        };
        let (target, confidence) = if candidates.len() == 1 {
            (
                JoinTarget::Context {
                    context: candidates[0].0.clone(),
                },
                Confidence::Medium,
            )
        } else {
            (
                JoinTarget::Opaque {
                    candidates: candidates.into_iter().map(|(context, _)| context).collect(),
                },
                hit.rule.confidence,
            )
        };
        let confidence = if hit.heuristic {
            Confidence::Low
        } else {
            confidence
        };
        let id = unique_edge_id(format!("e:join:0x{:x}", hit.site.get()), &mut used_edge_ids);
        edges.push(Edge::Join {
            id,
            from_function: hit.caller.clone(),
            from_context: membership.get(&hit.caller).cloned(),
            target,
            site: hit.site,
            join_kind: hit.rule.join_kind,
            scope: None,
            confidence,
        });
    }

    for hit in hits.iter().filter(|hit| hit.rule.op == RuleOp::Await) {
        let Some(from_context) = membership.get(&hit.caller).cloned() else {
            sink.push(
                Severity::Info,
                "await-context-unresolved",
                format!(
                    "{} await at 0x{:x} is not reachable from a known context",
                    hit.rule.api,
                    hit.site.get()
                ),
                Some(&hit.caller),
                Some(hit.site),
            );
            continue;
        };
        let spawned = spawn_by_caller
            .get(&hit.caller)
            .cloned()
            .unwrap_or_default();
        let preceding: Vec<(ContextId, Addr)> = spawned
            .iter()
            .filter(|(_, site)| *site <= hit.site)
            .cloned()
            .collect();
        let spawned = if preceding.is_empty() {
            spawned
        } else {
            preceding
        };
        let (target, confidence) = if spawned.len() == 1 {
            (
                AwaitTarget::Context {
                    context: spawned[0].0.clone(),
                },
                Confidence::Medium,
            )
        } else {
            let candidate_functions = spawned
                .iter()
                .filter_map(|(context_id, _)| {
                    contexts
                        .iter()
                        .find(|context| &context.id == context_id)
                        .map(|context| context.entry.clone())
                })
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            (
                AwaitTarget::Opaque {
                    candidates: candidate_functions,
                },
                hit.rule.confidence,
            )
        };
        let confidence = if hit.heuristic {
            Confidence::Low
        } else {
            confidence
        };
        let id = unique_edge_id(
            format!("e:await:0x{:x}", hit.site.get()),
            &mut used_edge_ids,
        );
        edges.push(Edge::Await {
            id,
            from_context,
            target,
            site: hit.site,
            await_kind: hit.rule.await_kind,
            confidence,
        });
    }

    let mut pending_scopes: Vec<PendingScope> = Vec::new();
    for hit in hits.iter().filter(|hit| hit.rule.op == RuleOp::Scope) {
        let Some(entering_context) = membership.get(&hit.caller).cloned() else {
            sink.push(
                Severity::Warning,
                "scope-context-unresolved",
                format!(
                    "{} scope at 0x{:x} is not reachable from a known context",
                    hit.rule.api,
                    hit.site.get()
                ),
                Some(&hit.caller),
                Some(hit.site),
            );
            continue;
        };
        let scope_id = ScopeId::new(format!("scope:0x{:x}", hit.site.get()));
        if scopes.iter().any(|scope| scope.id == scope_id) {
            continue;
        }
        let closure = hit
            .generic
            .as_deref()
            .and_then(|candidate| resolve_candidate(candidate, &normalized_index).chosen)
            .map(|function| function.id.clone());
        if closure.is_none() {
            sink.push(
                Severity::Warning,
                "scope-closure-unresolved",
                format!(
                    "{} scope at 0x{:x} has no resolved closure; scope membership is incomplete",
                    hit.rule.api,
                    hit.site.get()
                ),
                Some(&hit.caller),
                Some(hit.site),
            );
        }
        scopes.push(Scope {
            id: scope_id.clone(),
            kind: hit.rule.scope_kind,
            entering_context,
            enter_site: hit.site,
            exit_site: hit
                .inline_end
                .filter(|end| *end > hit.site.get())
                .map(Addr::new),
            implicit_join: true,
            members: Vec::new(),
            confidence: if hit.heuristic {
                Confidence::Low
            } else {
                hit.rule.confidence
            },
        });
        pending_scopes.push(PendingScope {
            id: scope_id,
            closure,
            caller: hit.caller.clone(),
            end: hit.inline_end.filter(|end| *end > hit.site.get()),
        });
    }

    link_scopes(contexts, edges, scopes, &pending_scopes, &adjacency);
    logical_functions
}

#[derive(Clone)]
struct Hit {
    rule: &'static Rule,
    caller: FunctionId,
    callee: Option<FunctionId>,
    site: Addr,
    generic: Option<String>,
    inline_depth: u32,
    inline_end: Option<u64>,
    heuristic: bool,
}

struct PendingScope {
    id: ScopeId,
    closure: Option<FunctionId>,
    caller: FunctionId,
    end: Option<u64>,
}

fn collect_hits(edges: &[Edge], functions: &BTreeMap<&FunctionId, &Function>) -> Vec<Hit> {
    let mut hits = Vec::new();
    for edge in edges {
        let Edge::Call {
            caller,
            callee,
            site,
            confidence,
            ..
        } = edge
        else {
            continue;
        };
        let (Some(caller_node), Some(target_node)) = (functions.get(caller), functions.get(callee))
        else {
            continue;
        };
        let Some(rule) = rules::match_function(target_node) else {
            continue;
        };
        if rule.filter_runtime_caller && rules::is_runtime_internal(&caller_node.primary_name) {
            continue;
        }
        let generic = if rule.closure_generic {
            rules::extract_first_generic_arg(&target_node.primary_name)
        } else {
            None
        };
        hits.push(Hit {
            rule,
            caller: caller.clone(),
            callee: Some(callee.clone()),
            site: *site,
            generic,
            inline_depth: 0,
            inline_end: None,
            heuristic: *confidence == Confidence::Low,
        });
    }
    hits.sort_by(|left, right| {
        (left.site, left.rule.api, left.caller.as_str()).cmp(&(
            right.site,
            right.rule.api,
            right.caller.as_str(),
        ))
    });
    hits.dedup_by(|left, right| {
        left.site == right.site && left.rule.api == right.rule.api && left.caller == right.caller
    });
    hits
}

fn inline_demangled_name(call: &crate::dwarf::DwarfInlinedCall) -> Option<String> {
    let raw = call
        .linkage_name
        .as_deref()
        .or(call.name.as_deref())?
        .trim();
    if raw.is_empty() {
        return None;
    }
    if (raw.starts_with("_R") || raw.starts_with("_ZN"))
        && let Ok(demangled) = rustc_demangle::try_demangle(raw)
    {
        return Some(demangled.to_string());
    }
    Some(raw.to_owned())
}

fn collect_inline_hits(image: &Image, functions: &[Function]) -> Vec<Hit> {
    let Some(dwarf) = &image.dwarf else {
        return Vec::new();
    };
    let mut sorted: Vec<&Function> = functions
        .iter()
        .filter(|function| function.size > 0)
        .collect();
    sorted.sort_by_key(|function| function.address.get());
    let mut hits = Vec::new();
    let mut grouped: BTreeMap<(FunctionId, String), (u32, u8, Hit)> = BTreeMap::new();
    let mut simple_groups: BTreeMap<(FunctionId, &'static str), Vec<Hit>> = BTreeMap::new();
    for call in &dwarf.inlined_calls {
        let Some(demangled) = inline_demangled_name(call) else {
            continue;
        };
        let Some(rule) = rules::match_demangled_name(&demangled) else {
            continue;
        };
        let Some(caller) = function_containing_sorted(&sorted, call.low_pc) else {
            continue;
        };
        let generic = if rule.closure_generic {
            rules::extract_first_generic_arg(&demangled)
        } else {
            None
        };
        // DWARF describes every inlined implementation layer too, including
        // `Builder::spawn` inside `thread::spawn`. Keep only instantiations
        // that are actually inlined into non-runtime code, such as a user
        // `thread::spawn` call inlined into `main`.
        if rule.filter_runtime_caller && rules::is_runtime_internal(&caller.primary_name) {
            continue;
        }
        if rule.closure_generic && generic.as_deref().is_some_and(rules::is_runtime_internal) {
            continue;
        }
        let hit = Hit {
            rule,
            caller: caller.id.clone(),
            callee: None,
            site: Addr::new(call.low_pc),
            generic,
            inline_depth: call.depth,
            inline_end: (call.high_pc > call.low_pc).then_some(call.high_pc),
            heuristic: false,
        };
        if rule.closure_generic {
            let key = (
                hit.caller.clone(),
                hit.generic
                    .clone()
                    .unwrap_or_else(|| format!("{}@{:x}", rule.api, call.low_pc)),
            );
            let rank = confidence_rank(rule.confidence);
            match grouped.get(&key) {
                Some((depth, existing_rank, _))
                    if (*depth < hit.inline_depth)
                        || (*depth == hit.inline_depth && *existing_rank >= rank) => {}
                _ => {
                    grouped.insert(key, (hit.inline_depth, rank, hit));
                }
            }
        } else {
            simple_groups
                .entry((hit.caller.clone(), rule.api))
                .or_default()
                .push(hit);
        }
    }
    hits.extend(grouped.into_values().map(|(_, _, hit)| hit));
    for group in simple_groups.into_values() {
        let Some(min_depth) = group.iter().map(|hit| hit.inline_depth).min() else {
            continue;
        };
        if let Some(hit) = group
            .into_iter()
            .filter(|hit| hit.inline_depth == min_depth)
            .min_by_key(|hit| hit.site)
        {
            hits.push(hit);
        }
    }
    hits
}

fn confidence_rank(confidence: Confidence) -> u8 {
    match confidence {
        Confidence::High => 3,
        Confidence::Medium => 2,
        Confidence::Low => 1,
        Confidence::Unknown => 0,
    }
}

fn function_containing_sorted<'a>(sorted: &[&'a Function], address: u64) -> Option<&'a Function> {
    let index = sorted
        .partition_point(|function| function.address.get() <= address)
        .checked_sub(1)?;
    let function = sorted[index];
    (address < function.address.get().saturating_add(function.size)).then_some(function)
}

#[allow(clippy::too_many_arguments)]
fn add_orphan_spawn_contexts(
    functions: &[Function],
    contexts: &[Context],
    new_contexts: &mut Vec<Context>,
    hits: &[Hit],
    normalized_index: &BTreeMap<String, Vec<&Function>>,
    frequency_domain: Option<&FrequencyDomainId>,
    sink: &mut DiagnosticSink<'_>,
) {
    let hit_callees: BTreeSet<FunctionId> = hits
        .iter()
        .filter(|hit| hit.rule.op == RuleOp::Spawn)
        .filter_map(|hit| hit.callee.clone())
        .collect();
    let mut existing_entries: BTreeSet<FunctionId> = contexts
        .iter()
        .map(|context| context.entry.clone())
        .chain(new_contexts.iter().map(|context| context.entry.clone()))
        .collect();
    let mut existing_names: BTreeSet<String> = contexts
        .iter()
        .chain(new_contexts.iter())
        .map(|context| rules::normalize_crate_hashes(&context.name))
        .collect();
    for function in functions {
        if hit_callees.contains(&function.id) {
            continue;
        }
        let Some(rule) = rules::match_function(function) else {
            continue;
        };
        if rule.op != RuleOp::Spawn || !rule.closure_generic {
            continue;
        }
        let Some(candidate) = rules::extract_first_generic_arg(&function.primary_name) else {
            continue;
        };
        let Some(entry) = resolve_candidate(&candidate, normalized_index).chosen else {
            continue;
        };
        if rules::is_runtime_internal(&entry.primary_name) {
            continue;
        }
        let normalized_entry = rules::normalize_crate_hashes(&entry.primary_name);
        if !existing_entries.insert(entry.id.clone()) || existing_names.contains(&normalized_entry)
        {
            continue;
        }
        existing_names.insert(normalized_entry.clone());
        let context_id = ContextId::new(format!(
            "ctx:{}:orphan:0x{:x}",
            context_tag(rule.spawn_kind),
            entry.address.get()
        ));
        let mut ext = BTreeMap::new();
        ext.insert(
            "elf2tdg.orphan_spawn_api".to_owned(),
            serde_json::Value::String(rule.api.to_owned()),
        );
        new_contexts.push(Context {
            id: context_id,
            name: normalized_entry,
            kind: context_kind(rule.spawn_kind),
            entry: entry.id.clone(),
            parent: None,
            scheduling: context_scheduling(rule.spawn_kind),
            priority: None,
            core: None,
            frequency_domain: frequency_domain.cloned(),
            spawn_edge: None,
            ext,
        });
        sink.push(
            Severity::Info,
            "orphan-spawn-context",
            format!(
                "found {} instantiation for {} but no direct call site (spawn likely inlined); created an orphan context",
                rule.api,
                rules::normalize_crate_hashes(&entry.primary_name)
            ),
            Some(&function.id),
            None,
        );
    }
}

fn dedup_closure_hits(hits: &mut Vec<Hit>) {
    let mut grouped: BTreeMap<(RuleOp, FunctionId, String), Hit> = BTreeMap::new();
    let mut rest = Vec::new();
    for hit in hits.drain(..) {
        if hit.rule.closure_generic
            && let Some(generic) = hit.generic.clone()
        {
            let key = (hit.rule.op, hit.caller.clone(), generic);
            match grouped.get(&key) {
                Some(existing) if !hit_is_better(&hit, existing) => {}
                _ => {
                    grouped.insert(key, hit);
                }
            }
        } else {
            rest.push(hit);
        }
    }
    rest.extend(grouped.into_values());
    *hits = rest;
}

fn hit_is_better(candidate: &Hit, existing: &Hit) -> bool {
    let candidate_rank = confidence_rank(candidate.rule.confidence);
    let existing_rank = confidence_rank(existing.rule.confidence);
    if candidate_rank != existing_rank {
        return candidate_rank > existing_rank;
    }
    if candidate.heuristic != existing.heuristic {
        return !candidate.heuristic;
    }
    if candidate.inline_depth != existing.inline_depth {
        return candidate.inline_depth < existing.inline_depth;
    }
    candidate.site < existing.site
}

fn build_normalized_index(functions: &[Function]) -> BTreeMap<String, Vec<&Function>> {
    let mut index: BTreeMap<String, Vec<&Function>> = BTreeMap::new();
    for function in functions {
        if function.primary_name.is_empty() {
            continue;
        }
        let key = rules::normalize_crate_hashes(&function.primary_name);
        index.entry(key).or_default().push(function);
    }
    index
}

#[derive(Default)]
struct Resolution<'a> {
    chosen: Option<&'a Function>,
    candidates: Vec<&'a Function>,
}

fn resolve_candidate<'a>(
    candidate: &str,
    index: &BTreeMap<String, Vec<&'a Function>>,
) -> Resolution<'a> {
    let key = rules::normalize_crate_hashes(candidate);
    let exact = index.get(&key).cloned().unwrap_or_default();
    if exact.len() == 1 {
        return Resolution {
            chosen: Some(exact[0]),
            candidates: exact,
        };
    }
    if !exact.is_empty() {
        return Resolution {
            chosen: None,
            candidates: exact,
        };
    }

    // Async spawns carry the future type; the generated poll body commonly
    // appears as `...::poll` or `...>::poll`. Only accept a unique match.
    let mut fallback = Vec::new();
    for functions in index.values() {
        for function in functions {
            let name = rules::normalize_crate_hashes(&function.primary_name);
            if name.contains(&key) && (name.ends_with("::poll") || name.contains(">::poll")) {
                fallback.push(*function);
            }
        }
    }
    fallback.sort_by(|left, right| left.id.as_str().cmp(right.id.as_str()));
    fallback.dedup_by(|left, right| left.id == right.id);
    let chosen = if fallback.len() == 1 {
        fallback.first().copied()
    } else {
        None
    };
    Resolution {
        chosen,
        candidates: fallback,
    }
}

fn function_at_address(functions: &[Function], address: u64) -> Option<&Function> {
    functions
        .iter()
        .find(|function| function.address.get() == address)
        .or_else(|| {
            functions.iter().find(|function| {
                function.size > 0
                    && address > function.address.get()
                    && address < function.address.get().saturating_add(function.size)
            })
        })
}

fn build_callers(edges: &[Edge]) -> BTreeMap<FunctionId, Vec<(FunctionId, Addr)>> {
    let mut callers: BTreeMap<FunctionId, Vec<(FunctionId, Addr)>> = BTreeMap::new();
    for edge in edges {
        if let Edge::Call {
            caller,
            callee,
            site,
            ..
        } = edge
        {
            callers
                .entry(callee.clone())
                .or_default()
                .push((caller.clone(), *site));
        }
    }
    for sites in callers.values_mut() {
        sites.sort_by_key(|(_, site)| *site);
        sites.dedup();
    }
    callers
}

fn build_adjacency(edges: &[Edge]) -> BTreeMap<FunctionId, BTreeSet<FunctionId>> {
    let mut adjacency: BTreeMap<FunctionId, BTreeSet<FunctionId>> = BTreeMap::new();
    for edge in edges {
        if let Edge::Call { caller, callee, .. } = edge {
            adjacency
                .entry(caller.clone())
                .or_default()
                .insert(callee.clone());
        }
    }
    adjacency
}

fn compute_membership(
    functions: &[Function],
    contexts: &[Context],
    adjacency: &BTreeMap<FunctionId, BTreeSet<FunctionId>>,
) -> BTreeMap<FunctionId, ContextId> {
    let function_ids: BTreeSet<&FunctionId> =
        functions.iter().map(|function| &function.id).collect();
    let mut best: BTreeMap<FunctionId, (u8, ContextId)> = BTreeMap::new();
    for context in contexts {
        let priority = context_priority(context.kind);
        let mut visited = BTreeSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(context.entry.clone());
        while let Some(function) = queue.pop_front() {
            if !function_ids.contains(&function) {
                continue;
            }
            if !visited.insert(function.clone()) {
                continue;
            }
            match best.get(&function) {
                Some((current, _)) if *current <= priority => {}
                _ => {
                    best.insert(function.clone(), (priority, context.id.clone()));
                }
            }
            if let Some(callees) = adjacency.get(&function) {
                for callee in callees {
                    queue.push_back(callee.clone());
                }
            }
        }
    }
    best.into_iter()
        .map(|(function, (_, context))| (function, context))
        .collect()
}

fn context_priority(kind: ContextKind) -> u8 {
    match kind {
        ContextKind::Thread
        | ContextKind::ScopedThread
        | ContextKind::AsyncTask
        | ContextKind::Executor
        | ContextKind::TimerCallback
        | ContextKind::SystemWorkqueue
        | ContextKind::KernelThread => 0,
        ContextKind::Main => 1,
        ContextKind::Startup => 2,
        ContextKind::Isr => 3,
        ContextKind::Unknown => 4,
    }
}

fn break_parent_cycles(contexts: &mut [Context], sink: &mut DiagnosticSink<'_>) {
    let parents: BTreeMap<ContextId, ContextId> = contexts
        .iter()
        .filter_map(|context| {
            context
                .parent
                .as_ref()
                .map(|parent| (context.id.clone(), parent.clone()))
        })
        .collect();
    let mut to_clear = BTreeSet::new();
    for context in &mut *contexts {
        let mut seen = BTreeSet::new();
        let mut current = Some(context.id.clone());
        while let Some(id) = current {
            if !seen.insert(id.clone()) {
                to_clear.insert(id);
                break;
            }
            current = parents.get(&id).cloned();
        }
    }
    for id in &to_clear {
        sink.push(
            Severity::Warning,
            "context-parent-cycle",
            format!("cleared cyclic parent link on context {id}"),
            None,
            None,
        );
    }
    for context in contexts {
        if to_clear.contains(&context.id) {
            context.parent = None;
        }
    }
}

/// OpenMP parallel regions are implicit scopes: the runtime call creates the
/// team and joins it before returning. Record one scope per resolved OpenMP
/// spawn so JSON/diagram consumers see the structured region, not just a
/// thread context.
fn add_parallel_scopes(
    edges: &[Edge],
    membership: &BTreeMap<FunctionId, ContextId>,
    scopes: &mut Vec<Scope>,
) {
    for edge in edges {
        let Edge::Spawn {
            id,
            from_function,
            site,
            spawn_kind: SpawnKind::OpenMpRegion,
            confidence,
            ..
        } = edge
        else {
            continue;
        };
        let Some(entering_context) = membership.get(from_function) else {
            continue;
        };
        let scope_id = ScopeId::new(format!("scope:omp:0x{:x}", site.get()));
        if scopes.iter().any(|scope| scope.id == scope_id) {
            continue;
        }
        scopes.push(Scope {
            id: scope_id,
            kind: elf2tdg_schema::ScopeKind::OpenMpParallel,
            entering_context: entering_context.clone(),
            enter_site: *site,
            exit_site: None,
            implicit_join: true,
            members: vec![id.clone()],
            confidence: *confidence,
        });
    }
}

fn link_scopes(
    contexts: &mut [Context],
    edges: &[Edge],
    scopes: &mut [Scope],
    pending_scopes: &[PendingScope],
    adjacency: &BTreeMap<FunctionId, BTreeSet<FunctionId>>,
) {
    let edge_by_id: BTreeMap<&EdgeId, &Edge> = edges.iter().map(|edge| (edge.id(), edge)).collect();
    for pending in pending_scopes {
        let reachable = pending
            .closure
            .as_ref()
            .map(|closure| reachable_functions(closure, adjacency))
            .unwrap_or_default();
        let Some(scope) = scopes.iter_mut().find(|scope| scope.id == pending.id) else {
            continue;
        };
        let entering_context = scope.entering_context.clone();
        let enter_site = scope.enter_site.get();
        let exit_site = pending.end.unwrap_or(u64::MAX);
        let mut members = BTreeSet::new();
        for edge in edges {
            if let Edge::Spawn {
                id,
                from_function,
                site,
                ..
            } = edge
                && (reachable.contains(from_function)
                    || (from_function == &pending.caller
                        && site.get() >= enter_site
                        && site.get() <= exit_site))
            {
                members.insert(id.clone());
            }
        }
        scope.members = members.into_iter().collect();

        let mut scoped_contexts = Vec::new();
        for member in &scope.members {
            if let Some(Edge::Spawn {
                target: SpawnTarget::Context { context, .. },
                ..
            }) = edge_by_id.get(member)
            {
                scoped_contexts.push((*context).clone());
            }
        }
        for context_id in scoped_contexts {
            if let Some(context) = contexts.iter_mut().find(|context| context.id == context_id)
                && context.parent.is_none()
                && context.kind == ContextKind::ScopedThread
            {
                context.parent = Some(entering_context.clone());
            }
        }
    }
}

fn reachable_functions(
    start: &FunctionId,
    adjacency: &BTreeMap<FunctionId, BTreeSet<FunctionId>>,
) -> BTreeSet<FunctionId> {
    let mut reachable = BTreeSet::new();
    let mut queue = VecDeque::new();
    queue.push_back(start.clone());
    while let Some(function) = queue.pop_front() {
        if !reachable.insert(function.clone()) {
            continue;
        }
        if let Some(callees) = adjacency.get(&function) {
            for callee in callees {
                queue.push_back(callee.clone());
            }
        }
    }
    reachable
}

fn context_tag(kind: SpawnKind) -> &'static str {
    match kind {
        SpawnKind::OsThread => "thread",
        SpawnKind::ScopedThread => "scoped",
        SpawnKind::AsyncTask | SpawnKind::ExecutorTask => "async",
        SpawnKind::RayonTask => "rayon",
        SpawnKind::OpenMpRegion => "omp",
        SpawnKind::TimerCallback => "timer",
        SpawnKind::Unknown => "task",
    }
}

fn context_kind(kind: SpawnKind) -> ContextKind {
    match kind {
        SpawnKind::OsThread | SpawnKind::RayonTask | SpawnKind::OpenMpRegion => ContextKind::Thread,
        SpawnKind::ScopedThread => ContextKind::ScopedThread,
        SpawnKind::AsyncTask | SpawnKind::ExecutorTask => ContextKind::AsyncTask,
        SpawnKind::TimerCallback => ContextKind::TimerCallback,
        SpawnKind::Unknown => ContextKind::Unknown,
    }
}

fn context_scheduling(kind: SpawnKind) -> Scheduling {
    match kind {
        SpawnKind::OsThread | SpawnKind::ScopedThread | SpawnKind::OpenMpRegion => {
            Scheduling::Preemptive
        }
        SpawnKind::AsyncTask | SpawnKind::ExecutorTask | SpawnKind::RayonTask => {
            Scheduling::Cooperative
        }
        SpawnKind::TimerCallback => Scheduling::Interrupt,
        SpawnKind::Unknown => Scheduling::Unknown,
    }
}

fn unique_edge_id(base: String, used: &mut BTreeSet<String>) -> EdgeId {
    if used.insert(base.clone()) {
        return EdgeId::new(base);
    }
    let mut suffix = 1u32;
    loop {
        let candidate = format!("{base}:{suffix}");
        if used.insert(candidate.clone()) {
            return EdgeId::new(candidate);
        }
        suffix = suffix.saturating_add(1);
    }
}

struct DiagnosticSink<'a> {
    diagnostics: &'a mut Vec<Diagnostic>,
    keys: BTreeSet<(String, Option<Addr>)>,
    max: usize,
}

impl DiagnosticSink<'_> {
    fn push(
        &mut self,
        severity: Severity,
        code: &str,
        message: impl Into<String>,
        function: Option<&FunctionId>,
        site: Option<Addr>,
    ) {
        let key = (code.to_owned(), site);
        if !self.keys.insert(key) {
            return;
        }
        if self.diagnostics.len() >= self.max {
            return;
        }
        self.diagnostics.push(Diagnostic {
            code: code.to_owned(),
            severity,
            message: message.into(),
            function: function.cloned(),
            context: None,
            site,
            details: BTreeMap::new(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::resolve_candidate;
    use std::collections::BTreeMap;

    #[test]
    fn unresolved_candidate_is_empty_not_a_panic() {
        let index = BTreeMap::new();
        let resolution = resolve_candidate("app::main::{{closure}}", &index);
        assert!(resolution.chosen.is_none());
        assert_eq!(resolution.candidates.len(), 0);
    }
}
