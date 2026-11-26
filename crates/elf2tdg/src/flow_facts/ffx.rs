//! FFX XML flow-fact parser.
//!
//! Supported shape:
//!
//! ```xml
//! <flowfacts>
//!   <function name="main">
//!     <loop source="main.c" line="29" maxcount="10" totalcount="15"/>
//!     <loop offset="0x24" max="10">
//!       <loop offset="0x30" max="4"/>
//!     </loop>
//!   </function>
//! </flowfacts>
//! ```
//!
//! `<call name="...">` nesting is retained as a caller context. The context is
//! normalized to F4 order: immediate caller first, excluding the function that
//! contains the fact. An optional `address` or `site` attribute on `<call>`
//! identifies the call instruction, allowing the same caller/callee pair to
//! have multiple context versions. Without an address, a unique call edge is
//! used; an ambiguous edge is rejected with a warning. Context-sensitive loop
//! facts are applied by the WCET backends; contextual branch/call facts are
//! enforced by IPET.

use roxmltree::{Document, Node};

use super::{
    BranchFact, BranchOutcome, CallFact, CallTarget, ConflictElementFact, ConflictFact,
    ContextKind, FlowFactDocument, LocationTarget, LoopFact, LoopTarget,
};

pub(super) fn parse(text: &str, origin: &str) -> Result<FlowFactDocument, String> {
    let document =
        Document::parse(text).map_err(|error| format!("{origin}: invalid FFX XML: {error}"))?;
    let root = document.root_element();
    if root.tag_name().name() != "flowfacts" {
        return Err(format!(
            "{origin}: FFX root element must be <flowfacts>, found <{}>",
            root.tag_name().name()
        ));
    }
    let mut state = State {
        document: FlowFactDocument {
            origin: origin.to_owned(),
            checksum: None,
            loops: Vec::new(),
            branches: Vec::new(),
            calls: Vec::new(),
            conflicts: Vec::new(),
            warnings: Vec::new(),
        },
        functions: Vec::new(),
        sites: Vec::new(),
        loops: Vec::new(),
    };
    process_children(root, &mut state, origin)?;
    Ok(state.document)
}

struct State {
    document: FlowFactDocument,
    /// Enclosing function names from the outermost `<function>` scope to the
    /// current function. A nested `<call name="...">` adds its callee name.
    functions: Vec<String>,
    /// Optional call-site address for each enclosing `<call>` scope. The
    /// entries parallel `functions`; `<function>` scopes use `None`.
    sites: Vec<Option<u64>>,
    /// Enclosing `<loop>` contexts, outermost first.
    loops: Vec<LoopTarget>,
}

impl State {
    fn current_function(&self) -> Option<String> {
        self.functions.last().cloned()
    }

    /// Caller chain in F4 order: immediate caller first, excluding the
    /// current function.
    fn context(&self) -> Vec<String> {
        let mut context = self.functions[..self.functions.len().saturating_sub(1)].to_vec();
        context.reverse();
        context
    }

    /// Call-site addresses matching [`State::context`].
    ///
    /// The context excludes the current function. Frame `i` therefore uses
    /// the address of the call that entered frame `i + 1`; reversing the
    /// slice from index 1 keeps immediate callers first.
    fn context_sites(&self) -> Vec<Option<u64>> {
        let mut sites = self.sites.iter().skip(1).copied().collect::<Vec<_>>();
        sites.reverse();
        sites
    }

    fn push_function(&mut self, name: &str, site: Option<u64>) -> bool {
        if self.functions.last().is_some_and(|last| last == name) {
            return false;
        }
        self.functions.push(name.to_owned());
        self.sites.push(site);
        true
    }
}

fn context_site(node: &Node<'_, '_>) -> Option<u64> {
    attribute(node, "site")
        .or_else(|| attribute(node, "address"))
        .and_then(|value| parse_number(value).ok())
}

fn process_children(node: Node<'_, '_>, state: &mut State, origin: &str) -> Result<(), String> {
    for child in node.children().filter(Node::is_element) {
        match child.tag_name().name() {
            "function" => {
                let name = attribute(&child, "name")
                    .ok_or_else(|| format!("{origin}: <function> lacks a name"))?;
                let pushed = state.push_function(name, None);
                process_children(child, state, origin)?;
                if pushed {
                    state.functions.pop();
                    state.sites.pop();
                }
            }
            "call" => {
                let name = attribute(&child, "name")
                    .ok_or_else(|| format!("{origin}: <call> lacks a name"))?;
                if let Some((fact, warnings)) = parse_call(&child, state, origin)? {
                    state.document.calls.push(fact);
                    state.document.warnings.extend(warnings);
                }
                let pushed = state.push_function(name, context_site(&child));
                process_children(child, state, origin)?;
                if pushed {
                    state.functions.pop();
                    state.sites.pop();
                }
            }
            "loop" => {
                let (fact, target, warnings) = parse_loop(&child, state, origin)?;
                if let Some(fact) = fact {
                    state.document.loops.push(fact);
                }
                state.document.warnings.extend(warnings);
                state.loops.push(target);
                process_children(child, state, origin)?;
                state.loops.pop();
            }
            "conditional" => {
                parse_conditional(&child, state, origin)?;
            }
            "conflict" => {
                if let Some((fact, warnings)) = parse_conflict(&child, state, origin, false, false)?
                {
                    state.document.conflicts.push(fact);
                    state.document.warnings.extend(warnings);
                }
            }
            "not-all" => {
                parse_not_all(&child, state, origin, false)?;
            }
            "iteration" => {
                let all_iterations =
                    attribute(&child, "number").is_some_and(|number| number.trim() == "*");
                if all_iterations && !state.loops.is_empty() {
                    process_iteration_children(&child, state, origin)?;
                } else {
                    state.document.warnings.push(format!(
                        "{origin}: iteration-specific FFX facts are ignored because the analysis is not iteration-sensitive"
                    ));
                }
            }
            other => {
                state.document.warnings.push(format!(
                    "{origin}: unsupported FFX element <{other}> and its descendants ignored"
                ));
            }
        }
    }
    Ok(())
}

fn parse_not_all(
    node: &Node<'_, '_>,
    state: &mut State,
    origin: &str,
    iteration_context: bool,
) -> Result<(), String> {
    let sequential = attribute(node, "seq")
        .map(parse_bool)
        .transpose()
        .map_err(|error| format!("{origin}: not-all seq attribute: {error}"))?
        .unwrap_or(false);
    if !sequential {
        state.document.warnings.push(format!(
            "{origin}: <not-all> without seq=\"true\" is ignored"
        ));
        return Ok(());
    }
    if let Some((mut fact, warnings)) =
        parse_conflict(node, state, origin, true, iteration_context)?
    {
        // OTAWA's not-all form is a sequence; never let an ordered attribute
        // downgrade it to an unordered conflict.
        fact.ordered = true;
        state.document.conflicts.push(fact);
        state.document.warnings.extend(warnings);
    }
    Ok(())
}

fn process_iteration_children(
    node: &Node<'_, '_>,
    state: &mut State,
    origin: &str,
) -> Result<(), String> {
    for child in node.children().filter(Node::is_element) {
        match child.tag_name().name() {
            "conflict" => {
                if let Some((fact, warnings)) = parse_conflict(&child, state, origin, false, true)?
                {
                    state.document.conflicts.push(fact);
                    state.document.warnings.extend(warnings);
                }
            }
            "not-all" => parse_not_all(&child, state, origin, true)?,
            other => {
                state.document.warnings.push(format!(
                    "{origin}: iteration-specific <{other}> is ignored because the analysis is not iteration-sensitive"
                ));
            }
        }
    }
    Ok(())
}

fn parse_call(
    node: &Node<'_, '_>,
    state: &State,
    origin: &str,
) -> Result<Option<(CallFact, Vec<String>)>, String> {
    let name = attribute(node, "name").ok_or_else(|| format!("{origin}: <call> lacks a name"))?;
    let mut warnings = Vec::new();
    let executed = attribute(node, "executed")
        .map(parse_bool)
        .transpose()
        .map_err(|error| format!("{origin}: call executed attribute: {error}"))?;
    let numcall = attribute(node, "numcall");
    let max = if executed == Some(false) {
        Some(0)
    } else {
        match numcall {
            Some("NOCOMP") => {
                warnings.push(format!("{origin}: call {name:?} numcall=NOCOMP ignored"));
                None
            }
            Some(value) => Some(parse_u32(value)?),
            None => None,
        }
    };
    let Some(max) = max else {
        return Ok(None);
    };
    if executed == Some(true) && numcall.is_none() {
        return Ok(None);
    }
    let target = if let Some(location) = parse_location(node, state, origin)? {
        CallTarget::Location(location)
    } else {
        CallTarget::Callee(name.to_owned())
    };
    Ok(Some((
        CallFact {
            target,
            callee: Some(name.to_owned()),
            scope: state.current_function(),
            max,
            context: state.context(),
            context_sites: state.context_sites(),
            context_kind: ContextKind::FfxCall,
        },
        warnings,
    )))
}

fn parse_conditional(node: &Node<'_, '_>, state: &mut State, origin: &str) -> Result<(), String> {
    let condition = node
        .children()
        .find(|child| child.is_element() && child.tag_name().name() == "condition");
    let location_node = condition.unwrap_or(*node);
    let conditional_executed = attribute(node, "executed")
        .map(parse_bool)
        .transpose()
        .map_err(|error| format!("{origin}: conditional executed attribute: {error}"))?;
    let condition_executed = if let Some(condition) = condition {
        attribute(&condition, "executed")
            .or_else(|| attribute(&condition, "isexecuted"))
            .map(parse_bool)
            .transpose()
            .map_err(|error| format!("{origin}: condition executed attribute: {error}"))?
    } else {
        None
    };
    let never = conditional_executed == Some(false) || condition_executed == Some(false);
    let location = if never {
        Some(
            parse_location(&location_node, state, origin)?.ok_or_else(|| {
                format!("{origin}: executed=false conditional needs address, offset or source/line")
            })?,
        )
    } else {
        None
    };
    if let Some(location) = location {
        state.document.branches.push(BranchFact {
            target: location,
            outcome: BranchOutcome::Both,
            max: 0,
            context: state.context(),
            context_sites: state.context_sites(),
            context_kind: ContextKind::FfxCall,
        });
    }
    let mut location: Option<LocationTarget> = None;
    for case in node
        .children()
        .filter(|child| child.is_element() && child.tag_name().name() == "case")
    {
        let cond = attribute(&case, "cond")
            .ok_or_else(|| format!("{origin}: <case> must declare cond=\"0\" or cond=\"1\""))?;
        let outcome = match cond {
            "1" => BranchOutcome::Taken,
            "0" => BranchOutcome::NotTaken,
            _ => {
                state.document.warnings.push(format!(
                    "{origin}: unsupported <case cond={cond:?}> ignored"
                ));
                process_children(case, state, origin)?;
                continue;
            }
        };
        let executed = attribute(&case, "executed")
            .map(parse_bool)
            .transpose()
            .map_err(|error| format!("{origin}: case executed attribute: {error}"))?;
        if ["maxcount", "max", "totalcount", "total"]
            .iter()
            .any(|name| attribute(&case, name).is_some())
        {
            state.document.warnings.push(format!(
                "{origin}: numeric branch counts are not supported; only executed=false is applied"
            ));
        }
        let max = (executed == Some(false)).then_some(0);
        if let Some(max) = max {
            let case_location = if let Some(location) = &location {
                location.clone()
            } else {
                parse_location(&location_node, state, origin)?.ok_or_else(|| {
                    format!(
                        "{origin}: branch fact needs address, offset or source/line on <condition> or <conditional>"
                    )
                })?
            };
            state.document.branches.push(BranchFact {
                target: case_location.clone(),
                outcome,
                max,
                context: state.context(),
                context_sites: state.context_sites(),
                context_kind: ContextKind::FfxCall,
            });
            location = Some(case_location);
        }
        process_children(case, state, origin)?;
    }
    Ok(())
}

fn parse_conflict(
    node: &Node<'_, '_>,
    state: &mut State,
    origin: &str,
    default_ordered: bool,
    iteration_context: bool,
) -> Result<Option<(ConflictFact, Vec<String>)>, String> {
    let Some(scope) = state.current_function() else {
        return Ok(Some((
            ConflictFact {
                elements: Vec::new(),
                ordered: default_ordered,
                scope: None,
                context: state.context(),
                context_sites: state.context_sites(),
                context_kind: ContextKind::FfxCall,
                loop_context: state.loops.last().cloned(),
                all_iterations: iteration_context,
            },
            Vec::new(),
        )));
    };
    let context = state.context();
    let context_sites = state.context_sites();
    let loop_context = state.loops.last().cloned();
    let ordered = attribute(node, "ordered")
        .map(parse_bool)
        .transpose()
        .map_err(|error| format!("{origin}: conflict ordered attribute: {error}"))?
        .unwrap_or(default_ordered);
    let mut elements = Vec::new();
    let mut warnings = Vec::new();
    for child in node.children().filter(Node::is_element) {
        let Some(element) = parse_conflict_element(child, state, origin, &mut warnings)? else {
            state.document.warnings.append(&mut warnings);
            return Ok(None);
        };
        elements.push(element);
    }
    if elements.is_empty() {
        warnings.push(format!("{origin}: empty <conflict> is ignored"));
        state.document.warnings.append(&mut warnings);
        return Ok(None);
    }
    Ok(Some((
        ConflictFact {
            elements,
            ordered,
            scope: Some(scope),
            context,
            context_sites,
            context_kind: ContextKind::FfxCall,
            loop_context,
            all_iterations: iteration_context,
        },
        warnings,
    )))
}

fn parse_conflict_element(
    node: Node<'_, '_>,
    state: &mut State,
    origin: &str,
    warnings: &mut Vec<String>,
) -> Result<Option<ConflictElementFact>, String> {
    match node.tag_name().name() {
        "edge" => {
            let (Some(src), Some(dst)) = (attribute(&node, "src"), attribute(&node, "dst")) else {
                warnings.push(format!(
                    "{origin}: conflict <edge> needs src and dst; conflict ignored"
                ));
                return Ok(None);
            };
            Ok(Some(ConflictElementFact::Edge {
                src: parse_number(src)?,
                dst: parse_number(dst)?,
            }))
        }
        "block" => {
            let Some(location) = parse_location(&node, state, origin)? else {
                warnings.push(format!(
                    "{origin}: conflict <block> needs address, offset or source/line; conflict ignored"
                ));
                return Ok(None);
            };
            Ok(Some(ConflictElementFact::Block { location }))
        }
        "call" => parse_conflict_call(node, state, origin, warnings),
        "loop" | "iteration" => {
            warnings.push(format!(
                "{origin}: nested <{}> inside <conflict> is not supported; conflict ignored",
                node.tag_name().name()
            ));
            Ok(None)
        }
        other => {
            warnings.push(format!(
                "{origin}: unsupported <conflict> child <{other}>; conflict ignored"
            ));
            Ok(None)
        }
    }
}

fn parse_conflict_call(
    node: Node<'_, '_>,
    state: &mut State,
    origin: &str,
    warnings: &mut Vec<String>,
) -> Result<Option<ConflictElementFact>, String> {
    let Some(name) = attribute(&node, "name") else {
        warnings.push(format!(
            "{origin}: <call> inside <conflict> needs a name; conflict ignored"
        ));
        return Ok(None);
    };
    if ["offset", "source", "line"]
        .iter()
        .any(|attribute_name| attribute(&node, attribute_name).is_some())
    {
        warnings.push(format!(
            "{origin}: <call> inside <conflict> supports only address/site selection; conflict ignored"
        ));
        return Ok(None);
    }
    let site = attribute(&node, "site")
        .or_else(|| attribute(&node, "address"))
        .map(parse_number)
        .transpose()?;
    // Resolve relative locations against the callee while parsing this group.
    state.functions.push(name.to_owned());
    state.sites.push(site);
    let result = parse_conflict_call_elements(node, state, origin, warnings);
    state.functions.pop();
    state.sites.pop();
    let Some(elements) = result? else {
        return Ok(None);
    };
    if elements.is_empty() {
        warnings.push(format!(
            "{origin}: empty call group in <conflict> is ignored"
        ));
        return Ok(None);
    }
    Ok(Some(ConflictElementFact::Call {
        name: name.to_owned(),
        site,
        elements,
    }))
}

fn parse_conflict_call_elements(
    node: Node<'_, '_>,
    state: &mut State,
    origin: &str,
    warnings: &mut Vec<String>,
) -> Result<Option<Vec<ConflictElementFact>>, String> {
    let mut elements = Vec::new();
    for child in node.children().filter(Node::is_element) {
        match child.tag_name().name() {
            "edge" | "block" => {
                let Some(element) = parse_conflict_element(child, state, origin, warnings)? else {
                    return Ok(None);
                };
                elements.push(element);
            }
            "call" => {
                warnings.push(format!(
                    "{origin}: nested <call> inside a conflict call group is not supported; conflict ignored"
                ));
                return Ok(None);
            }
            "loop" | "iteration" => {
                warnings.push(format!(
                    "{origin}: <{}> inside a conflict call group is not supported; conflict ignored",
                    child.tag_name().name()
                ));
                return Ok(None);
            }
            other => {
                warnings.push(format!(
                    "{origin}: unsupported <conflict> child <{other}> in a call group; conflict ignored"
                ));
                return Ok(None);
            }
        }
    }
    Ok(Some(elements))
}

fn parse_location(
    node: &Node<'_, '_>,
    state: &State,
    origin: &str,
) -> Result<Option<LocationTarget>, String> {
    if let Some(address) = attribute(node, "address") {
        return Ok(Some(LocationTarget::Address(parse_number(address)?)));
    }
    if let Some(offset) = attribute(node, "offset") {
        let function = state.current_function().ok_or_else(|| {
            format!("{origin}: offset location requires an enclosing <function> or <call>")
        })?;
        return Ok(Some(LocationTarget::FunctionOffset {
            function,
            offset: parse_number(offset)?,
        }));
    }
    if let Some(source) = attribute(node, "source") {
        let line = attribute(node, "line")
            .ok_or_else(|| format!("{origin}: source location requires line"))?;
        return Ok(Some(LocationTarget::SourceLine {
            function: state.current_function(),
            file: source.to_owned(),
            line: parse_u32(line)?,
        }));
    }
    Ok(None)
}

fn parse_bool(value: &str) -> Result<bool, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "yes" | "1" => Ok(true),
        "false" | "no" | "0" => Ok(false),
        _ => Err(format!("invalid boolean {value:?}")),
    }
}

fn parse_loop(
    node: &Node<'_, '_>,
    state: &State,
    origin: &str,
) -> Result<(Option<LoopFact>, LoopTarget, Vec<String>), String> {
    let mut warnings = Vec::new();
    let offset = attribute(node, "offset");
    let source = attribute(node, "source");
    let line = attribute(node, "line");
    let target = if let Some(offset) = offset {
        if source.is_some() {
            warnings.push("loop has both offset and source/line; using offset".to_owned());
        }
        let function = state.current_function().ok_or_else(|| {
            format!("{origin}: <loop offset=...> requires an enclosing <function> or <call>")
        })?;
        LoopTarget::FunctionOffset {
            function,
            offset: parse_number(offset)?,
        }
    } else if let Some(address) = attribute(node, "address") {
        LoopTarget::Address(parse_number(address)?)
    } else if let Some(source) = source {
        let line = line.ok_or_else(|| format!("{origin}: <loop source=...> requires a line"))?;
        LoopTarget::SourceLine {
            function: state.current_function(),
            file: source.to_owned(),
            line: parse_u32(line)?,
        }
    } else {
        return Err(format!(
            "{origin}: <loop> needs offset, address, or source/line"
        ));
    };

    let max = if let Some(value) = attribute(node, "maxcount").or_else(|| attribute(node, "max")) {
        Some(parse_u32(value)?)
    } else if let Some(total) = attribute(node, "totalcount").or_else(|| attribute(node, "total")) {
        warnings.push("loop has only a total count; using it as the per-entry bound".to_owned());
        Some(parse_u32(total)?)
    } else {
        warnings.push(
            "<loop> has no maxcount/max or totalcount/total; treating it as a context only"
                .to_owned(),
        );
        None
    };
    let Some(max) = max else {
        return Ok((None, target, warnings));
    };
    if max == 0 {
        return Err(format!("{origin}: loop max bound must be positive"));
    }
    Ok((
        Some(LoopFact {
            target: target.clone(),
            max,
            context: state.context(),
            context_sites: state.context_sites(),
            context_kind: ContextKind::FfxCall,
        }),
        target,
        warnings,
    ))
}

fn attribute<'a>(node: &'a Node<'_, '_>, name: &str) -> Option<&'a str> {
    node.attribute(name)
}

fn parse_u32(value: &str) -> Result<u32, String> {
    u32::try_from(parse_number(value)?).map_err(|_| "FFX number exceeds u32".to_owned())
}

fn parse_number(value: &str) -> Result<u64, String> {
    let cleaned = value.trim().replace('_', "");
    if let Some(hex) = cleaned
        .strip_prefix("0x")
        .or_else(|| cleaned.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16)
            .map_err(|error| format!("invalid FFX hex number {value:?}: {error}"))
    } else {
        cleaned
            .parse::<u64>()
            .map_err(|error| format!("invalid FFX number {value:?}: {error}"))
    }
}

#[cfg(test)]
mod tests {
    use super::parse;
    use crate::flow_facts::{ContextKind, LoopTarget};

    #[test]
    fn parses_function_source_and_nested_loops() {
        let document = parse(
            r#"
<flowfacts>
  <function name="sum">
    <loop source="bench.c" line="4" maxcount="10">
      <loop source="bench.c" line="5" maxcount="10" totalcount="45"/>
    </loop>
  </function>
</flowfacts>
"#,
            "bench.ffx",
        )
        .expect("parse");
        assert_eq!(document.loops.len(), 2);
        assert!(matches!(
            &document.loops[0].target,
            LoopTarget::SourceLine { function: Some(function), file, line }
                if function == "sum" && file == "bench.c" && *line == 4
        ));
        assert_eq!(document.loops[1].max, 10);
    }

    #[test]
    fn parses_offset_and_call_context() {
        let document = parse(
            r#"
<flowfacts>
  <function name="main">
    <call name="g1">
      <call name="f">
        <loop offset="0x24" max="10" total="15"/>
      </call>
    </call>
  </function>
</flowfacts>
"#,
            "ctx.ffx",
        )
        .expect("parse");
        assert_eq!(document.loops.len(), 1);
        assert!(matches!(
            &document.loops[0].target,
            LoopTarget::FunctionOffset { function, offset }
                if function == "f" && *offset == 0x24
        ));
        assert_eq!(document.loops[0].max, 10);
        assert_eq!(document.loops[0].context, vec!["g1", "main"]);
        assert_eq!(document.loops[0].context_kind, ContextKind::FfxCall);
    }

    #[test]
    fn rejects_a_missing_loop_target() {
        let error = parse(
            "<flowfacts><function name=\"main\"><loop max=\"3\"/></function></flowfacts>",
            "bad.ffx",
        )
        .expect_err("missing target");
        assert!(error.contains("offset, address, or source/line"));
    }
}

#[cfg(test)]
mod non_loop_tests {
    use super::parse;
    use crate::flow_facts::{
        BranchOutcome, CallTarget, ConflictElementFact, LocationTarget, LoopTarget,
    };

    #[test]
    fn parses_branch_cases_and_never_executed_conditionals() {
        let document = parse(
            r#"
<flowfacts>
  <function name="main">
    <conditional>
      <condition address="0x1004" line="7" source="main.c"/>
      <case cond="1" executed="false"/>
      <case cond="0" executed="true"/>
    </conditional>
    <conditional executed="false" address="0x1010"/>
  </function>
</flowfacts>
"#,
            "branch.ffx",
        )
        .expect("parse");
        assert_eq!(document.branches.len(), 2);
        assert_eq!(document.branches[0].outcome, BranchOutcome::Taken);
        assert_eq!(document.branches[0].max, 0);
        assert!(matches!(
            document.branches[0].target,
            LocationTarget::Address(0x1004)
        ));
        assert_eq!(document.branches[1].outcome, BranchOutcome::Both);
        assert_eq!(document.branches[1].max, 0);
    }

    #[test]
    fn parses_call_counts_and_never_executed_calls() {
        let document = parse(
            r#"
<flowfacts>
  <function name="main">
    <call name="sensor" numcall="3" address="0x1010"/>
    <call name="monitor" executed="false"/>
  </function>
</flowfacts>
"#,
            "calls.ffx",
        )
        .expect("parse");
        assert_eq!(document.calls.len(), 2);
        assert_eq!(document.calls[0].max, 3);
        assert!(matches!(
            document.calls[0].target,
            CallTarget::Location(LocationTarget::Address(0x1010))
        ));
        assert_eq!(document.calls[1].max, 0);
        assert!(matches!(
            document.calls[1].target,
            CallTarget::Callee(ref name) if name == "monitor"
        ));
    }

    #[test]
    fn normalizes_nested_call_fact_scope_and_context() {
        let document = parse(
            r#"
<flowfacts>
  <function name="main">
    <call name="g">
      <call name="delay" numcall="2"/>
    </call>
  </function>
</flowfacts>
"#,
            "scope.ffx",
        )
        .expect("parse");
        assert_eq!(document.calls.len(), 1);
        assert_eq!(document.calls[0].context, vec!["main"]);
        assert_eq!(document.calls[0].scope.as_deref(), Some("g"));
        assert_eq!(document.calls[0].max, 2);
    }

    #[test]
    fn parses_conflict_and_not_all_elements() {
        let document = parse(
            r#"
<flowfacts>
  <function name="main">
    <conflict>
      <edge src="0x1000" dst="0x1002"/>
      <block address="0x1004"/>
    </conflict>
    <conflict ordered="yes">
      <edge src="0x1000" dst="0x1002"/>
      <edge src="0x1002" dst="0x1004"/>
    </conflict>
    <not-all seq="true">
      <edge src="0x1000" dst="0x1002"/>
      <edge src="0x1002" dst="0x1004"/>
    </not-all>
  </function>
</flowfacts>
"#,
            "conflicts.ffx",
        )
        .expect("parse");
        assert_eq!(document.conflicts.len(), 3);
        assert!(!document.conflicts[0].ordered);
        assert_eq!(document.conflicts[0].scope.as_deref(), Some("main"));
        assert_eq!(document.conflicts[0].context, Vec::<String>::new());
        assert_eq!(document.conflicts[0].elements.len(), 2);
        assert!(document.conflicts[1].ordered);
        assert!(document.conflicts[2].ordered);
    }

    #[test]
    fn parses_conflict_call_groups() {
        let document = parse(
            r#"
<flowfacts>
  <function name="main">
    <conflict ordered="yes">
      <block address="0x1000"/>
      <call name="helper">
        <block address="0x2000"/>
        <edge src="0x2002" dst="0x2004"/>
      </call>
    </conflict>
  </function>
</flowfacts>
"#,
            "cross.ffx",
        )
        .expect("parse");
        assert_eq!(document.conflicts.len(), 1);
        let conflict = &document.conflicts[0];
        assert!(conflict.ordered);
        assert_eq!(conflict.elements.len(), 2);
        let ConflictElementFact::Call { name, elements, .. } = &conflict.elements[1] else {
            panic!("call group");
        };
        assert_eq!(name, "helper");
        assert_eq!(elements.len(), 2);
        assert!(matches!(elements[0], ConflictElementFact::Block { .. }));
        assert!(matches!(elements[1], ConflictElementFact::Edge { .. }));
    }

    #[test]
    fn rejects_nested_conflict_call_groups() {
        let document = parse(
            r#"
<flowfacts>
  <function name="main">
    <conflict ordered="yes">
      <call name="outer">
        <call name="inner">
          <block address="0x2000"/>
        </call>
      </call>
    </conflict>
  </function>
</flowfacts>
"#,
            "nested.ffx",
        )
        .expect("parse");
        assert!(document.conflicts.is_empty());
        assert!(
            document
                .warnings
                .iter()
                .any(|warning| warning.contains("nested <call>"))
        );
    }

    #[test]
    fn parses_context_only_loop_and_all_iterations_conflict() {
        let document = parse(
            r#"
<flowfacts>
  <function name="main">
    <loop address="0x1000">
      <iteration number="*">
        <conflict>
          <block address="0x1002"/>
          <block address="0x1004"/>
        </conflict>
      </iteration>
    </loop>
  </function>
</flowfacts>
"#,
            "iteration.ffx",
        )
        .expect("parse");
        assert!(document.loops.is_empty());
        assert_eq!(document.conflicts.len(), 1);
        assert!(matches!(
            document.conflicts[0].loop_context,
            Some(LoopTarget::Address(0x1000))
        ));
        assert!(
            document
                .warnings
                .iter()
                .any(|warning| warning.contains("context only"))
        );
    }

    #[test]
    fn ignores_specific_iteration_conflicts() {
        let document = parse(
            r#"
<flowfacts>
  <function name="main">
    <loop address="0x1000">
      <iteration number="-1">
        <conflict>
          <block address="0x1002"/>
          <block address="0x1004"/>
        </conflict>
      </iteration>
    </loop>
  </function>
</flowfacts>
"#,
            "last-iteration.ffx",
        )
        .expect("parse");
        assert!(document.conflicts.is_empty());
        assert!(
            document
                .warnings
                .iter()
                .any(|warning| warning.contains("iteration-specific"))
        );
    }

    #[test]
    fn rejects_branch_fact_without_location() {
        let error = parse(
            "<flowfacts><function name=\"main\"><conditional><case cond=\"1\" executed=\"false\"/></conditional></function></flowfacts>",
            "bad.ffx",
        )
        .expect_err("missing location");
        assert!(error.contains("needs address"));
    }
}
