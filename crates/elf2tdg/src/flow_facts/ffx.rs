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
//! `<call name="...">` nesting is retained as context. Because the current
//! WCET analysis is context-insensitive, context-specific facts are merged
//! conservatively and reported as warnings.

use roxmltree::{Document, Node};

use super::{
    BranchFact, BranchOutcome, CallFact, CallTarget, FlowFactDocument, LocationTarget, LoopFact,
    LoopTarget,
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
            warnings: Vec::new(),
        },
        function: None,
        calls: Vec::new(),
    };
    process_children(root, &mut state, origin)?;
    Ok(state.document)
}

struct State {
    document: FlowFactDocument,
    function: Option<String>,
    calls: Vec<String>,
}

fn process_children(node: Node<'_, '_>, state: &mut State, origin: &str) -> Result<(), String> {
    for child in node.children().filter(Node::is_element) {
        match child.tag_name().name() {
            "function" => {
                let name = attribute(&child, "name")
                    .ok_or_else(|| format!("{origin}: <function> lacks a name"))?;
                let old_function = state.function.replace(name.to_owned());
                let old_calls = std::mem::take(&mut state.calls);
                process_children(child, state, origin)?;
                state.function = old_function;
                state.calls = old_calls;
            }
            "call" => {
                let name = attribute(&child, "name")
                    .ok_or_else(|| format!("{origin}: <call> lacks a name"))?;
                if let Some((fact, warnings)) = parse_call(&child, state, origin)? {
                    state.document.calls.push(fact);
                    state.document.warnings.extend(warnings);
                }
                let old_function = state.function.replace(name.to_owned());
                state.calls.push(name.to_owned());
                process_children(child, state, origin)?;
                state.calls.pop();
                state.function = old_function;
            }
            "loop" => {
                let (fact, warnings) = parse_loop(&child, state, origin)?;
                state.document.loops.push(fact);
                state.document.warnings.extend(warnings);
                process_children(child, state, origin)?;
            }
            "conditional" => {
                parse_conditional(&child, state, origin)?;
            }
            "iteration" => {
                state.document.warnings.push(format!(
                    "{origin}: iteration-specific FFX facts are ignored because the analysis is not iteration-sensitive"
                ));
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
            max,
            context: state.calls.clone(),
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
            context: state.calls.clone(),
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
                context: state.calls.clone(),
            });
            location = Some(case_location);
        }
        process_children(case, state, origin)?;
    }
    Ok(())
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
        let function = state.function.clone().ok_or_else(|| {
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
            function: state.function.clone(),
            file: source.to_owned(),
            line: parse_u32(line)?,
        }));
    }
    Ok(None)
}

fn parse_bool(value: &str) -> Result<bool, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "1" => Ok(true),
        "false" | "0" => Ok(false),
        _ => Err(format!("invalid boolean {value:?}")),
    }
}

fn parse_loop(
    node: &Node<'_, '_>,
    state: &State,
    origin: &str,
) -> Result<(LoopFact, Vec<String>), String> {
    let mut warnings = Vec::new();
    let max = if let Some(value) = attribute(node, "maxcount").or_else(|| attribute(node, "max")) {
        parse_u32(value)?
    } else {
        let Some(total) = attribute(node, "totalcount").or_else(|| attribute(node, "total")) else {
            return Err(format!(
                "{origin}: <loop> lacks maxcount/max and totalcount/total"
            ));
        };
        warnings.push("loop has only a total count; using it as the per-entry bound".to_owned());
        parse_u32(total)?
    };
    if max == 0 {
        return Err(format!("{origin}: loop max bound must be positive"));
    }

    let offset = attribute(node, "offset");
    let source = attribute(node, "source");
    let line = attribute(node, "line");
    let target = if let Some(offset) = offset {
        if source.is_some() {
            warnings.push("loop has both offset and source/line; using offset".to_owned());
        }
        let function = state.function.clone().ok_or_else(|| {
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
            function: state.function.clone(),
            file: source.to_owned(),
            line: parse_u32(line)?,
        }
    } else {
        return Err(format!(
            "{origin}: <loop> needs offset, address, or source/line"
        ));
    };

    Ok((
        LoopFact {
            target,
            max,
            context: state.calls.clone(),
        },
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
    use crate::flow_facts::LoopTarget;

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
        assert_eq!(document.loops[0].context, vec!["g1", "f"]);
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
    use crate::flow_facts::{BranchOutcome, CallTarget, LocationTarget};

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
    fn rejects_branch_fact_without_location() {
        let error = parse(
            "<flowfacts><function name=\"main\"><conditional><case cond=\"1\" executed=\"false\"/></conditional></function></flowfacts>",
            "bad.ffx",
        )
        .expect_err("missing location");
        assert!(error.contains("needs address"));
    }
}
