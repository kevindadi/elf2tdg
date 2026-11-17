//! Noreturn classification and call-continuation semantics.
//!
//! The fixture uses a halt loop, a forwarded function pointer to `_exit`, and
//! a direct call whose continuation is emitted by GCC because `_exit` is
//! declared without the noreturn attribute. The analyzer must classify the
//! halt loop from its CFG, suppress continuations after the exit calls, and
//! keep the shared return block of a conditional halt call.

use std::path::PathBuf;
use std::process::Command;

use elf2tdg::analysis::{AnalysisOptions, analyze_with_cfg};
use elf2tdg::cfg::{self, CfgEdgeKind, CfgNoreturnReason, CfgTerminator, FunctionCfg};
use elf2tdg::loader;
use elf2tdg_schema::{Edge, FunctionKind};
use petgraph::visit::IntoEdgeReferences;

const SOURCE: &str = r#"
extern void _exit(int);

__attribute__((noinline, noreturn)) static void halt_forever(void) {
    for (;;) {
        __asm__ volatile("" ::: "memory");
    }
}

__attribute__((noinline)) static int call_through_pointer(void (*fn)(void)) {
    fn();
    return 3;
}

__attribute__((noinline)) static int indirect_exit(void) {
    return call_through_pointer((void (*)(void))_exit);
}

__attribute__((noinline)) static int direct_exit(int code) {
    _exit(code);
    return 9;
}

__attribute__((noinline)) static int halt_if(int x) {
    if (x) {
        halt_forever();
    }
    return x + 1;
}

int main(int argc, char **argv) {
    (void)argv;
    int x = halt_if(argc);
    x += indirect_exit();
    x += direct_exit(argc);
    return x;
}
"#;

fn compile_fixture() -> Option<PathBuf> {
    let available = Command::new("gcc")
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success());
    if !available {
        eprintln!("skipping noreturn fixture: gcc is not available");
        return None;
    }
    let directory = std::env::temp_dir().join(format!("elf2tdg-noreturn-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).ok()?;
    let source = directory.join("noreturn.c");
    std::fs::write(&source, SOURCE).ok()?;
    let binary = directory.join("noreturn");
    let status = Command::new("gcc")
        .args([
            "-O0",
            "-g",
            "-fno-inline",
            "-fno-builtin",
            "-fno-pie",
            "-no-pie",
            "-o",
        ])
        .arg(&binary)
        .arg(&source)
        .status()
        .ok()?;
    if status.success() && binary.exists() {
        Some(binary)
    } else {
        eprintln!("skipping noreturn fixture: compilation failed");
        None
    }
}

fn function<'a>(program: &'a cfg::ProgramCfg, name: &str) -> &'a cfg::CfgFunction {
    program
        .functions
        .iter()
        .find(|function| function.primary_name == name)
        .unwrap_or_else(|| panic!("missing CFG function {name}"))
}

fn call_to(program: &cfg::ProgramCfg, cfg: &FunctionCfg, target_name: &str) -> cfg::CfgCallSite {
    cfg.blocks_by_address
        .values()
        .flat_map(|node| cfg.graph[*node].calls.iter())
        .find(|call| {
            call.target_function
                .as_ref()
                .and_then(|id| program.function(id))
                .is_some_and(|function| function.primary_name == target_name)
        })
        .unwrap_or_else(|| panic!("missing call to {target_name}"))
        .clone()
}

fn call_block(cfg: &FunctionCfg, site: u64) -> &cfg::CfgBlock {
    cfg.blocks_by_address
        .values()
        .map(|node| &cfg.graph[*node])
        .find(|block| block.calls.iter().any(|call| call.site == site))
        .unwrap_or_else(|| panic!("missing call block for 0x{site:x}"))
}

#[test]
#[allow(clippy::too_many_lines)]
fn suppresses_noreturn_continuations_and_keeps_shared_returns() {
    if !cfg!(target_arch = "x86_64") {
        eprintln!("skipping noreturn fixture: host-specific code generation");
        return;
    }
    let Some(binary) = compile_fixture() else {
        return;
    };
    let image = loader::load(&binary).expect("fixture must load");
    let analysis =
        analyze_with_cfg(&image, &AnalysisOptions::default()).expect("analysis must succeed");
    let tdg = &analysis.tdg;
    tdg.ensure_valid().expect("TDG must validate");

    let halt = function(&analysis.cfg, "halt_forever");
    assert_eq!(halt.noreturn, Some(CfgNoreturnReason::ControlFlow));
    assert_eq!(
        halt.cfg.blocks_by_address.len(),
        2,
        "halt loop has prologue and loop blocks"
    );
    assert!(
        halt.cfg
            .blocks_by_address
            .values()
            .any(|node| halt.cfg.graph[*node].terminator == CfgTerminator::Jump)
    );

    // The indirect call is resolved through the caller argument. `_exit` is
    // an API-level noreturn function, so the post-return block must vanish.
    let indirect = function(&analysis.cfg, "call_through_pointer");
    assert_eq!(indirect.noreturn, Some(CfgNoreturnReason::ControlFlow));
    let call = call_to(&analysis.cfg, &indirect.cfg, "_exit");
    assert!(call.noreturn);
    assert!(!call.direct && !call.unresolved && !call.null_target);
    let indirect_site = call.site;
    let block = call_block(&indirect.cfg, indirect_site);
    assert_eq!(block.terminator, CfgTerminator::NoreturnCall);
    assert_eq!(indirect.cfg.blocks_by_address.len(), 1);
    assert_eq!(indirect.cfg.graph.edge_count(), 0);

    // GCC declared `_exit` without noreturn here, so it emitted a return path.
    // The analyzer must remove that path from the direct call site.
    let direct = function(&analysis.cfg, "direct_exit");
    assert_eq!(direct.noreturn, Some(CfgNoreturnReason::ControlFlow));
    let call = call_to(&analysis.cfg, &direct.cfg, "_exit");
    let direct_site = call.site;
    assert!(call.direct && call.noreturn && !call.unresolved);
    assert_eq!(
        call_block(&direct.cfg, direct_site).terminator,
        CfgTerminator::NoreturnCall
    );
    assert_eq!(direct.cfg.blocks_by_address.len(), 1);
    assert_eq!(direct.cfg.graph.edge_count(), 0);

    // A conditional halt call cannot return when taken, but the other branch
    // still reaches the shared return block. Only the call-return edge goes.
    let halt_if = function(&analysis.cfg, "halt_if");
    assert_eq!(halt_if.noreturn, None);
    let call = call_to(&analysis.cfg, &halt_if.cfg, "halt_forever");
    let halt_site = call.site;
    assert!(call.noreturn && call.direct);
    let conditional_block = call_block(&halt_if.cfg, halt_site);
    assert_eq!(conditional_block.terminator, CfgTerminator::NoreturnCall);
    assert!(
        !halt_if.cfg.graph.edge_references().any(|edge| {
            edge.weight().kind == CfgEdgeKind::CallReturn && edge.weight().site == halt_site
        }),
        "noreturn call must not have a call-return edge"
    );
    assert!(
        halt_if
            .cfg
            .blocks_by_address
            .values()
            .any(|node| halt_if.cfg.graph[*node].terminator == CfgTerminator::Return),
        "shared return block must remain reachable from the other branch"
    );
    assert_eq!(halt_if.cfg.blocks_by_address.len(), 3);

    // The TDG keeps call edges to noreturn targets, marks the function
    // metadata, and exposes empty successor sets for the removed continuations.
    let exit = tdg
        .functions
        .iter()
        .find(|function| function.primary_name == "_exit")
        .expect("external _exit function");
    assert_eq!(exit.kind, FunctionKind::Plt);
    assert_eq!(
        exit.ext
            .get("elf2tdg.noreturn")
            .and_then(serde_json::Value::as_bool),
        Some(true)
    );
    assert!(
        tdg.edges.iter().any(|edge| matches!(
            edge,
            Edge::Call { caller, callee, site, direct: false, .. }
                if caller == &indirect_id(tdg) && callee == &exit.id && site.get() == indirect_site
        )),
        "noreturn call edge must remain in the TDG"
    );
    assert!(
        tdg.edges.iter().any(|edge| matches!(
            edge,
            Edge::Call { caller, callee, site, direct: true, .. }
                if caller == &direct_id(tdg) && callee == &exit.id && site.get() == direct_site
        )),
        "direct noreturn call edge must remain in the TDG"
    );
    let halt_if_schema = tdg
        .functions
        .iter()
        .find(|function| function.primary_name == "halt_if")
        .expect("halt_if TDG function");
    assert_eq!(halt_if_schema.ext.get("elf2tdg.noreturn"), None);
    assert!(
        halt_if_schema
            .blocks
            .iter()
            .find(|block| block.id == conditional_block.id)
            .is_some_and(|block| block.successors.is_empty())
    );

    let selected: Vec<&cfg::CfgFunction> = ["call_through_pointer", "halt_if"]
        .iter()
        .map(|name| function(&analysis.cfg, name))
        .collect();
    let json = cfg::render_json_selected(&analysis.cfg, tdg, &selected, false).expect("CFG JSON");
    let value: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    assert_eq!(value["cfg_schema_version"], cfg::CFG_SCHEMA_VERSION);
    assert_eq!(value["functions"][0]["noreturn"], "control-flow");
    assert_eq!(value["functions"][1]["noreturn"], serde_json::Value::Null);
    assert!(
        json.contains("\"noreturn-call\""),
        "CFG JSON should expose noreturn-call terminators"
    );
    assert!(
        json.contains("\"noreturn\": true"),
        "CFG JSON should expose noreturn call sites"
    );

    let _ = std::fs::remove_dir_all(binary.parent().expect("fixture directory"));
}

fn indirect_id(tdg: &elf2tdg_schema::Tdg) -> elf2tdg_schema::FunctionId {
    tdg.functions
        .iter()
        .find(|function| function.primary_name == "call_through_pointer")
        .expect("call_through_pointer TDG function")
        .id
        .clone()
}

fn direct_id(tdg: &elf2tdg_schema::Tdg) -> elf2tdg_schema::FunctionId {
    tdg.functions
        .iter()
        .find(|function| function.primary_name == "direct_exit")
        .expect("direct_exit TDG function")
        .id
        .clone()
}
