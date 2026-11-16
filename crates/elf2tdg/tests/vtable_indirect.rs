//! Interprocedural function-pointer and vtable resolution tests.
//!
//! These compile tiny C/C++ programs on demand and skip when the host
//! compiler is unavailable.

use std::path::PathBuf;
use std::process::Command;

use elf2tdg::analysis::{AnalysisOptions, analyze_with_cfg};
use elf2tdg::loader;

fn tool_available(tool: &str) -> bool {
    Command::new(tool)
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success())
}

fn compile(compiler: &str, source_name: &str, source: &str) -> Option<PathBuf> {
    compile_with_optimization(compiler, source_name, source, "-O0")
}

fn compile_with_optimization(
    compiler: &str,
    source_name: &str,
    source: &str,
    optimization: &str,
) -> Option<PathBuf> {
    if !tool_available(compiler) {
        eprintln!("skipping {source_name}: {compiler} is not available");
        return None;
    }
    let directory =
        std::env::temp_dir().join(format!("elf2tdg-{}-{}", source_name, std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).ok()?;
    let source_path = directory.join(source_name);
    std::fs::write(&source_path, source).ok()?;
    let binary = directory.join("fixture");
    let status = Command::new(compiler)
        .args([optimization, "-g", "-fno-inline", "-fno-pie", "-no-pie"])
        .arg("-o")
        .arg(&binary)
        .arg(&source_path)
        .status()
        .ok()?;
    if status.success() && binary.exists() {
        Some(binary)
    } else {
        eprintln!("skipping {source_name}: compilation failed");
        None
    }
}

#[test]
fn resolves_function_pointer_passed_to_a_dispatch_helper() {
    let source = r"
__attribute__((noinline)) int impl(int x) { return x + 7; }
__attribute__((noinline)) int dispatch(int (*fn)(int), int x) { return fn(x); }
int main(void) { return dispatch(impl, 35) == 42 ? 0 : 1; }
";
    let Some(binary) = compile("gcc", "function_pointer.c", source) else {
        return;
    };
    let image = loader::load(&binary).expect("C fixture must load");
    let analysis =
        analyze_with_cfg(&image, &AnalysisOptions::default()).expect("analysis must succeed");
    let dispatch = analysis
        .cfg
        .functions
        .iter()
        .find(|function| function.primary_name == "dispatch")
        .expect("dispatch function");
    let call = dispatch
        .cfg
        .blocks_by_address
        .values()
        .flat_map(|node| dispatch.cfg.graph[*node].calls.iter())
        .find(|call| !call.direct)
        .expect("indirect call in dispatch");
    assert!(!call.unresolved);
    let target = call
        .target_function
        .as_ref()
        .and_then(|id| analysis.cfg.function(id))
        .expect("resolved callee");
    assert_eq!(target.primary_name, "impl");
    assert!(
        analysis
            .tdg
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "resolved-forwarded-indirect-call")
    );
}

#[test]
fn resolves_cpp_vtable_call_from_static_caller_argument() {
    let source = r"
struct Base { virtual int f(int x) = 0; virtual ~Base() {} };
struct Derived : Base { int f(int x) override { return x + 7; } };
static Derived obj;
__attribute__((noinline)) int dispatch(Base& b, int x) { return b.f(x); }
int main() { return dispatch(obj, 35) == 42 ? 0 : 1; }
";
    let Some(binary) = compile("g++", "vtable_dispatch.cpp", source) else {
        return;
    };
    let image = loader::load(&binary).expect("C++ fixture must load");
    let analysis =
        analyze_with_cfg(&image, &AnalysisOptions::default()).expect("analysis must succeed");
    let dispatch = analysis
        .cfg
        .functions
        .iter()
        .find(|function| {
            function.primary_name.contains("dispatch") && !function.primary_name.contains("GLOBAL")
        })
        .expect("dispatch function");
    let call = dispatch
        .cfg
        .blocks_by_address
        .values()
        .flat_map(|node| dispatch.cfg.graph[*node].calls.iter())
        .find(|call| !call.direct)
        .expect("vtable call in dispatch");
    assert!(!call.unresolved);
    let target = call
        .target_function
        .as_ref()
        .and_then(|id| analysis.cfg.function(id))
        .expect("resolved virtual callee");
    assert!(target.primary_name.contains("Derived"));
    assert!(target.primary_name.contains('f'));
    assert!(
        analysis
            .tdg
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "resolved-forwarded-indirect-call")
    );
}

#[test]
fn resolves_indirect_tail_call_through_caller_argument() {
    let source = r"
__attribute__((noinline)) int impl(int x) { return x + 7; }
__attribute__((noinline)) int dispatch(int (*fn)(int), int x) { return fn(x); }
int main(void) { return dispatch(impl, 35) == 42 ? 0 : 1; }
";
    let Some(binary) = compile_with_optimization("gcc", "function_pointer_tail.c", source, "-O2")
    else {
        return;
    };
    let image = loader::load(&binary).expect("C fixture must load");
    let analysis =
        analyze_with_cfg(&image, &AnalysisOptions::default()).expect("analysis must succeed");
    let dispatch = analysis
        .cfg
        .functions
        .iter()
        .find(|function| function.primary_name == "dispatch")
        .expect("dispatch function");
    let call = dispatch
        .cfg
        .blocks_by_address
        .values()
        .flat_map(|node| dispatch.cfg.graph[*node].calls.iter())
        .find(|call| call.tail && !call.direct)
        .expect("indirect tail call in dispatch");
    assert!(!call.unresolved);
    let target = call
        .target_function
        .as_ref()
        .and_then(|id| analysis.cfg.function(id))
        .expect("resolved tail callee");
    assert_eq!(target.primary_name, "impl");
    assert!(
        analysis
            .tdg
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "resolved-forwarded-indirect-jump")
    );
}

#[test]
fn resolves_cpp_vtable_tail_call_from_static_caller_argument() {
    let source = r"
struct Base { virtual int f(int x) = 0; virtual ~Base() {} };
struct Derived : Base { int f(int x) override { return x + 7; } };
static Derived obj;
__attribute__((noinline)) int dispatch(Base& b, int x) { return b.f(x); }
int main() { return dispatch(obj, 35) == 42 ? 0 : 1; }
";
    let Some(binary) = compile_with_optimization("g++", "vtable_tail.cpp", source, "-O2") else {
        return;
    };
    let image = loader::load(&binary).expect("C++ fixture must load");
    let analysis =
        analyze_with_cfg(&image, &AnalysisOptions::default()).expect("analysis must succeed");
    let dispatch = analysis
        .cfg
        .functions
        .iter()
        .find(|function| {
            function.primary_name.contains("dispatch") && !function.primary_name.contains("GLOBAL")
        })
        .expect("dispatch function");
    let call = dispatch
        .cfg
        .blocks_by_address
        .values()
        .flat_map(|node| dispatch.cfg.graph[*node].calls.iter())
        .find(|call| call.tail && !call.direct)
        .expect("vtable tail call in dispatch");
    assert!(!call.unresolved);
    let target = call
        .target_function
        .as_ref()
        .and_then(|id| analysis.cfg.function(id))
        .expect("resolved virtual tail callee");
    assert!(target.primary_name.contains("Derived"));
    assert!(target.primary_name.contains('f'));
}

#[test]
fn resolves_local_indirect_tail_jump_from_global_pointer() {
    let source = r"
__attribute__((noinline)) int impl(int x) { return x + 7; }
int (*volatile fp)(int) = impl;
__attribute__((noinline)) int dispatch(int x) { return fp(x); }
int main(void) { return dispatch(35) == 42 ? 0 : 1; }
";
    let Some(binary) = compile_with_optimization("gcc", "jump_pointer.c", source, "-O2") else {
        return;
    };
    let image = loader::load(&binary).expect("C fixture must load");
    let analysis =
        analyze_with_cfg(&image, &AnalysisOptions::default()).expect("analysis must succeed");
    let dispatch = analysis
        .cfg
        .functions
        .iter()
        .find(|function| function.primary_name == "dispatch")
        .expect("dispatch function");
    let call = dispatch
        .cfg
        .blocks_by_address
        .values()
        .flat_map(|node| dispatch.cfg.graph[*node].calls.iter())
        .find(|call| call.tail && !call.direct)
        .expect("indirect tail jump in dispatch");
    assert!(!call.unresolved);
    let target = call
        .target_function
        .as_ref()
        .and_then(|id| analysis.cfg.function(id))
        .expect("resolved tail callee");
    assert_eq!(target.primary_name, "impl");
    assert!(
        analysis
            .tdg
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "resolved-indirect-jump")
    );
}
