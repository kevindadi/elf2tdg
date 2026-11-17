//! DWARF type/variable recovery and typed points-to.
//!
//! The fixture declares a function-pointer array, aggregate objects with a
//! function-pointer member, global pointers to those objects, and a local
//! function pointer. The analyzer must expose the type/layout metadata, use
//! the DWARF object bounds for table scans, and resolve a dynamic
//! `ops->run()` call from typed global objects.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use elf2tdg::analysis::{AnalysisOptions, analyze_with_cfg};
use elf2tdg::cfg::{CfgCallSite, ProgramCfg};
use elf2tdg::dwarf::DwarfInfo;
use elf2tdg::loader;
use elf2tdg_schema::Tdg;

const SOURCE: &str = r"
#include <stddef.h>

struct ops { void (*run)(void); int value; };

volatile int selector;

static void cmd_a(void) { }
static void cmd_b(void) { }
static void cmd_c(void) { }
static void cmd_d(void) { }
static void (*const commands[])(void) = { cmd_a, cmd_b, cmd_c, cmd_d };

static void handler_a(void) { }
static void handler_b(void) { }
static struct ops op_array[2] = { { handler_a, 1 }, { handler_b, 2 } };
static struct ops *ptr_a = &op_array[0];
static struct ops *ptr_b = &op_array[1];

__attribute__((noinline)) void dispatch(struct ops *ops) {
    ops->run();
}

int main(void) {
    commands[selector & 3]();
    dispatch(ptr_a);
    dispatch(ptr_b);
    void (*local)(void) = handler_a;
    local();
    return 0;
}
";

fn tool_available(tool: &str) -> bool {
    Command::new(tool)
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success())
}

fn compile(compiler: &str, source_name: &str, args: &[&str]) -> Option<PathBuf> {
    if !tool_available(compiler) {
        eprintln!("skipping {source_name}: {compiler} is not available");
        return None;
    }
    let directory =
        std::env::temp_dir().join(format!("elf2tdg-{source_name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).ok()?;
    let source_path = directory.join(source_name);
    std::fs::write(&source_path, SOURCE).ok()?;
    let binary = directory.join("fixture");
    let status = Command::new(compiler)
        .args(args)
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

fn compile_host(source_name: &str) -> Option<PathBuf> {
    compile(
        "gcc",
        source_name,
        &[
            "-O0",
            "-g",
            "-fno-inline",
            "-fno-builtin",
            "-fno-pie",
            "-no-pie",
        ],
    )
}

fn compile_thumb(source_name: &str) -> Option<PathBuf> {
    compile(
        "arm-none-eabi-gcc",
        source_name,
        &[
            "-O0",
            "-g",
            "-mthumb",
            "-mcpu=cortex-m4",
            "-nostdlib",
            "-ffreestanding",
            "-Wl,-Ttext=0x8000000",
            "-Wl,-e,main",
        ],
    )
}

fn variable<'a>(dwarf: &'a DwarfInfo, name: &str) -> &'a elf2tdg::dwarf::DwarfVariable {
    dwarf
        .variables
        .iter()
        .find(|variable| variable.name.as_deref() == Some(name))
        .unwrap_or_else(|| panic!("missing DWARF variable {name}"))
}

fn field_member<'a>(
    dwarf: &'a DwarfInfo,
    aggregate_index: usize,
    name: &str,
) -> &'a elf2tdg::dwarf::DwarfMember {
    dwarf
        .aggregates
        .get(aggregate_index)
        .and_then(|aggregate| {
            aggregate
                .members
                .iter()
                .find(|member| member.name.as_deref() == Some(name))
        })
        .unwrap_or_else(|| panic!("missing member {name} in aggregate {aggregate_index}"))
}

fn candidate_names(cfg: &ProgramCfg, call: &CfgCallSite) -> BTreeSet<String> {
    let targets: Vec<u64> = if call.candidates.is_empty() {
        call.target.into_iter().collect()
    } else {
        call.candidates
            .iter()
            .map(|candidate| candidate.target)
            .collect()
    };
    targets
        .into_iter()
        .filter_map(|target| cfg.function_at(target))
        .map(|function| function.primary_name.clone())
        .collect()
}

fn indirect_calls<'a>(cfg: &'a ProgramCfg, caller: &str) -> Vec<&'a CfgCallSite> {
    let function = cfg
        .functions
        .iter()
        .find(|function| function.primary_name == caller)
        .unwrap_or_else(|| panic!("missing caller {caller}"));
    function
        .cfg
        .blocks_by_address
        .values()
        .flat_map(|node| function.cfg.graph[*node].calls.iter())
        .chain(function.cfg.recovered_calls.iter())
        .filter(|call| !call.direct)
        .collect()
}

fn assert_type_metadata(image: &loader::Image) {
    let dwarf = image.dwarf.as_ref().expect("fixture must retain DWARF");
    let pointer_size = image.pointer_size() as u64;

    let commands = variable(dwarf, "commands");
    assert_eq!(commands.byte_size, Some(4 * pointer_size));
    assert_eq!(commands.array_count, Some(4));
    assert!(commands.function_pointer_array);
    let commands_address = commands.address.expect("commands address");
    assert_eq!(
        dwarf.object_end_at(commands_address),
        Some(commands_address + 4 * pointer_size)
    );
    assert!(dwarf.variable_at(commands_address).is_some());

    let ptr_a = variable(dwarf, "ptr_a");
    let aggregate_index = ptr_a
        .pointee_aggregate_index
        .expect("ptr_a pointee aggregate");
    let aggregate = &dwarf.aggregates[aggregate_index];
    assert_eq!(aggregate.name.as_deref(), Some("ops"));
    let run = field_member(dwarf, aggregate_index, "run");
    assert_eq!(run.offset, 0);
    assert!(run.function_pointer);
    assert!(dwarf.function_pointer_field_at(0).is_some());
    let ptr_b = variable(dwarf, "ptr_b");
    assert_eq!(ptr_b.pointee_aggregate_index, Some(aggregate_index));

    let op_array = variable(dwarf, "op_array");
    assert_eq!(op_array.array_count, Some(2));
    assert_eq!(
        op_array.byte_size,
        Some(2 * aggregate.byte_size.expect("ops size"))
    );
    let op_array_address = op_array.address.expect("op_array address");
    assert!(!op_array.function_pointer_array);
    assert_eq!(
        dwarf.object_end_at(op_array_address),
        Some(op_array_address + op_array.byte_size.expect("op_array size"))
    );

    let local = variable(dwarf, "local");
    assert!(local.function_pointer);
    assert!(local.address.is_none());
    assert!(local.frame_offset.is_some() || local.call_frame_offset.is_some());

    let parameter = dwarf
        .variables
        .iter()
        .find(|variable| variable.name.as_deref() == Some("ops") && variable.is_parameter)
        .expect("dispatch parameter");
    assert!(parameter.pointee_aggregate_index.is_some());
    if let (Some(function_low), Some(frame_offset)) =
        (parameter.function_low, parameter.frame_offset)
    {
        assert!(
            dwarf
                .local_variable_at(function_low, frame_offset)
                .is_some()
        );
    }
}

fn assert_typed_dispatch(binary: &Path) {
    let image = loader::load(binary).expect("fixture must load");
    let analysis =
        analyze_with_cfg(&image, &AnalysisOptions::default()).expect("analysis must succeed");
    let tdg: &Tdg = &analysis.tdg;
    tdg.ensure_valid().expect("TDG must validate");
    assert_type_metadata(&image);

    let calls = indirect_calls(&analysis.cfg, "dispatch");
    assert_eq!(calls.len(), 1, "dispatch has one indirect call site");
    let call = calls[0];
    assert!(!call.unresolved);
    assert_eq!(
        candidate_names(&analysis.cfg, call),
        BTreeSet::from(["handler_a".to_owned(), "handler_b".to_owned()])
    );

    let table = indirect_calls(&analysis.cfg, "main")
        .into_iter()
        .find(|call| candidate_names(&analysis.cfg, call).contains("cmd_a"))
        .expect("indexed command table call");
    assert_eq!(
        candidate_names(&analysis.cfg, table),
        BTreeSet::from([
            "cmd_a".to_owned(),
            "cmd_b".to_owned(),
            "cmd_c".to_owned(),
            "cmd_d".to_owned()
        ])
    );

    assert!(
        tdg.diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "resolved-typed-field-candidates"),
        "missing typed-field diagnostic"
    );

    let _ = std::fs::remove_dir_all(binary.parent().expect("fixture directory"));
}

#[test]
fn recovers_types_variables_and_typed_field_targets() {
    let Some(binary) = compile_host("dwarf_types.c") else {
        return;
    };
    assert_typed_dispatch(&binary);
}

#[test]
fn recovers_typed_dispatch_on_thumb() {
    let Some(binary) = compile_thumb("dwarf_types_thumb.c") else {
        return;
    };
    assert_typed_dispatch(&binary);
}

#[test]
fn bounds_tables_with_dwarf_variables_after_symbol_strip() {
    if !tool_available("objcopy") {
        eprintln!("skipping DWARF table-bound test: objcopy is not available");
        return;
    }
    let Some(binary) = compile_host("dwarf_types_strip.c") else {
        return;
    };
    let image = loader::load(&binary).expect("fixture must load");
    let dwarf = image.dwarf.as_ref().expect("fixture must retain DWARF");
    let commands = variable(dwarf, "commands");
    let address = commands.address.expect("commands address");
    assert!(image.data_symbols.contains_key(&address));

    let stripped = binary.with_file_name("fixture-stripped");
    let status = Command::new("objcopy")
        .arg("--strip-symbol=commands")
        .arg(&binary)
        .arg(&stripped)
        .status()
        .ok();
    assert!(
        status.is_some_and(|status| status.success()),
        "objcopy must strip the commands symbol"
    );
    let stripped_image = loader::load(&stripped).expect("stripped fixture must load");
    assert!(!stripped_image.data_symbols.contains_key(&address));
    let stripped_dwarf = stripped_image
        .dwarf
        .as_ref()
        .expect("fixture must retain DWARF");
    let stripped_commands = variable(stripped_dwarf, "commands");
    assert_eq!(stripped_commands.address, Some(address));
    assert_eq!(
        stripped_dwarf.object_end_at(address),
        Some(address + stripped_commands.byte_size.expect("commands size"))
    );

    let analysis = analyze_with_cfg(&stripped_image, &AnalysisOptions::default())
        .expect("analysis must succeed");
    analysis.tdg.ensure_valid().expect("TDG must validate");
    let table = indirect_calls(&analysis.cfg, "main")
        .into_iter()
        .find(|call| candidate_names(&analysis.cfg, call).contains("cmd_a"))
        .expect("indexed command table call");
    assert_eq!(
        candidate_names(&analysis.cfg, table),
        BTreeSet::from([
            "cmd_a".to_owned(),
            "cmd_b".to_owned(),
            "cmd_c".to_owned(),
            "cmd_d".to_owned()
        ])
    );
    let _ = std::fs::remove_dir_all(binary.parent().expect("fixture directory"));
}
