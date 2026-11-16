//! Prints the JSON Schema for the TDG document format.

fn main() {
    let schema = elf2tdg_schema::Tdg::json_schema();
    println!(
        "{}",
        serde_json::to_string_pretty(&schema).expect("schema must be serializable")
    );
}
