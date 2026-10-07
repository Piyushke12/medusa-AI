//! Dump every builtin tool definition as tab-separated rows so external
//! scripts can batch-test the registry argv against real binaries:
//! id <TAB> exe_candidates(|) <TAB> version_args <TAB> default_args
//! Usage: cargo run --example dump_tools

fn main() {
    for t in medusa_lib::registry::tools::builtin_tools() {
        println!(
            "{}\t{}\t{}\t{}",
            t.id,
            t.executable_candidates.join("|"),
            t.version_args.join(" "),
            t.default_args.join(" ")
        );
    }
}
