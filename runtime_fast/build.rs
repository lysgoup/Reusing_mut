extern crate cc;

use std::fs;

/// Single source of truth: read DATA_MAP_SIZE_POW2 from common/src/config.rs so
/// the StorFuzz runtime map matches the fuzzer (data_cov.rs) and the LLVM pass.
fn data_map_pow2() -> String {
    let txt = fs::read_to_string("../common/src/config.rs").unwrap_or_default();
    for line in txt.lines() {
        let line = line.trim();
        if line.starts_with("pub const DATA_MAP_SIZE_POW2") {
            if let Some(eq) = line.find('=') {
                let digits: String =
                    line[eq + 1..].chars().filter(|c| c.is_ascii_digit()).collect();
                if !digits.is_empty() {
                    return digits;
                }
            }
        }
    }
    "17".to_string()
}

fn main() {
    let pow2 = data_map_pow2();
    cc::Build::new()
        .file("src/context.c")
        .file("src/storfuzz_rt.c")
        .define("STORFUZZ_MAP_SIZE_POW2", pow2.as_str())
        .compile("libcontext.a");
    println!("cargo:rerun-if-changed=src/storfuzz_rt.c");
    println!("cargo:rerun-if-changed=../common/src/config.rs");
}
