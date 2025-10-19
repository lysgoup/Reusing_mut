# AGENTS.md - Developer Guide for Angora Fuzzer

## Build & Test Commands
- **Build**: `cargo build --release` (from root) or `./build/build.sh` (full build with LLVM)
- **Test single**: `cd tests && ./test.sh <testname>` (e.g., `./test.sh mini`)
- **Test script vars**: Set `BUILD_TYPE=release` or `LLVM_MODE=1` or `PIN_MODE=1` as needed
- **Lint**: Use `rustfmt` with config in `rustfmt.toml` (4 spaces, merge imports, same-line braces)

## Code Style Guidelines
- **Language**: Rust 2018 edition, stable toolchain
- **Formatting**: 4-space indentation, `brace_style = "SameLineWhere"`, `control_brace_style = "AlwaysSameLine"`
- **Imports**: Group and merge with `merge_imports = true`, structured as: std → external crates → internal modules
- **Types**: Explicit types preferred, especially for public APIs; use derive_more for common traits
- **Naming**: snake_case for functions/variables, UpperCamelCase for types, SCREAMING_SNAKE_CASE for constants
- **Error handling**: Use Result types, log errors with `log` crate macros (trace/debug/info/warn/error)
- **Modules**: Internal visibility by default, explicit `pub` for external APIs
- **Documentation**: Minimal inline comments; let code be self-documenting; see LLVM passes for C++ style

## Architecture Notes
- Rust workspace with 4 members: common, fuzzer, runtime, runtime_fast
- Two-binary strategy: `.taint` (DFSan tracking) and `.fast` (lightweight instrumentation)
- LLVM passes in `llvm_mode/pass/` (C++), runtime in Rust, fuzzer logic in `fuzzer/src/`
- Shared memory for branch/condition communication between runtime and fuzzer
