# AGENTS.md - Developer Guide for Angora Fuzzer

## Build & Test Commands
- **Build**: `cargo build --release` or `./build/build.sh` (full build with LLVM passes)
- **Test all**: `cargo test` from project root
- **Test single**: `cd tests && ./test.sh <dirname>` (e.g., `./test.sh mini`, `./test.sh if_eq`)
- **Test env vars**: `RELEASE=1` for release build, `LLVM_MODE=1` or `PIN_MODE=1` for mode selection
- **Lint/Format**: `cargo fmt` (uses rustfmt.toml: 4-space indent, merge_imports, SameLineWhere braces)

## Code Style Guidelines
- **Rust**: Edition 2018, stable toolchain; snake_case (funcs/vars), UpperCamelCase (types), SCREAMING_SNAKE_CASE (consts)
- **Imports**: Group as std → external crates → internal modules; use `merge_imports`
- **Error handling**: Use Result types, log with `log` crate (trace/debug/info/warn/error), avoid unwrap in production
- **Visibility**: Internal by default, explicit `pub` for external APIs
- **C++ (LLVM passes)**: Standard LLVM style, group includes (system → llvm → local)

## Architecture
- Workspace: common, fuzzer, runtime, runtime_fast
- Two-binary strategy: `.taint` (DFSan tracking) + `.fast` (lightweight instrumentation)
- LLVM passes in `llvm_mode/pass/` (C++), compiled via CMake to `bin/`
