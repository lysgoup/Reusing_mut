# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Angora is a mutation-based coverage-guided fuzzer that increases branch coverage by solving path constraints without symbolic execution. It uses a hybrid approach with two instrumented binaries: one with taint tracking (DFSan-based) and one with lightweight branch/constraint instrumentation.

**Key paper**: "Angora: Efficient Fuzzing by Principled Search" (S&P 2018)

## Architecture

### Two-Binary Instrumentation Strategy

Angora requires compiling target programs twice with different instrumentation:

1. **Taint tracking binary** (`*.taint`): Uses DFSan (DataFlowSanitizer) to track which input bytes affect which branch conditions. Resource-intensive, used selectively.
2. **Fast binary** (`*.fast`): Lightweight instrumentation for branch coverage and constraint feedback. Used for most fuzzing iterations.

This separation ensures efficiency by avoiding the overhead of taint tracking on every execution.

### Component Structure

**Workspace layout** (Rust workspace with 4 members):
- `common/`: Shared constants, data structures (cond_stmt_base, config, defs, shm, tag)
- `fuzzer/`: Main fuzzer logic
  - `src/depot/`: Input/output file management
  - `src/executor/`: Target program execution management
  - `src/search/`: Exploration strategies for constraint solving
  - `src/cond_stmt/`: Conditional statement and constraint handling
  - `src/mut_input/`: Input mutation based on taint analysis
  - `src/track/`: Taint analysis result parsing
  - `src/stats/`: Statistics and UI
  - `src/branches/`: Branch coverage tracking
- `runtime/`: Taint tracking runtime (tags, heap mapping, logging)
- `runtime_fast/`: Fast mode runtime (branch/condition shared memory)

**LLVM instrumentation** (`llvm_mode/`):
- `pass/AngoraPass.cc`: Lightweight instrumentation pass for fast mode
- `pass/DFSanPass.cc`: Modified DFSan implementation for taint tracking
- `pass/UnfoldBranchPass.cc`: Branch unfolding for better analysis
- `compiler/angora_clang.c`: Compiler wrapper that invokes clang with appropriate flags
- `dfsan_rt/`: DFSan runtime library
- `external_lib/`: Models for external libraries (I/O functions, custom taint propagation)
- `rules/`: DFSan ABI lists for library handling
- `libcxx/`: DFSan-instrumented C++ standard library

**Pin mode** (`pin_mode/`): Alternative instrumentation using Intel Pin with libdft64 for taint tracking

## Building Angora

### Initial Setup

```bash
# Install LLVM (4.0.0 - 12.0.1)
PREFIX=/path-to-install ./build/install_llvm.sh

# Set environment variables in ~/.bashrc or ~/.zshrc
export PATH=/path-to-clang/bin:$PATH
export LD_LIBRARY_PATH=/path-to-clang/lib:$LD_LIBRARY_PATH

# Build Angora
./build/build.sh
```

The build script:
1. Builds Rust components (`cargo build --release`)
2. Installs fuzzer binary and static libraries to `bin/` directory
3. Builds LLVM passes and compiler wrappers via CMake
4. Installs instrumentation tools (angora-clang, angora-clang++) to `bin/`

**System configuration** (required):
```bash
echo core | sudo tee /proc/sys/kernel/core_pattern
```

### Testing the Build

```bash
cd tests
./test.sh mini
```

This compiles and fuzzes a simple test case to verify the installation.

## Building Target Programs

Target programs must be compiled twice with Angora's instrumenting compilers. The compilers are wrappers around clang that add instrumentation passes.

### Basic Compilation Pattern

```bash
# Fast mode (lightweight instrumentation)
USE_FAST=1 /path/to/angora/bin/angora-clang target.c -o target.fast

# Taint tracking mode
USE_TRACK=1 /path/to/angora/bin/angora-clang target.c -o target.taint
```

### Autoconf Projects

```bash
CC=/path/to/angora/bin/angora-clang \
CXX=/path/to/angora/bin/angora-clang++ \
LD=/path/to/angora/bin/angora-clang \
./configure --disable-shared

# Build taint tracking binary first
USE_TRACK=1 make -j
make install
# Save binary as *.taint

# Build fast binary
make clean
USE_FAST=1 make -j
make install
# Save binary as *.fast
```

**Important**: `--disable-shared` is required due to DFSan limitations with dynamic linking.

### CMake Projects

```bash
cmake -DCMAKE_C_COMPILER=/path/to/angora/bin/angora-clang \
      -DCMAKE_CXX_COMPILER=/path/to/angora/bin/angora-clang++ \
      -DBUILD_SHARED_LIBS=OFF ../src

USE_FAST=1 make
USE_TRACK=1 make
```

### Alternative: Using wllvm/gllvm

For complex build systems:

```bash
sudo pip install wllvm
export LLVM_COMPILER=clang
CC=wllvm CFLAGS=-O0 ./configure --disable-shared
make
extract-bc target
/path/to/angora/bin/angora-clang target.bc -o target.fast
USE_TRACK=1 /path/to/angora/bin/angora-clang target.bc -o target.taint
```

### Compilation Environment Variables

**Build mode control**:
- `USE_FAST=1`: Compile with lightweight branch/constraint instrumentation
- `USE_TRACK=1`: Compile with full taint tracking support
- `USE_DFSAN=1`: Enable DFSan for external libraries
- `ANGORA_USE_ASAN=1`: Enable AddressSanitizer (for bug detection)

**Instrumentation customization**:
- `ANGORA_CUSTOM_FN_CONTEXT=k`: Use last k (0-32) function calls as context (0 disables)
- `ANGORA_GEN_ID_RANDOM=1`: Generate random predicate IDs instead of location-based hashes
- `ANGORA_OUTPUT_COND_LOC=1`: Debug option to output predicate locations during compilation
- `ANGORA_INST_RATIO`: Control instrumentation density

**External library handling**:
- `ANGORA_TAINT_RULE_LIST=/path/to/abilist.txt`: DFSan ABI list for library taint rules
- `ANGORA_TAINT_CUSTOM_RULE=/path/to/object`: Custom taint propagation functions

### Handling External Libraries

Generate ABI lists for libraries not compiled with Angora:

```bash
# Ignore library (no taint propagation)
./tools/gen_library_abilist.sh /usr/lib/x86_64-linux-gnu/libz.so discard > zlib_abilist.txt

# Use functional rules (automatic taint propagation)
./tools/gen_library_abilist.sh /usr/lib/x86_64-linux-gnu/libz.so functional > zlib_abilist.txt

# Custom rules (write your own taint handlers in llvm_mode/external_lib/)
./tools/gen_library_abilist.sh /usr/lib/x86_64-linux-gnu/libz.so custom > zlib_abilist.txt

export ANGORA_TAINT_RULE_LIST=/path/to/zlib_abilist.txt
export ANGORA_TAINT_CUSTOM_RULE=/path/to/custom-func.o
```

Custom I/O functions can be added to `llvm_mode/external_lib/io-func.c`.

## Running Angora

### Basic Fuzzing Command

```bash
./angora_fuzzer -i input_dir -o output_dir \
    -t path/to/target.taint \
    -- path/to/target.fast [program arguments]
```

**Command structure**:
- `-i input_dir`: Directory containing seed inputs
- `-o output_dir`: Output directory for crashes, hangs, and queue
- `-t path/to/target.taint`: Taint tracking binary
- `-- path/to/target.fast [args]`: Fast binary and its arguments

Use `@@` in arguments as placeholder for input file path if program reads from file.

### Runtime Environment Variables

- `RUST_LOG=trace`: Enable tracing output for debugging
- `RUST_LOG=debug`: Enable debug output
- `ANGORA_DISABLE_CPU_BINDING=1`: Disable automatic CPU affinity binding

## Development Workflow

### Modifying Instrumentation Passes

LLVM passes are in `llvm_mode/pass/`:
1. Edit `AngoraPass.cc`, `DFSanPass.cc`, or `UnfoldBranchPass.cc`
2. Rebuild with `./build/build.sh` (rebuilds both Rust and LLVM components)
3. Test changes by recompiling a target program

### Modifying Fuzzer Logic

Fuzzer source in `fuzzer/src/`:
1. Edit relevant Rust files (mutation strategies in `search/`, execution in `executor/`, etc.)
2. Build with `cargo build --release` from root directory
3. Binary output to `target/release/fuzzer`
4. Run `./build/build.sh` to install to `bin/` directory

### Adding New Mutation Strategies

Exploration strategies are in `fuzzer/src/search/`. Implement new strategies following existing patterns and integrate into the main search loop.

### Testing Changes

```bash
cd tests
./test.sh mini  # Quick smoke test
./test.sh <specific_test_dir>  # Test specific program
```

Test directories contain small C programs with known bugs for validation.

## Key Implementation Details

### Branch Context

Angora uses call stack context to distinguish identical branches in different execution contexts. Controlled by `ANGORA_CUSTOM_FN_CONTEXT` during compilation.

### Taint Tracking Flow

1. Fast binary explores new paths quickly
2. When new coverage found, fuzzer runs taint binary on same input
3. Taint analysis identifies input bytes affecting uncovered branches
4. Fuzzer applies targeted mutations to solve constraints
5. Process repeats with newly generated inputs

### Shared Memory Communication

Runtime libraries use shared memory regions for efficient communication:
- `runtime_fast/src/shm_branches.rs`: Branch coverage bitmap
- `runtime_fast/src/shm_conds.rs`: Constraint information
- Fuzzer reads these regions after each execution

### Constraint Solving

Multiple strategies in `fuzzer/src/search/`:
- Gradient descent for numeric comparisons
- Random mutations for exploration
- Linear and affine transformations
- Magic byte insertion for specific patterns

## Common Issues

**Compilation failures**: Check that LLVM is in PATH and LD_LIBRARY_PATH includes runtime libraries.

**Shared library errors**: Use `--disable-shared` with configure, or compile libraries with `USE_TRACK=1`.

**Missing input taints**: Add custom input functions to `llvm_mode/external_lib/io-func.c` if program uses non-standard I/O.

**Performance**: Adjust `ANGORA_INST_RATIO` to reduce instrumentation overhead if needed.

See `docs/troubleshoot.md` for more debugging guidance.
