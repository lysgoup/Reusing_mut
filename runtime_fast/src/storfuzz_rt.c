/*
 * storfuzz_rt.c — StorFuzz data-coverage runtime for Angora fast builds.
 *
 * Defines __angora_data_area_ptr (the map pointer the LLVM pass writes to)
 * and attaches the shared memory region passed via ANGORA_DATA_SHM_ID.
 *
 * Build note: compiled into libcontext.a alongside context.c by build.rs.
 * STORFUZZ_MAP_SIZE_POW2 is injected by build.rs from common/src/config.rs
 * (DATA_MAP_SIZE_POW2) so this stays in sync with the fuzzer and the pass.
 *
 * This object is always linked into libruntime_fast.a, but it is inert unless
 * the target was instrumented with StorFuzzPass (which emits references to
 * __angora_data_area_ptr) AND ANGORA_DATA_SHM_ID is exported by the fuzzer.
 */

#include <stdint.h>
#include <stdlib.h>
#include <sys/shm.h>

#ifndef STORFUZZ_MAP_SIZE_POW2
# define STORFUZZ_MAP_SIZE_POW2 17   /* fallback; overridden by build.rs */
#endif
#define STORFUZZ_MAP_SIZE (1u << STORFUZZ_MAP_SIZE_POW2)

/* Static fallback map used when shmem is not configured (e.g. running the
 * instrumented binary standalone without ANGORA_DATA_SHM_ID). Sized exactly
 * like the shared map so instrumented stores never write out of bounds. */
static uint8_t __angora_storfuzz_default_map[STORFUZZ_MAP_SIZE];

/* The LLVM pass emits:
 *   @__angora_data_area_ptr = external global i8*
 * and dereferences it at every instrumented store.
 * We define it here with ExternalLinkage (must match the pass). */
uint8_t *__angora_data_area_ptr = __angora_storfuzz_default_map;

/* Prioritized constructor (200): prioritized ctors run BEFORE non-prioritized
 * ones, so this attaches the data-coverage shm and sets __angora_data_area_ptr
 * BEFORE Angora's plain fork-server constructor takes over. That ordering is
 * REQUIRED: the fork-server ctor calls start_forkcli(), which never returns, so
 * any setup that must precede forking has to run from a higher-priority ctor.
 * Do NOT change this to a plain/lower-priority ctor — it would never run. */
__attribute__((constructor(200)))
static void __angora_storfuzz_init(void) {
    const char *id_str = getenv("ANGORA_DATA_SHM_ID");
    if (!id_str) return;

    int shm_id = atoi(id_str);
    void *p = shmat(shm_id, NULL, 0);
    if (p == (void *)-1) return;

    __angora_data_area_ptr = (uint8_t *)p;
}
