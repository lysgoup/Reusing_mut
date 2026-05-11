use crate::depot::{merge_segments, ReuseEntry, ReusePattern};
use crate::search::SearchHandler;
use rand::Rng;
use angora_common::tag::TagSeg;
use crate::stats::REUSING_STATS;

const MAX_CONSECUTIVE_MISSES: usize = 10;
const EXHAUSTIVE_THRESHOLD: usize = 200;

pub enum ReusingResult {
    Solved,
    RanNoSolve,
    NothingToRun,
}

pub fn reusing_mutation(handler: &mut SearchHandler, iterations: usize) -> ReusingResult {
    if handler.cond.is_done() {
        return ReusingResult::NothingToRun;
    }

    // Skip 2 turns to let the pool grow, then force a run on the 3rd
    if handler.cond.reusing_skip_count < 2 {
        handler.cond.reusing_skip_count += 1;
        return ReusingResult::NothingToRun;
    }
    handler.cond.reusing_skip_count = 0;

    let merged_offsets = merge_segments(&handler.cond.offsets);
    let pattern: ReusePattern = merged_offsets.iter().map(|s| s.end - s.begin).collect();
    if pattern.is_empty() {
        return ReusingResult::NothingToRun;
    }

    let snapshot = handler.executor.local_stats.snapshot();
    let buf_backup = handler.buf.clone();
    let mut execution_count = 0;

    // Phase 1: try direct pool entries
    let total_records = handler.executor.reuse_pool().record_count(&pattern);
    if handler.cond.reusing_record_index < total_records {
        let start = handler.cond.reusing_record_index;
        if let Some((entries, new_idx)) = handler.executor.reuse_pool().get_entries_from(&pattern, start, iterations) {
            handler.cond.reusing_record_index = new_idx;

            let mut consecutive_misses = 0;
            for entry in &entries {
                if handler.is_stopped_or_skip() || consecutive_misses >= MAX_CONSECUTIVE_MISSES {
                    break;
                }
                if insert_entry_bytes(handler, entry, &merged_offsets) {
                    set_reusing_detail(handler, &merged_offsets, &entry.segment_values());
                    let buf = handler.buf.clone();
                    handler.execute(&buf);
                    execution_count += 1;
                    if handler.executor.has_new_path {
                        consecutive_misses = 0;
                    } else {
                        consecutive_misses += 1;
                    }
                }
            }
        }
    }

    // Phase 2: try combined segments
    if execution_count < iterations && pattern.len() >= 2 {
        let remaining = iterations - execution_count;
        execution_count += try_combined_segments(handler, &pattern, &merged_offsets, remaining);
    }

    {
        let mut reusing_stats = REUSING_STATS.lock().unwrap();
        reusing_stats.num_exec.0 += handler.executor.local_stats.num_exec.0 - snapshot.num_exec.0;
        reusing_stats.num_inputs.0 += handler.executor.local_stats.num_inputs.0 - snapshot.num_inputs.0;
        reusing_stats.num_hangs.0 += handler.executor.local_stats.num_hangs.0 - snapshot.num_hangs.0;
        reusing_stats.num_crashes.0 += handler.executor.local_stats.num_crashes.0 - snapshot.num_crashes.0;
    }

    handler.executor.local_stats.restore(&snapshot);
    handler.buf = buf_backup;

    if handler.cond.is_done() {
        return ReusingResult::Solved;
    }
    if execution_count > 0 {
        ReusingResult::RanNoSolve
    } else {
        ReusingResult::NothingToRun
    }
}

fn try_combined_segments(handler: &mut SearchHandler, pattern: &[u32], merged_offsets: &[TagSeg], iterations: usize) -> usize {
    let segment_pools: Vec<Vec<Vec<u8>>> = pattern.iter()
        .map(|&size| handler.executor.reuse_pool().get_single_segment_values(size))
        .collect();

    if segment_pools.iter().any(|pool| pool.is_empty()) {
        return 0;
    }

    if merged_offsets.len() != pattern.len() {
        return 0;
    }

    let max_end = merged_offsets.iter().map(|s| s.end as usize).max().unwrap_or(0);
    if max_end > handler.buf.len() {
        handler.buf.resize(max_end, 0);
    }

    let pool_sizes: Vec<usize> = segment_pools.iter().map(|p| p.len()).collect();
    let total_combinations = pool_sizes.iter()
        .try_fold(1usize, |acc, &n| acc.checked_mul(n))
        .unwrap_or(usize::MAX);

    if total_combinations <= EXHAUSTIVE_THRESHOLD {
        run_exhaustive_combined(handler, &segment_pools, &merged_offsets, &pool_sizes, total_combinations)
    } else {
        run_random_combined(handler, &segment_pools, &merged_offsets, iterations)
    }
}

fn run_exhaustive_combined(
    handler: &mut SearchHandler,
    segment_pools: &[Vec<Vec<u8>>],
    merged_offsets: &[TagSeg],
    pool_sizes: &[usize],
    total_combinations: usize,
) -> usize {
    let start = handler.cond.reusing_combined_index;
    if start >= total_combinations {
        return 0;
    }

    let mut execution_count = 0;
    let mut consecutive_misses = 0;
    let mut idx = start;

    while idx < total_combinations {
        if handler.is_stopped_or_skip() || consecutive_misses >= MAX_CONSECUTIVE_MISSES {
            break;
        }

        let combination = index_to_combination(idx, pool_sizes);
        idx += 1;

        apply_combination(handler, segment_pools, merged_offsets, &combination);
        let buf = handler.buf.clone();
        handler.execute(&buf);
        execution_count += 1;

        if handler.executor.has_new_path {
            consecutive_misses = 0;
        } else {
            consecutive_misses += 1;
        }
    }

    handler.cond.reusing_combined_index = idx;
    execution_count
}

fn run_random_combined(
    handler: &mut SearchHandler,
    segment_pools: &[Vec<Vec<u8>>],
    merged_offsets: &[TagSeg],
    iterations: usize,
) -> usize {
    let mut rng = rand::thread_rng();
    let mut execution_count = 0;
    let mut consecutive_misses = 0;

    for _ in 0..iterations {
        if handler.is_stopped_or_skip() || consecutive_misses >= MAX_CONSECUTIVE_MISSES {
            break;
        }

        let combination: Vec<usize> = segment_pools.iter()
            .map(|pool| rng.gen_range(0, pool.len()))
            .collect();

        apply_combination(handler, segment_pools, merged_offsets, &combination);
        let buf = handler.buf.clone();
        handler.execute(&buf);
        execution_count += 1;

        if handler.executor.has_new_path {
            consecutive_misses = 0;
        } else {
            consecutive_misses += 1;
        }
    }

    execution_count
}

fn apply_combination(
    handler: &mut SearchHandler,
    segment_pools: &[Vec<Vec<u8>>],
    merged_offsets: &[TagSeg],
    combination: &[usize],
) {
    for (j, (seg, &idx)) in merged_offsets.iter().zip(combination.iter()).enumerate() {
        let value = &segment_pools[j][idx];
        let begin = seg.begin as usize;
        let end = seg.end as usize;
        let copy_len = value.len().min(end - begin);
        handler.buf[begin..begin + copy_len].copy_from_slice(&value[..copy_len]);
    }

    handler.executor.current_reusing_detail = merged_offsets.iter()
        .zip(combination.iter())
        .enumerate()
        .map(|(j, (seg, &idx))| (seg.begin, seg.end, segment_pools[j][idx].clone()))
        .collect();
}

fn index_to_combination(mut index: usize, pool_sizes: &[usize]) -> Vec<usize> {
    let mut result = vec![0usize; pool_sizes.len()];
    for j in (0..pool_sizes.len()).rev() {
        result[j] = index % pool_sizes[j];
        index /= pool_sizes[j];
    }
    result
}

fn set_reusing_detail(handler: &mut SearchHandler, merged_offsets: &[TagSeg], values: &[&[u8]]) {
    handler.executor.current_reusing_detail = merged_offsets.iter()
        .zip(values.iter())
        .map(|(seg, val)| (seg.begin, seg.end, val.to_vec()))
        .collect();
}

fn insert_entry_bytes(
    handler: &mut SearchHandler,
    entry: &ReuseEntry,
    merged_offsets: &[TagSeg],
) -> bool {
    let values = entry.segment_values();
    if merged_offsets.len() != values.len() {
        return false;
    }

    let max_end = merged_offsets.iter().map(|s| s.end as usize).max().unwrap_or(0);
    if max_end > handler.buf.len() {
        handler.buf.resize(max_end, 0);
    }

    for (seg, value) in merged_offsets.iter().zip(values.iter()) {
        let begin = seg.begin as usize;
        let end = seg.end as usize;
        let copy_len = value.len().min(end - begin);
        handler.buf[begin..begin + copy_len].copy_from_slice(&value[..copy_len]);
    }
    true
}
