use crate::depot::{extract_pattern_merged, ReuseEntry};
use crate::search::SearchHandler;
use rand::seq::SliceRandom;
use angora_common::tag::TagSeg;
use crate::stats::REUSING_STATS;

pub fn apply_reusing_mutation(handler: &mut SearchHandler, iterations: usize) -> bool {
    if handler.cond.is_done() {
        return false;
    }

    let snapshot = handler.executor.local_stats.snapshot();
    let buf_backup = handler.buf.clone();

    let pattern = extract_pattern_merged(&handler.cond.offsets);
    if pattern.is_empty() {
        return false;
    }

    let mut execution_count = 0;
    let total_records = handler.executor.reuse_pool().record_count(&pattern);

    if handler.cond.reusing_record_index < total_records {
        let start = handler.cond.reusing_record_index;
        if let Some((entries, new_idx)) = handler.executor.reuse_pool().get_entries_from(&pattern, start, iterations) {
            handler.cond.reusing_record_index = new_idx;
            let merged_offsets = merge_continuous_segments(&handler.cond.offsets);

            for entry in &entries {
                if handler.is_stopped_or_skip() {
                    break;
                }
                if insert_entry_bytes(handler, entry, &merged_offsets) {
                    handler.executor.current_reusing_detail = merged_offsets.iter()
                        .zip(entry.segment_values().iter())
                        .map(|(seg, val)| (seg.begin, seg.end, val.to_vec()))
                        .collect();
                    let buf = handler.buf.clone();
                    handler.execute(&buf);
                    execution_count += 1;
                }
            }
        }
    }

    if execution_count < iterations && pattern.len() >= 2 {
        let remaining = iterations - execution_count;
        execution_count += try_combined_segments(handler, &pattern, remaining);
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
        return true;
    }
    false
}

fn try_combined_segments(handler: &mut SearchHandler, pattern: &[u32], iterations: usize) -> usize {
    let segment_pools: Vec<Vec<Vec<u8>>> = pattern.iter()
        .map(|&size| handler.executor.reuse_pool().get_single_segment_values(size))
        .collect();

    if segment_pools.iter().any(|pool| pool.is_empty()) {
        warn!("[Reusing] Cannot combine: some segment pools are empty");
        return 0;
    }

    let merged_offsets = merge_continuous_segments(&handler.cond.offsets);
    if merged_offsets.len() != pattern.len() {
        warn!("[Reusing] Merged offsets mismatch: offsets={}, pattern={}",
              merged_offsets.len(), pattern.len());
        return 0;
    }

    let max_end = merged_offsets.iter().map(|s| s.end as usize).max().unwrap_or(0);
    if max_end > handler.buf.len() {
        handler.buf.resize(max_end, 0);
    }

    let mut rng = rand::thread_rng();
    let mut execution_count = 0;
    let mut combined: Vec<Vec<u8>> = Vec::with_capacity(pattern.len());

    for iter in 0..iterations {
        if handler.is_stopped_or_skip() {
            warn!("[Reusing] Stopped early at combined iteration {}/{}", iter, iterations);
            break;
        }

        combined.clear();
        for pool in &segment_pools {
            if let Some(val) = pool.choose(&mut rng) {
                combined.push(val.clone());
            }
        }

        if combined.len() == merged_offsets.len() {
            for (seg, value) in merged_offsets.iter().zip(combined.iter()) {
                let begin = seg.begin as usize;
                let end = seg.end as usize;
                let copy_len = value.len().min(end - begin);
                handler.buf[begin..begin + copy_len].copy_from_slice(&value[..copy_len]);
            }

            handler.executor.current_reusing_detail = merged_offsets.iter()
                .zip(combined.iter())
                .map(|(seg, val)| (seg.begin, seg.end, val.clone()))
                .collect();

            let buf = handler.buf.clone();
            handler.execute(&buf);
            execution_count += 1;
        }
    }
    execution_count
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

fn merge_continuous_segments(offsets: &[TagSeg]) -> Vec<TagSeg> {
    if offsets.is_empty() {
        return vec![];
    }
    let mut merged = Vec::new();
    let mut current = offsets[0];
    for &next in &offsets[1..] {
        if current.end == next.begin {
            current.end = next.end;
        } else {
            merged.push(current);
            current = next;
        }
    }
    merged.push(current);
    merged
}
