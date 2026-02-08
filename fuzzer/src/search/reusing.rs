use crate::depot::{LABEL_PATTERN_MAP, extract_pattern_merged, CondRecord, get_next_records, update_pattern_stats, update_condstmt_stats, update_combined_success};
use crate::search::SearchHandler;
use rand::seq::SliceRandom;
use angora_common::tag::TagSeg;
use crate::stats::REUSING_STATS;

// Reusing mutation
pub fn apply_reusing_mutation(handler: &mut SearchHandler, iterations: usize) -> bool {
    if handler.cond.is_done() {
        return false;
    }

    let snapshot = handler.executor.local_stats.snapshot();
    let buf_backup = handler.buf.clone();

    let pattern = extract_pattern_merged(&handler.cond.offsets);
    if pattern.is_empty(){
        return false;
    }

    let mut execution_count = 0;
    let mut stage1_executed = false;
    let mut stage2_executed = false;

    let map = LABEL_PATTERN_MAP.lock().unwrap();
    let total_records = if let Some(records) = map.get(&pattern) {
        records.len()
    } else {
        0
    };
    drop(map);

    if handler.cond.reusing_record_index < total_records {
        if let Some(selected_records) = get_next_records(&mut handler.cond, &pattern, iterations) {
            stage1_executed = true;

            let merged_offsets = merge_continuous_segments(&handler.cond.offsets);

            for record in selected_records.iter() {
                if handler.is_stopped_or_skip() {
                    break;
                }

                if insert_critical_value_with_merged(handler, record, &merged_offsets) {
                    let buf = handler.buf.clone();
                    handler.execute(&buf);
                    execution_count += 1;
                }
            }
        }
    }

    if execution_count < iterations && pattern.len() >= 2 {
        let remaining = iterations - execution_count;
        stage2_executed = true;
        let combined_count = try_combined_segments(handler, &pattern, remaining);
        if combined_count > 0 {
            update_combined_success(&pattern);
        }
        execution_count += combined_count;
    }

    {
        let mut reusing_stats = REUSING_STATS.lock().unwrap();
        let exec_delta = handler.executor.local_stats.num_exec.0 - snapshot.num_exec.0;
        let inputs_delta = handler.executor.local_stats.num_inputs.0 - snapshot.num_inputs.0;
        let hangs_delta = handler.executor.local_stats.num_hangs.0 - snapshot.num_hangs.0;
        let crashes_delta = handler.executor.local_stats.num_crashes.0 - snapshot.num_crashes.0;

        reusing_stats.num_exec.0 += exec_delta;
        reusing_stats.num_inputs.0 += inputs_delta;
        reusing_stats.num_hangs.0 += hangs_delta;
        reusing_stats.num_crashes.0 += crashes_delta;
    }

    let is_success = handler.cond.is_done();
    update_pattern_stats(
        &pattern,
        handler.cond.reusing_record_index,
        stage1_executed,
        stage2_executed,
        is_success,
    );

    update_condstmt_stats(
        handler.cond.base.cmpid,
        handler.cond.base.context,
        handler.cond.base.order,
        &pattern,
        stage1_executed,
        stage2_executed,
    );

    handler.executor.local_stats.restore(&snapshot);
    handler.buf = buf_backup;

    if is_success {
        return true;
    }
    return false;
}

fn try_combined_segments(handler: &mut SearchHandler, pattern: &Vec<u32>, iterations: usize) -> usize {
    let segment_pools: Vec<Vec<Vec<u8>>> = {
        let map = LABEL_PATTERN_MAP.lock().unwrap();

        pattern.iter().map(|&segment_size| {
            let single_pattern = vec![segment_size];
            map.get(&single_pattern)
                .map(|records| {
                    records.iter()
                        .filter_map(|r| r.critical_values.first().cloned())
                        .collect()
                })
                .unwrap_or_default()
        }).collect()
    };

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

    let max_end = merged_offsets.iter()
        .map(|s| s.end as usize)
        .max()
        .unwrap_or(0);

    if max_end > handler.buf.len() {
        handler.buf.resize(max_end, 0);
    }

    let mut rng = rand::thread_rng();
    let mut execution_count = 0;

    let mut combined_values: Vec<Vec<u8>> = Vec::with_capacity(pattern.len());

    for iter in 0..iterations {
        if handler.is_stopped_or_skip() {
            warn!("[Reusing] Stopped early at combined iteration {}/{}", iter, iterations);
            break;
        }

        combined_values.clear();

        for pool in &segment_pools {
            if let Some(record) = pool.choose(&mut rng) {
                combined_values.push(record.clone());
            }
        }

        if combined_values.len() == merged_offsets.len() {
            for (seg, value) in merged_offsets.iter().zip(combined_values.iter()) {
                let begin = seg.begin as usize;
                let end = seg.end as usize;
                let copy_len = value.len().min(end - begin);

                handler.buf[begin..begin + copy_len]
                    .copy_from_slice(&value[..copy_len]);
            }

            let buf = handler.buf.clone();
            handler.execute(&buf);
            execution_count += 1;
        }
    }
    execution_count
}

fn insert_critical_value_with_merged(
    handler: &mut SearchHandler,
    record: &CondRecord,
    merged_offsets: &[TagSeg],
) -> bool {
    let critical_values = &record.critical_values;

    if merged_offsets.len() != critical_values.len() {
        return false;
    }

    let max_end = merged_offsets.iter().map(|s| s.end as usize).max().unwrap_or(0);
    if max_end > handler.buf.len() {
        handler.buf.resize(max_end, 0);
    }

    for (seg, value) in merged_offsets.iter().zip(critical_values.iter()) {
        let begin = seg.begin as usize;
        let end = seg.end as usize;
        let copy_len = value.len().min(end - begin);

        handler.buf[begin..begin + copy_len].copy_from_slice(&value[..copy_len]);
    }

    true
}

fn merge_continuous_segments(offsets: &Vec<TagSeg>) -> Vec<TagSeg> {
    if offsets.is_empty() {
        return vec![];
    }

    let mut merged = Vec::new();
    let mut current = offsets[0];

    for i in 1..offsets.len() {
        let next = offsets[i];
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
