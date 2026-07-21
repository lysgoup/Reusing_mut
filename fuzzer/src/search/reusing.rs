use crate::depot::{LABEL_PATTERN_MAP, extract_pattern, CondRecord, get_next_records};
use crate::search::SearchHandler;
use crate::mut_input::offsets::merge_offsets;
use rand::seq::SliceRandom;
use angora_common::{config, tag::TagSeg};
use crate::stats::REUSING_STATS;

pub fn apply_reusing_mutation(handler: &mut SearchHandler, iterations: usize) -> bool {
    if handler.cond.is_done() {
        return false;
    }

    if handler.cond.offsets.is_empty() {
        return false;
    }

    let snapshot = handler.executor.local_stats.snapshot();
    let buf_backup = handler.buf.clone();

    let mut best_f = u64::MAX;
    let mut best_buf = handler.buf.clone();
    let mut execution_count = 0;

    let primary_offsets = handler.cond.offsets.clone();
    let opt_offsets = handler.cond.offsets_opt.clone();

    // Phase A: primary offsets
    execution_count += run_reusing_phase(handler, iterations, &mut best_f, &mut best_buf);

    // Phase B: offsets_opt
    if !opt_offsets.is_empty() && !handler.cond.is_done() {
        handler.cond.offsets = opt_offsets.clone();
        std::mem::swap(
            &mut handler.cond.reusing_record_index,
            &mut handler.cond.reusing_record_index_opt,
        );

        execution_count += run_reusing_phase(handler, iterations, &mut best_f, &mut best_buf);

        std::mem::swap(
            &mut handler.cond.reusing_record_index,
            &mut handler.cond.reusing_record_index_opt,
        );
        handler.cond.offsets = primary_offsets.clone();
    }

    // Phase C: merged offsets (offsets_all)
    if !opt_offsets.is_empty() && !handler.cond.is_done() {
        let merged_all = merge_offsets(&primary_offsets, &opt_offsets);
        handler.cond.offsets = merged_all;
        std::mem::swap(
            &mut handler.cond.reusing_record_index,
            &mut handler.cond.reusing_record_index_all,
        );

        execution_count += run_reusing_phase(handler, iterations, &mut best_f, &mut best_buf);

        std::mem::swap(
            &mut handler.cond.reusing_record_index,
            &mut handler.cond.reusing_record_index_all,
        );
        handler.cond.offsets = primary_offsets.clone();
    }

    // reusing 통계 누적
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

    handler.executor.local_stats.restore(&snapshot);

    if best_f < u64::MAX {
        handler.buf = best_buf;
    } else {
        handler.buf = buf_backup;
    }

    handler.reset_phase();

    if handler.cond.is_done() {
        return true;
    }
    false
}

// 현재 cond.offsets 기준으로 reusing을 수행하고 실행 횟수를 반환한다.
// best_f / best_buf는 모든 phase에 걸쳐 공유된다.
fn run_reusing_phase(
    handler: &mut SearchHandler,
    iterations: usize,
    best_f: &mut u64,
    best_buf: &mut Vec<u8>,
) -> usize {
    let pattern = extract_pattern(&merge_continuous_segments(&handler.cond.offsets));
    if pattern.is_empty() {
        return 0;
    }

    let mut execution_count = 0;

    let map = LABEL_PATTERN_MAP.lock().unwrap();
    let total_records = if let Some(records) = map.get(&pattern) {
        records.len()
    } else {
        0
    };
    drop(map);

    if handler.cond.reusing_record_index >= total_records {
        info!(
            "[Reusing] Pattern {:?}: All records already used (index={}/{}), skipping",
            pattern, handler.cond.reusing_record_index, total_records
        );
    } else {
        if let Some(selected_records) = get_next_records(&mut handler.cond, &pattern, iterations) {
            let merged_offsets = merge_continuous_segments(&handler.cond.offsets);

            for record in selected_records.iter() {
                handler.reset_phase();
                if handler.is_stopped() {
                    break;
                }

                if insert_critical_value_with_merged(handler, record, &merged_offsets) {
                    handler.executor.current_reusing_detail = merged_offsets
                        .iter()
                        .zip(record.critical_values.iter())
                        .map(|(seg, val)| (seg.begin, seg.end, val.clone()))
                        .collect();

                    let f = handler.execute_cond_direct();
                    execution_count += 1;

                    if f < *best_f {
                        *best_f = f;
                        *best_buf = handler.buf.clone();
                        let input = handler.get_f_input();
                        handler.cond.variables = input.get_value();
                    }

                    if !handler.cond.is_done() {
                        run_det_for_coverage(handler);
                    }
                }

                if handler.cond.is_done() {
                    break;
                }
            }
        }
    }

    if execution_count < iterations && pattern.len() >= 2 {
        let remaining = iterations - execution_count;
        let combined_count =
            try_combined_segments(handler, &pattern, remaining, best_f, best_buf);
        execution_count += combined_count;
    }

    execution_count
}

fn run_det_for_coverage(handler: &mut SearchHandler) {
    let offsets = handler.cond.offsets.clone();
    for seg in &offsets {
        handler.record_mutated_range(seg.begin as usize, seg.end as usize);
    }

    let mut input = handler.get_f_input();
    let n = std::cmp::min(input.val_len() << 3, config::MAX_SEARCH_EXEC_NUM);
    for i in 0..n {
        if handler.cond.is_done() {
            break;
        }
        input.bitflip(i);
        handler.execute_cond(&input);
        input.bitflip(i);
    }
}

fn try_combined_segments(
    handler: &mut SearchHandler,
    pattern: &Vec<u32>,
    iterations: usize,
    best_f: &mut u64,
    best_buf: &mut Vec<u8>,
) -> usize {
    let segment_pools: Vec<Vec<Vec<u8>>> = {
        let map = LABEL_PATTERN_MAP.lock().unwrap();
        pattern
            .iter()
            .map(|&segment_size| {
                let single_pattern = vec![segment_size];
                map.get(&single_pattern)
                    .map(|records| {
                        records
                            .iter()
                            .filter_map(|r| r.critical_values.first().cloned())
                            .collect()
                    })
                    .unwrap_or_default()
            })
            .collect()
    };

    if segment_pools.iter().any(|pool| pool.is_empty()) {
        warn!("[Reusing] Cannot combine: some segment pools are empty");
        return 0;
    }

    let merged_offsets = merge_continuous_segments(&handler.cond.offsets);
    if merged_offsets.len() != pattern.len() {
        warn!(
            "[Reusing] Merged offsets mismatch: offsets={}, pattern={}",
            merged_offsets.len(),
            pattern.len()
        );
        return 0;
    }

    let max_end = merged_offsets
        .iter()
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
        handler.reset_phase();
        if handler.is_stopped() {
            warn!(
                "[Reusing] Stopped early at combined iteration {}/{}",
                iter, iterations
            );
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
                handler.buf[begin..begin + copy_len].copy_from_slice(&value[..copy_len]);
            }

            handler.executor.current_reusing_detail = merged_offsets
                .iter()
                .zip(combined_values.iter())
                .map(|(seg, val)| (seg.begin, seg.end, val.clone()))
                .collect();

            let f = handler.execute_cond_direct();
            execution_count += 1;

            if f < *best_f {
                *best_f = f;
                *best_buf = handler.buf.clone();
                let input = handler.get_f_input();
                handler.cond.variables = input.get_value();
            }

            if !handler.cond.is_done() {
                run_det_for_coverage(handler);
            }
        }

        if handler.cond.is_done() {
            break;
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

    let max_end = merged_offsets
        .iter()
        .map(|s| s.end as usize)
        .max()
        .unwrap_or(0);
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
