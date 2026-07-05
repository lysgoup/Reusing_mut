use crate::depot::{LABEL_PATTERN_MAP, extract_pattern, CondRecord, get_next_records};
use crate::search::SearchHandler;
use crate::cond_stmt::CondState;
use crate::mut_input::offsets::merge_continuous_segments;
use rand::seq::SliceRandom;
use angora_common::{config, tag::TagSeg};
use crate::stats::{REUSING_STATS, TimeIns};

// Whether ReusingFuzz::run() solved the cond outright, merely left behind an
// improved (but not solving) buffer for whatever runs next to build on, or made
// no headway at all. Lets callers distinguish "Reusing", "Reusing+<Det/GD/...>"
// (this phase's discovery built on a reusing improvement), and plain misses in
// the analysis-mode log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReusingOutcome {
    Solved,
    Improved,
    NoProgress,
}

pub struct ReusingFuzz<'a, 'b> {
    pub handler: &'b mut SearchHandler<'a>,
}

impl<'a, 'b> ReusingFuzz<'a, 'b> {
    pub fn new(handler: &'b mut SearchHandler<'a>) -> Self {
        Self { handler }
    }

    pub fn run(&mut self, iterations: usize) -> ReusingOutcome {
        let handler = &mut *self.handler;

        if handler.cond.is_done() {
            return ReusingOutcome::NoProgress;
        }

        if handler.cond.offsets.is_empty() {
            return ReusingOutcome::NoProgress;
        }

        let snapshot = handler.executor.local_stats.snapshot();
        let start_time = TimeIns::default();
        let buf_backup = handler.buf.clone();

        let mut best_f = u64::MAX;
        let mut best_buf = handler.buf.clone();
        let mut execution_count = 0;

        let primary_offsets = handler.cond.offsets.clone();
        let opt_offsets = handler.cond.offsets_opt.clone();

        // CondState machine (cond_state.rs) already drives cond.offsets through
        // Offset -> OffsetOpt -> OffsetAll as the outer search advances. While it's still
        // in Offset/OffsetOpt, cond.offsets only ever holds one operand's taint offsets, so
        // Phase B fills in the other operand. Once it reaches OffsetAll, cond.offsets is
        // already the merged set, so Phase A alone performs the merge attempt and a
        // separate merge phase would just repeat it.
        let is_early_state = matches!(handler.cond.state, CondState::Offset | CondState::OffsetOpt);

        // Phase A: whatever offsets the CondState machine currently has cond.offsets set to
        // (a single operand while early, the merged set once OffsetAll+). Progress is tracked
        // in its own dedicated counter, reusing_record_index.
        let mut primary_index = handler.cond.reusing_record_index;
        execution_count += run_reusing_phase(handler, &mut primary_index, iterations, &buf_backup, &mut best_f, &mut best_buf);
        handler.cond.reusing_record_index = primary_index;

        // Phase B: the other tainted operand's offsets, only while still early. Tracked by its
        // own counter, reusing_record_index_opt, so it never interferes with Phase A's progress.
        if is_early_state && !opt_offsets.is_empty() && !handler.cond.is_done() {
            handler.cond.offsets = opt_offsets.clone();

            let mut opt_index = handler.cond.reusing_record_index_opt;
            execution_count += run_reusing_phase(handler, &mut opt_index, iterations, &buf_backup, &mut best_f, &mut best_buf);
            handler.cond.reusing_record_index_opt = opt_index;

            handler.cond.offsets = primary_offsets.clone();
        }

        // reusing 통계 누적: local_stats.num_exec 등은 그대로 둬서 grand total에는
        // 계속 잡히게 하고, reusing_num_exec 등에 델타를 남겨서 sync_from_local()이
        // Explore/Exploit 등 fuzz_type별 세부 집계에서만 이 몫을 빼도록 한다.
        {
            let exec_delta = handler.executor.local_stats.num_exec.0 - snapshot.num_exec.0;
            let inputs_delta = handler.executor.local_stats.num_inputs.0 - snapshot.num_inputs.0;
            let hangs_delta = handler.executor.local_stats.num_hangs.0 - snapshot.num_hangs.0;
            let crashes_delta = handler.executor.local_stats.num_crashes.0 - snapshot.num_crashes.0;

            let mut reusing_stats = REUSING_STATS.lock().unwrap();
            reusing_stats.num_exec.0 += exec_delta;
            reusing_stats.num_inputs.0 += inputs_delta;
            reusing_stats.num_hangs.0 += hangs_delta;
            reusing_stats.num_crashes.0 += crashes_delta;
            reusing_stats.total_time += start_time.into();
            drop(reusing_stats);

            handler.executor.local_stats.reusing_num_exec.0 += exec_delta;
            handler.executor.local_stats.reusing_num_inputs.0 += inputs_delta;
            handler.executor.local_stats.reusing_num_hangs.0 += hangs_delta;
            handler.executor.local_stats.reusing_num_crashes.0 += crashes_delta;
        }

        let made_progress = best_f < u64::MAX;
        if made_progress {
            handler.buf = best_buf;
        } else {
            handler.buf = buf_backup;
        }

        handler.reset_phase();

        if handler.cond.is_done() {
            return ReusingOutcome::Solved;
        }
        if made_progress {
            ReusingOutcome::Improved
        } else {
            ReusingOutcome::NoProgress
        }
    }
}

// 현재 cond.offsets 기준으로 reusing을 수행하고 실행 횟수를 반환한다.
// best_f / best_buf는 모든 phase에 걸쳐 공유된다.
fn run_reusing_phase(
    handler: &mut SearchHandler,
    record_index: &mut usize,
    iterations: usize,
    original_buf: &[u8],
    best_f: &mut u64,
    best_buf: &mut Vec<u8>,
) -> usize {
    let merged_offsets = merge_continuous_segments(&handler.cond.offsets);
    let pattern = extract_pattern(&merged_offsets);
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

    if *record_index >= total_records {
        info!(
            "[Reusing] Pattern {:?}: All records already used (index={}/{}), skipping",
            pattern, *record_index, total_records
        );
    } else {
        if let Some(selected_records) = get_next_records(record_index, &pattern, iterations) {
            for record in selected_records.iter() {
                handler.reset_phase();
                if handler.is_stopped() {
                    break;
                }

                if insert_critical_value_with_merged(handler, record, &merged_offsets, original_buf) {
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
                        handler.executor.current_mut_op = "Reusing+Det";
                        run_det_for_coverage(handler);
                        handler.executor.current_mut_op = "Reusing";
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
            try_combined_segments(handler, &pattern, &merged_offsets, original_buf, remaining, best_f, best_buf);
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
    merged_offsets: &[TagSeg],
    original_buf: &[u8],
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

        if combined_values.len() == merged_offsets.len() && !matches_original(merged_offsets, &combined_values, original_buf) {
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
                handler.executor.current_mut_op = "Reusing+Det";
                run_det_for_coverage(handler);
                handler.executor.current_mut_op = "Reusing";
            }
        }

        if handler.cond.is_done() {
            break;
        }
    }
    execution_count
}

// True if every value would write back exactly what's already in original_buf at
// that segment, i.e. this candidate is indistinguishable from the base input.
fn matches_original(merged_offsets: &[TagSeg], values: &[Vec<u8>], original_buf: &[u8]) -> bool {
    merged_offsets.iter().zip(values.iter()).all(|(seg, value)| {
        let begin = seg.begin as usize;
        let end = seg.end as usize;
        end <= original_buf.len() && &original_buf[begin..end] == value.as_slice()
    })
}

fn insert_critical_value_with_merged(
    handler: &mut SearchHandler,
    record: &CondRecord,
    merged_offsets: &[TagSeg],
    original_buf: &[u8],
) -> bool {
    let critical_values = &record.critical_values;

    if merged_offsets.len() != critical_values.len() {
        return false;
    }

    // Same value as the base input at every one of these positions would just
    // repeat an already-known execution, so skip it instead of wasting a run.
    if matches_original(merged_offsets, critical_values, original_buf) {
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
