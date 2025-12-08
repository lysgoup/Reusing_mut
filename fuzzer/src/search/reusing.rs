use crate::depot::{LABEL_PATTERN_MAP, extract_pattern_merged, CondRecord, get_next_records};
use crate::search::SearchHandler;
use rand::seq::SliceRandom;
use angora_common::tag::TagSeg;
use crate::stats::REUSING_STATS;
use std::fs::OpenOptions;
use std::io::Write;

// 로그 파일에 기록하는 helper 함수
fn log_to_file(handler: &SearchHandler, message: &str) {
    let depot = handler.executor.get_depot();
    let log_path = depot.dirs.inputs_dir
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join("reusing_success.log");

    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
    {
        let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
        let _ = writeln!(file, "[{}] {}", timestamp, message);
    }
}

// Reusing mutation
pub fn apply_reusing_mutation(handler: &mut SearchHandler, iterations: usize) -> bool {
    // 0. 이미 해결된 조건이면 스킵
    if handler.cond.is_done() {
        return false;
    }

    // 1. local_stats 전체 백업
    let snapshot = handler.executor.local_stats.snapshot();
    let buf_backup = handler.buf.clone();

    // 2. pattern 추출
    let pattern = extract_pattern_merged(&handler.cond.offsets);
    if pattern.is_empty(){
        return false;
    }

    // 3. reusing 진행
    let mut execution_count = 0;
    let map = LABEL_PATTERN_MAP.lock().unwrap();
    let total_records = if let Some(records) = map.get(&pattern) {
        records.len()
    } else {
        0
    };
    drop(map);

    if handler.cond.reusing_record_index >= total_records {
        info!("[Reusing] Pattern {:?}: All records already used (index={}/{}), skipping original reusing",
              pattern, handler.cond.reusing_record_index, total_records);
    } else {
        // ===== 1단계: 동일 패턴 시도 =====
        if let Some(selected_records) = get_next_records(&mut handler.cond, &pattern, iterations) {
            // let actual_iterations = selected_records.len();
            //    info!("[Reusing] Exact match: pattern={:?}, trying {} records (sequential)", pattern, actual_iterations);
            
            let merged_offsets = merge_continuous_segments(&handler.cond.offsets);

            for (i, record) in selected_records.iter().enumerate() {
                if handler.is_stopped_or_skip() {
                    // warn!("[Reusing] Stopped early at iteration {}/{}", i, actual_iterations);
                    break;
                }

                if insert_critical_value_with_merged(handler, record, &merged_offsets) {
                    let buf = handler.buf.clone();
                    handler.execute(&buf);
                    execution_count += 1;

                    // 새로운 경로 발견 여부 확인
                    if handler.executor.has_new_path {
                        let depot = handler.executor.get_depot();
                        let new_input_id = depot.num_inputs.load(std::sync::atomic::Ordering::Relaxed) - 1;

                        // 삽입된 offset 정보 (merged_offsets 사용)
                        let target_offsets: Vec<String> = merged_offsets.iter()
                            .map(|seg| format!("[{}..{}]", seg.begin, seg.end))
                            .collect();

                        // 값의 출처 정보 (record의 cmpid와 offsets)
                        let source_offsets: Vec<String> = record.offsets.iter()
                            .map(|seg| format!("[{}..{}]", seg.begin, seg.end))
                            .collect();

                        let log_msg = format!(
                            "[ORIGINAL REUSING] input_id={}, cmpid={}, pattern={:?}, \
                             target_offsets={:?}, critical_values={:?}, source_input_id={}, source_cmpid={}, source_offsets={:?}, \
                             new_queue_input=id:{:06}",
                            handler.cond.base.belong, handler.cond.base.cmpid, pattern,
                            target_offsets, record.critical_values, record.belong, record.cmpid, source_offsets,
                            new_input_id
                        );
                        info!("{}", log_msg);
                        log_to_file(handler, &log_msg);
                    }
                }
            }
    
        //    info!("[Reusing] Exact match complete: executed {} iterations", execution_count);
        } else {
        //    info!("[Reusing] Pattern {:?}: All records exhausted or no records available", pattern);
        }
    }

    // ===== 2단계: 남은 횟수를 개별 세그먼트 조합으로 채우기 =====
    if execution_count < iterations && pattern.len() >= 2 {
        let remaining = iterations - execution_count;
        //  info!("[Reusing] Trying combined segments: {} iterations remaining", remaining);
        let combined_count = try_combined_segments(handler, &pattern, remaining);
        execution_count += combined_count;
        //  info!("[Reusing] Combined complete: executed {} iterations", combined_count);
    }

    // 4. reusing 종료 후, local_stats의 증가량을 REUSING_STATS로 복사
    {
        let mut reusing_stats = REUSING_STATS.lock().unwrap();

        // 증가량 계산
        let exec_delta = handler.executor.local_stats.num_exec.0 - snapshot.num_exec.0;
        let inputs_delta = handler.executor.local_stats.num_inputs.0 - snapshot.num_inputs.0;
        let hangs_delta = handler.executor.local_stats.num_hangs.0 - snapshot.num_hangs.0;
        let crashes_delta = handler.executor.local_stats.num_crashes.0 - snapshot.num_crashes.0;

        // reusing 종료 시 증가량 로그
        // info!("[Reusing] Delta before save: exec={}, inputs={} (new paths), hangs={}, crashes={}",
        // exec_delta, inputs_delta, hangs_delta, crashes_delta);

        // REUSING_STATS에 누적
        reusing_stats.num_exec.0 += exec_delta;
        reusing_stats.num_inputs.0 += inputs_delta;
        reusing_stats.num_hangs.0 += hangs_delta;
        reusing_stats.num_crashes.0 += crashes_delta;

        // info!("[Reusing] COMPLETE: cmpid={}, pattern={:?}, executed={}/{}, reusing_delta: exec={}, inputs={}, total_reusing: exec={}, inputs={}",
        //       handler.cond.base.cmpid, pattern, execution_count, actual_iterations,
        //       exec_delta, inputs_delta,
        //       reusing_stats.num_exec.0, reusing_stats.num_inputs.0);
    }

    // 5. local_stats를 백업으로 복원 (다음 mutation에서 reusing이 카운트 안 되도록)
    handler.executor.local_stats.restore(&snapshot);
    handler.buf = buf_backup;

    // 복원 후 로그
    // info!("[Reusing] Restored local_stats: exec={}, inputs={}, hangs={}, crashes={}",
    // handler.executor.local_stats.num_exec.0,
    // handler.executor.local_stats.num_inputs.0,
    // handler.executor.local_stats.num_hangs.0,
    // handler.executor.local_stats.num_crashes.0);

     // 6. 조건문이 해결되었는지 확인
     if handler.cond.is_done() {
        // info!("[Reusing] SUCCESS! Solved cmpid={}",handler.cond.base.cmpid);
        return true;
    }
    return false;
}

fn try_combined_segments(handler: &mut SearchHandler, pattern: &Vec<u32>, iterations: usize) -> usize {
    // 각 세그먼트별로 개별 패턴 레코드 수집
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

    // 모든 세그먼트에 후보가 있는지 확인
    if segment_pools.iter().any(|pool| pool.is_empty()) {
        warn!("[Reusing] Cannot combine: some segment pools are empty");
        return 0;
    }

    // info!("[Reusing] All segment pools available, starting combined mutations");
    // ✅ 병합 오프셋을 루프 밖에서 1회만 계산
    let merged_offsets = merge_continuous_segments(&handler.cond.offsets);

    if merged_offsets.len() != pattern.len() {
        warn!("[Reusing] Merged offsets mismatch: offsets={}, pattern={}",
              merged_offsets.len(), pattern.len());
        return 0;
    }

    // ✅ 최대 버퍼 크기 미리 계산 및 할당
    let max_end = merged_offsets.iter()
        .map(|s| s.end as usize)
        .max()
        .unwrap_or(0);

    if max_end > handler.buf.len() {
        handler.buf.resize(max_end, 0);
    }

    let mut rng = rand::thread_rng();
    let mut execution_count = 0;

    // ✅ Vec 재사용 (매번 할당 X)
    let mut combined_values: Vec<Vec<u8>> = Vec::with_capacity(pattern.len());

    for iter in 0..iterations {
        if handler.is_stopped_or_skip() {
            warn!("[Reusing] Stopped early at combined iteration {}/{}", iter, iterations);
            break;
        }

        combined_values.clear();

        // 각 세그먼트별로 랜덤 선택
        for pool in &segment_pools {
            if let Some(record) = pool.choose(&mut rng) {
                combined_values.push(record.clone());
            }
        }



        // 조합된 값으로 mutation
        if combined_values.len() == merged_offsets.len() {
            // 값 삽입
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

            // 새로운 경로 발견 여부 확인
            if handler.executor.has_new_path {
                let depot = handler.executor.get_depot();
                let new_input_id = depot.num_inputs.load(std::sync::atomic::Ordering::Relaxed) - 1;

                // 삽입된 offset 정보
                let target_offsets: Vec<String> = merged_offsets.iter()
                    .map(|seg| format!("[{}..{}]", seg.begin, seg.end))
                    .collect();

                let log_msg = format!(
                    "[COMBINING REUSING] input_id={}, cmpid={}, pattern={:?}, \
                     target_offsets={:?}, combined_values={:?}, new_queue_input=id:{:06}",
                    handler.cond.base.belong, handler.cond.base.cmpid, pattern,
                    target_offsets, combined_values, new_input_id
                );
                info!("{}", log_msg);
                log_to_file(handler, &log_msg);
            }
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

    // 필요한 최대 크기를 한 번에 계산
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
        // if current.end == next.begin && current.sign == next.sign {
        if current.end == next.begin{
            current.end = next.end;
        } else {
            merged.push(current);
            current = next;
        }
    }
    merged.push(current);
    merged
}