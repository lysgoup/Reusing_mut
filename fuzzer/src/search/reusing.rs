use crate::depot::{LABEL_PATTERN_MAP, extract_pattern_merged, CondRecord, get_next_records};
use crate::search::SearchHandler;
use rand::seq::SliceRandom;
use angora_common::tag::TagSeg;
use crate::stats::REUSING_STATS;

// Reusing mutation
pub fn apply_reusing_mutation(handler: &mut SearchHandler, iterations: usize) -> bool {
    // ✅ 1. local_stats 전체 백업
    let snapshot = handler.executor.local_stats.snapshot();
    let buf_backup = handler.buf.clone();

    // 2. pattern 추출
    let pattern = extract_pattern_merged(&handler.cond.offsets);

    let mut execution_count = 0;
    // ===== 1단계: 동일 패턴 시도 =====
    if !pattern.is_empty() {
       if let Some(selected_records) = get_next_records(&pattern, iterations) {
           let actual_iterations = selected_records.len();
        //    info!("[Reusing] Exact match: pattern={:?}, trying {} records (sequential)", pattern, actual_iterations);
   
           for (i, record) in selected_records.iter().enumerate() {
               if handler.is_stopped_or_skip() {
                   warn!("[Reusing] Stopped early at iteration {}/{}", i, actual_iterations);
                   break;
               }
   
               if insert_critical_value(handler, record) {
                   let buf = handler.buf.clone();
                   handler.execute(&buf);
                   execution_count += 1;
               }
           }
   
        //    info!("[Reusing] Exact match complete: executed {} iterations", execution_count);
       } else {
        //    info!("[Reusing] Pattern {:?}: All records exhausted or no records available", pattern);
       }
   }

    // ===== 2단계: 남은 횟수를 개별 세그먼트 조합으로 채우기 =====
    if execution_count < iterations {
        let remaining = iterations - execution_count;
        info!("[Reusing] Trying combined segments: {} iterations remaining", remaining);
        let combined_count = try_combined_segments(handler, &pattern, remaining);
        execution_count += combined_count;
        info!("[Reusing] Combined complete: executed {} iterations", combined_count);
    }

    // ✅ 6. reusing 종료 후, local_stats의 증가량을 REUSING_STATS로 복사
    {
        let mut reusing_stats = REUSING_STATS.lock().unwrap();

        // 증가량 계산
        let exec_delta = handler.executor.local_stats.num_exec.0 - snapshot.num_exec.0;
        let inputs_delta = handler.executor.local_stats.num_inputs.0 - snapshot.num_inputs.0;
        let hangs_delta = handler.executor.local_stats.num_hangs.0 - snapshot.num_hangs.0;
        let crashes_delta = handler.executor.local_stats.num_crashes.0 - snapshot.num_crashes.0;

        // ✅ reusing 종료 시 증가량 로그
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

    // ✅ 7. local_stats를 백업으로 복원 (다음 mutation에서 reusing이 카운트 안 되도록)
    handler.executor.local_stats.restore(&snapshot);
    handler.buf = buf_backup;

    // ✅ 복원 후 로그
    // info!("[Reusing] Restored local_stats: exec={}, inputs={}, hangs={}, crashes={}",
    // handler.executor.local_stats.num_exec.0,
    // handler.executor.local_stats.num_inputs.0,
    // handler.executor.local_stats.num_hangs.0,
    // handler.executor.local_stats.num_crashes.0);

     // ✅ 조건문이 해결되었는지 확인
     if handler.cond.is_done() {
        // info!("[Reusing] SUCCESS! Solved cmpid={}",handler.cond.base.cmpid);

        return true;  // ✅ 성공!
    }
    return false;
}

fn try_combined_segments(handler: &mut SearchHandler, pattern: &Vec<u32>, iterations: usize) -> usize {
    let map = LABEL_PATTERN_MAP.lock().unwrap();

    // 각 세그먼트별로 개별 패턴 레코드 수집
    let mut segment_pools: Vec<Vec<CondRecord>> = Vec::new();

    for (idx, &segment_size) in pattern.iter().enumerate() {
        let single_pattern = vec![segment_size];
        if let Some(records) = map.get(&single_pattern) {
            segment_pools.push(records.clone());
            // info!("[Reusing] Segment[{}] size={}: {} records available",idx, segment_size, records.len());
        } else {
            segment_pools.push(vec![]);
            warn!("[Reusing] Segment[{}] size={}: NO records available", idx, segment_size);
        }
    }

    drop(map);

    // 모든 세그먼트에 후보가 있는지 확인
    if segment_pools.iter().any(|pool| pool.is_empty()) {
        warn!("[Reusing] Cannot combine: some segment pools are empty");
        return 0;
    }

    // info!("[Reusing] All segment pools available, starting combined mutations");

    let mut rng = rand::thread_rng();
    let mut execution_count = 0;

    for iter in 0..iterations {
        if handler.is_stopped_or_skip() {
            warn!("[Reusing] Stopped early at combined iteration {}/{}", iter, iterations);
            break;
        }

        // 각 세그먼트별로 랜덤 선택
        let mut combined_values: Vec<Vec<u8>> = Vec::new();

        for pool in &segment_pools {
            if let Some(record) = pool.choose(&mut rng) {
                if !record.critical_values.is_empty() {
                    combined_values.push(record.critical_values[0].clone());
                }
            }
        }

        // 조합된 값으로 mutation
        if combined_values.len() == pattern.len() {
            if insert_combined_values(handler, &combined_values) {
                let buf = handler.buf.clone();
                handler.execute(&buf);
                execution_count += 1;
            }
        }
    }

    execution_count  // ✅ 실행 횟수 반환
}

fn insert_combined_values(handler: &mut SearchHandler, values: &Vec<Vec<u8>>) -> bool {  // ✅ bool 반환
    let merged_offsets = merge_continuous_segments(&handler.cond.offsets);

    if merged_offsets.len() != values.len() {
        warn!("[Reusing] Combined values size mismatch: offsets={}, values={}",
              merged_offsets.len(), values.len());
        return false;
    }

    for (i, seg) in merged_offsets.iter().enumerate() {
        if i >= values.len() {
            break;
        }

        let begin = seg.begin as usize;
        let end = seg.end as usize;
        let value = &values[i];

        if end > handler.buf.len() {
            handler.buf.resize(end, 0);
        }

        let copy_len = std::cmp::min(value.len(), end - begin);
        handler.buf[begin..begin + copy_len]
            .copy_from_slice(&value[..copy_len]);
    }

    true  // ✅ 성공 시 true 반환
}

fn insert_critical_value(handler: &mut SearchHandler, record: &CondRecord) -> bool {
    let offsets = &handler.cond.offsets;
    let critical_values = &record.critical_values;

    let merged_offsets = merge_continuous_segments(offsets);

    if merged_offsets.len() != critical_values.len() {
        debug!("[Reusing] Offset mismatch: expected {} segments, got {} values (from cmpid={})",
               merged_offsets.len(), critical_values.len(), record.cmpid);
        return false;
    }

    for (i, seg) in merged_offsets.iter().enumerate() {
        let begin = seg.begin as usize;
        let end = seg.end as usize;
        let value = &critical_values[i];

        if end > handler.buf.len() {
            handler.buf.resize(end, 0);
        }

        let copy_len = std::cmp::min(value.len(), end - begin);
        handler.buf[begin..begin + copy_len]
            .copy_from_slice(&value[..copy_len]);

        debug!("[Reusing] Inserted value at offset {}..{}: {:?} (from cmpid={})", begin, begin + copy_len, &value[..copy_len], record.cmpid);
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
        if current.end == next.begin && current.sign == next.sign {
            current.end = next.end;
        } else {
            merged.push(current);
            current = next;
        }
    }
    merged.push(current);
    merged
}