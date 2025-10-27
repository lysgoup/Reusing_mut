use crate::depot::{LABEL_PATTERN_MAP, extract_pattern_merged, CondRecord};
use crate::search::SearchHandler;
use rand::seq::SliceRandom;
use angora_common::tag::TagSeg;
use crate::stats::REUSING_STATS;

// Reusing mutation 수행 (100회 반복)
pub fn apply_reusing_mutation(handler: &mut SearchHandler, iterations: usize) -> bool {
    // ✅ 1. local_stats 전체 백업
    let snapshot = handler.executor.local_stats.snapshot();

    // 2. pattern 추출
    let pattern = extract_pattern_merged(&handler.cond.offsets);

    if pattern.is_empty() {
        debug!("[Reusing] No offsets found for cmpid={}, skipping", handler.cond.base.cmpid);
        return false;
    }

    // 3. pattern_map에서 레코드 찾기
    let map = LABEL_PATTERN_MAP.lock().unwrap();
    let records = match map.get(&pattern) {
        Some(r) if r.len() > 0 => r.clone(),
        _ => {
            debug!("[Reusing] Pattern {:?} not found in map (cmpid={})", pattern, handler.cond.base.cmpid);
            return false;
        }
    };
    drop(map);

    let available_count = records.len();
    let actual_iterations = std::cmp::min(iterations, available_count);

    // info!("[Reusing] START: cmpid={}, pattern={:?}, available={}, actual={}",
    //       handler.cond.base.cmpid, pattern, available_count, actual_iterations);

    // 4. 레코드 섞기 및 선택
    let mut rng = rand::thread_rng();
    let mut shuffled_records = records.clone();
    shuffled_records.shuffle(&mut rng);
    let selected_records = &shuffled_records[..actual_iterations];

    let mut execution_count = 0;

    // 5. reusing 실행 (local_stats에 자동 누적됨)
    for (i, record) in selected_records.iter().enumerate() {
        if handler.is_stopped_or_skip() {
            warn!("[Reusing] Stopped early at iteration {}/{}", i, actual_iterations);
            break;
        }

        if insert_critical_value(handler, record) {
            let buf = handler.buf.clone();
            handler.execute(&buf);  // num_exec++, num_inputs++ 등 자동 증가
            execution_count += 1;
        }
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

    // ✅ 복원 후 로그
    // info!("[Reusing] Restored local_stats: exec={}, inputs={}, hangs={}, crashes={}",
    // handler.executor.local_stats.num_exec.0,
    // handler.executor.local_stats.num_inputs.0,
    // handler.executor.local_stats.num_hangs.0,
    // handler.executor.local_stats.num_crashes.0);

     // ✅ 조건문이 해결되었는지 확인
     if handler.cond.is_done() {
        info!("[Reusing] SUCCESS! Solved cmpid={}",
              handler.cond.base.cmpid);

        // REUSING_STATS 업데이트
        // ... (기존 로직)

        // local_stats 복원
        handler.executor.local_stats.restore(&snapshot);

        return true;  // ✅ 성공!
    }
    return false;
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