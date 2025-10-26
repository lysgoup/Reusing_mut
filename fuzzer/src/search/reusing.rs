use crate::depot::{LABEL_PATTERN_MAP, extract_pattern_merged, CondRecord};
use crate::search::SearchHandler;
use rand::seq::SliceRandom;
use angora_common::tag::TagSeg;

/// Reusing mutation 수행 (100회 반복)
pub fn apply_reusing_mutation(handler: &mut SearchHandler, iterations: usize) {
    // 1. 현재 CondStmt의 label pattern 추출
    let pattern = extract_pattern_merged(&handler.cond.offsets);

    if pattern.is_empty() {
        debug!("[Reusing] No offsets found for cmpid={}, skipping", handler.cond.base.cmpid);
        return;
    }

    // 2. pattern_map에서 같은 패턴 찾기
    let map = LABEL_PATTERN_MAP.lock().unwrap();
    let records = match map.get(&pattern) {
        Some(r) if r.len() > 0 => r.clone(),
        _ => {
            debug!("[Reusing] Pattern {:?} not found in map (cmpid={})", pattern, handler.cond.base.cmpid);
            return;
        }
    };
    drop(map);

    let available_count = records.len();
    let actual_iterations = std::cmp::min(iterations, available_count);

    info!("[Reusing] START: cmpid={}, pattern={:?}, available_records={}, requested={}, actual={}",
          handler.cond.base.cmpid, pattern, available_count, iterations, actual_iterations);

    // 3. 중복 없이 선택: records를 섞은 후 앞에서부터 actual_iterations개 사용
    let mut rng = rand::thread_rng();
    use rand::seq::SliceRandom;  // shuffle 사용을 위해

    let mut shuffled_records = records.clone();
    shuffled_records.shuffle(&mut rng);  // 전체를 섞음

    let selected_records = &shuffled_records[..actual_iterations];  // 앞에서 필요한 만큼만

    let mut execution_count = 0;

    for (i, record) in selected_records.iter().enumerate() {
        if handler.is_stopped_or_skip() {
            warn!("[Reusing] Stopped early at iteration {}/{}", i, actual_iterations);
            break;
        }

        if insert_critical_value(handler, record) {
            let buf = handler.buf.clone();
            handler.execute(&buf);
            execution_count += 1;

            // 주기적으로 진행 상황 출력 (매 25회마다)
            if (i + 1) % 25 == 0 {
                debug!("[Reusing] Progress: {}/{} iterations, {} executions",
                       i + 1, actual_iterations, execution_count);
            }
        }
    }

    info!("[Reusing] COMPLETE: cmpid={}, pattern={:?}, executed={}/{}, has_new_path={}, inputs={}",
          handler.cond.base.cmpid, pattern, execution_count, actual_iterations,
          handler.executor.has_new_path,
          handler.executor.local_stats.num_inputs.0);
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