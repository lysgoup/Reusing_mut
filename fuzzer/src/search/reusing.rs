use crate::depot::{LABEL_PATTERN_MAP, LOOP_COUNTER_MAP, LabelPattern, extract_pattern_merged, CondRecord, get_next_records};
use crate::search::SearchHandler;
use rand::seq::SliceRandom;
use angora_common::tag::TagSeg;
use crate::stats::REUSING_STATS;

// Reusing mutation
pub fn apply_reusing_mutation(handler: &mut SearchHandler, iterations: usize) -> bool {
    // 0. 이미 해결된 조건이면 스킵
    if handler.cond.is_done() {
        return false;
    }

    // 1. local_stats 전체 백업
    let snapshot = handler.executor.local_stats.snapshot();
    let buf_backup = handler.buf.clone();

    // 2. pattern/merged_offsets 추출 -- 인접 1바이트 magic byte 그룹에 속한 cond라면
    //    (magic_byte_group, fparser.rs에서 taint tracking 직후에 계산됨) 자기 자신의
    //    1바이트 offsets 대신 그룹 전체의 병합된 offsets를 써야 LABEL_PATTERN_MAP에
    //    실제로 저장돼있는(병합된) 패턴/범위와 일치함. magic 값도 이제 일반 값과 같은
    //    LABEL_PATTERN_MAP에 저장되므로(add_magic_byte_records 참고) 모든 cond가 이
    //    한 경로(apply_label_pattern_pool)만 씀 -- is_magic_byte 여부는 loop-counter
    //    cmpid인지 먼저 확인할지 판단할 때만 씀.
    let merged_offsets = if !handler.cond.magic_byte_group.is_empty() {
        handler.cond.magic_byte_group.clone()
    } else {
        merge_continuous_segments(&handler.cond.offsets)
    };
    let pattern: LabelPattern = extract_pattern_merged(&merged_offsets);
    if pattern.is_empty(){
        return false;
    }

    // 3. reusing 진행 -- cmpid 자체가 loop counter로 확정된 magic byte 조건문이면
    //    LOOP_COUNTER_MAP으로 먼저 타겟팅함: 바로 이 cond 자신의 실제 관측값(예: 다른
    //    이미지들의 진짜 width)이 담겨있어서 LABEL_PATTERN_MAP보다 더 타겟팅됨. 소진
    //    후 남은 budget은 reusing_general_record_index로 분리 관리해서
    //    LABEL_PATTERN_MAP으로 폴백 -- reusing_record_index를 같이 쓰면 반복 호출마다
    //    서로 진행 상황을 밀어내서 둘 다 처음부터 다시 시도하게 됨.
    let mut execution_count = 0;

    if handler.cond.is_magic_byte
        && LOOP_COUNTER_MAP.lock().unwrap().contains_key(&handler.cond.base.cmpid)
    {
        execution_count = apply_loop_counter_pool(handler, iterations);
        if execution_count < iterations && !handler.is_stopped_or_skip() {
            let remaining = iterations - execution_count;
            let mut general_index = handler.cond.reusing_general_record_index;
            execution_count += apply_label_pattern_pool(
                handler, &pattern, &merged_offsets, remaining, &mut general_index,
            );
            handler.cond.reusing_general_record_index = general_index;
        }
    } else {
        let mut index = handler.cond.reusing_record_index;
        execution_count = apply_label_pattern_pool(handler, &pattern, &merged_offsets, iterations, &mut index);
        handler.cond.reusing_record_index = index;
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

// LABEL_PATTERN_MAP 소비: 정확 패턴 매칭(exact match) 시도 후, 부족분은 개별
// 세그먼트 조합(combined segments)으로 채움. magic-byte 값도 이제 일반 값과 같은
// 풀에 저장되므로(insert_magic_byte_value 참고) 모든 cond가 이 함수 하나로 처리됨.
// `record_index`는 호출부가 어떤 인덱스 필드(reusing_record_index 또는
// reusing_general_record_index)를 쓸지 결정해서 넘겨줌 -- loop-counter pool
// 소진 후 폴백하는 경우엔 별도 인덱스를 써야 서로 진행 상황을 안 밀어냄.
fn apply_label_pattern_pool(
    handler: &mut SearchHandler,
    pattern: &LabelPattern,
    merged_offsets: &[TagSeg],
    iterations: usize,
    record_index: &mut usize,
) -> usize {
    let mut execution_count = 0;

    let total_records = {
        let map = LABEL_PATTERN_MAP.lock().unwrap();
        map.get(pattern).map(|pool| pool.records.len()).unwrap_or(0)
    };

    if *record_index < total_records {
        // ===== 1단계: 동일 패턴 시도 =====
        if let Some(selected_records) = get_next_records(record_index, pattern, iterations) {
            for record in selected_records.iter() {
                if handler.is_stopped_or_skip() {
                    break;
                }

                if insert_critical_value_with_merged(handler, record, merged_offsets) {
                    handler.executor.current_reusing_detail = merged_offsets.iter()
                        .zip(record.critical_values.iter())
                        .map(|(seg, val)| (seg.begin, seg.end, val.clone()))
                        .collect();
                    let buf = handler.buf.clone();
                    handler.execute(&buf);
                    execution_count += 1;
                }
            }
        }
    }

    // ===== 2단계: 남은 횟수를 개별 세그먼트 조합으로 채우기 =====
    if execution_count < iterations && pattern.len() >= 2 {
        let remaining = iterations - execution_count;
        execution_count += try_combined_segments(handler, pattern, remaining);
    }

    execution_count
}

// loop-counter로 확정된 magic byte 조건문 전용. LABEL_PATTERN_MAP처럼 길이(pattern)로
// 조회하지 않고 cmpid로 직접 조회함 -- 이 cond 자신이 관측한 값들만 담겨있어서
// (다른 cmpid 값과 안 섞임) apply_label_pattern_pool보다 더 타겟팅된 candidate pool임.
// 나머지 로직(인덱스 슬라이싱, offset에 그대로 삽입)은 apply_label_pattern_pool과 유사.
fn apply_loop_counter_pool(handler: &mut SearchHandler, iterations: usize) -> usize {
    let cmpid = handler.cond.base.cmpid;
    let candidates: Vec<Vec<u8>> = {
        let map = LOOP_COUNTER_MAP.lock().unwrap();
        match map.get(&cmpid) {
            Some(pool) => {
                let total = pool.order.len();
                let start = handler.cond.reusing_record_index;
                if start >= total {
                    Vec::new()
                } else {
                    let end = (start + iterations).min(total);
                    handler.cond.reusing_record_index = end;
                    pool.order[start..end].to_vec()
                }
            },
            None => Vec::new(),
        }
    };
    if candidates.is_empty() {
        return 0;
    }

    let merged_offsets = if !handler.cond.magic_byte_group.is_empty() {
        handler.cond.magic_byte_group.clone()
    } else {
        merge_continuous_segments(&handler.cond.offsets)
    };
    if merged_offsets.len() != 1 {
        return 0;
    }
    let seg = merged_offsets[0];
    let begin = seg.begin as usize;
    let end = seg.end as usize;

    let max_end = end.max(handler.buf.len());
    if max_end > handler.buf.len() {
        handler.buf.resize(max_end, 0);
    }

    let mut execution_count = 0;
    for value in candidates.iter() {
        if handler.is_stopped_or_skip() {
            break;
        }

        let len = value.len().min(end - begin);
        handler.buf[begin..begin + len].copy_from_slice(&value[..len]);
        handler.executor.current_reusing_detail = vec![(seg.begin, seg.begin + len as u32, value[..len].to_vec())];

        let buf = handler.buf.clone();
        handler.execute(&buf);
        execution_count += 1;
    }
    execution_count
}

fn try_combined_segments(handler: &mut SearchHandler, pattern: &Vec<u32>, iterations: usize) -> usize {
    // 각 세그먼트별로 개별 패턴 레코드 수집
    let segment_pools: Vec<Vec<Vec<u8>>> = {
        let map = LABEL_PATTERN_MAP.lock().unwrap();

        pattern.iter().map(|&segment_size| {
            let single_pattern = vec![segment_size];
            map.get(&single_pattern)
                .map(|pool| {
                    pool.records.iter()
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

            handler.executor.current_reusing_detail = merged_offsets.iter()
                .zip(combined_values.iter())
                .map(|(seg, val)| (seg.begin, seg.end, val.clone()))
                .collect();

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