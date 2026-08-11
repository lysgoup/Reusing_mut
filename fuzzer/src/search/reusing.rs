use crate::depot::{LABEL_PATTERN_MAP, MAGIC_BYTE_MAP, LOOP_COUNTER_MAP, LabelPattern, extract_pattern_merged, extract_magic_and_tainted, CondRecord, get_next_records};
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

    // 2. is_magic_byte는 구조적 분류일 뿐(CondStmt::from) -- 이 cond가 실제로
    //    변형 없이 입력 바이트를 그대로 비교하는지는 여기서 원본 buf로 다시
    //    검증해야 함. 검증 실패(변형된 비교)면 애초에 add_magic_byte_records가
    //    MAGIC_BYTE_MAP/LOOP_COUNTER_MAP에 이 cond의 값을 저장하지 않았고
    //    (add_cond_to_pattern_map이 대신 LABEL_PATTERN_MAP에 저장해둠), 그래서
    //    magic byte 경로로 보내봐야 후보가 없어 그냥 허탕침 -- 검증 통과한
    //    것만 magic 경로로 보내고, 나머지는 일반 경로로 폴백함.
    let is_untransformed_magic = handler.cond.is_magic_byte
        && extract_magic_and_tainted(&handler.cond, &handler.buf).is_some();

    // 3. pattern 추출 -- 인접 1바이트 magic byte 그룹에 속한 cond라면(
    //    magic_byte_group, fparser.rs에서 taint tracking 직후에 계산됨),
    //    자기 자신의 1바이트 offsets 대신 그룹 전체의 병합된 offsets를 써야
    //    MAGIC_BYTE_MAP에 실제로 저장돼있는(병합된) 패턴과 일치함. 일반 경로로
    //    폴백하는 경우엔 LABEL_PATTERN_MAP이 cond 자신의 offsets로 저장돼있으니
    //    그룹 병합 패턴을 쓰면 안 됨.
    let pattern = if is_untransformed_magic && !handler.cond.magic_byte_group.is_empty() {
        extract_pattern_merged(&handler.cond.magic_byte_group)
    } else {
        extract_pattern_merged(&handler.cond.offsets)
    };
    if pattern.is_empty(){
        return false;
    }

    // 4. reusing 진행 -- magic byte 조건문은 MAGIC_BYTE_MAP만, 나머지는 LABEL_PATTERN_MAP만 사용.
    //    단, cmpid 자체가 loop counter로 확정된 magic byte 조건문이라면 LOOP_COUNTER_MAP으로
    //    완전히 대체 -- MAGIC_BYTE_MAP[pattern]엔 이 cmpid의 값이 이미 다 빠져있어서(스윕됨)
    //    거기서 뭘 뽑아봐야 이 cond 자신과는 무관한 값들뿐이고, LOOP_COUNTER_MAP[cmpid]엔
    //    바로 이 cond 자신의 실제 관측값(예: 다른 이미지들의 진짜 width)이 있어서 더 타겟팅됨.
    let mut execution_count = 0;

    if is_untransformed_magic {
        let is_loop_counter = LOOP_COUNTER_MAP.lock().unwrap().contains_key(&handler.cond.base.cmpid);
        execution_count = if is_loop_counter {
            apply_loop_counter_pool(handler, iterations)
        } else {
            apply_magic_byte_pool(handler, &pattern, iterations)
        };

        // Magic/loop pool 소진 후 남은 budget으로 general pool fallback
        let remaining = iterations - execution_count;
        if remaining > 0 && !handler.is_stopped_or_skip() {
            let general_pattern = extract_pattern_merged(&handler.cond.offsets);
            if !general_pattern.is_empty() {
                let total_records = {
                    let map = LABEL_PATTERN_MAP.lock().unwrap();
                    map.get(&general_pattern).map(|p| p.records.len()).unwrap_or(0)
                };
                if handler.cond.reusing_general_record_index < total_records {
                    if let Some(selected_records) = get_next_records(
                        &mut handler.cond.reusing_general_record_index,
                        &general_pattern,
                        remaining,
                    ) {
                        let merged_offsets = merge_continuous_segments(&handler.cond.offsets);
                        for record in selected_records.iter() {
                            if handler.is_stopped_or_skip() { break; }
                            if insert_critical_value_with_merged(handler, record, &merged_offsets) {
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
                let remaining2 = iterations - execution_count;
                if remaining2 > 0 && general_pattern.len() >= 2 {
                    execution_count += try_combined_segments(handler, &general_pattern, remaining2);
                }
            }
        }
    } else {
        let map = LABEL_PATTERN_MAP.lock().unwrap();
        let total_records = map.get(&pattern).map(|pool| pool.records.len()).unwrap_or(0);
        drop(map);

        if handler.cond.reusing_record_index >= total_records {
            info!("[Reusing] Pattern {:?}: All records already used (index={}/{}), skipping original reusing",
                  pattern, handler.cond.reusing_record_index, total_records);
        } else {
            // ===== 1단계: 동일 패턴 시도 =====
            if let Some(selected_records) = get_next_records(&mut handler.cond.reusing_record_index, &pattern, iterations) {
                // let actual_iterations = selected_records.len();
                //    info!("[Reusing] Exact match: pattern={:?}, trying {} records (sequential)", pattern, actual_iterations);

                let merged_offsets = merge_continuous_segments(&handler.cond.offsets);

                for (i, record) in selected_records.iter().enumerate() {
                    if handler.is_stopped_or_skip() {
                        // warn!("[Reusing] Stopped early at iteration {}/{}", i, actual_iterations);
                        break;
                    }

                    if insert_critical_value_with_merged(handler, record, &merged_offsets) {
                        handler.executor.current_reusing_detail = merged_offsets.iter()
                            .zip(record.critical_values.iter())
                            .map(|(seg, val)| (seg.begin, seg.end, val.clone()))
                            .collect();
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
        if execution_count < iterations && pattern.len() >= 2 {
            let remaining = iterations - execution_count;
            //  info!("[Reusing] Trying combined segments: {} iterations remaining", remaining);
            let combined_count = try_combined_segments(handler, &pattern, remaining);
            execution_count += combined_count;
            //  info!("[Reusing] Combined complete: executed {} iterations", combined_count);
        }
    }

    // 5. reusing 종료 후, local_stats의 증가량을 REUSING_STATS로 복사
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

    // 6. local_stats를 백업으로 복원 (다음 mutation에서 reusing이 카운트 안 되도록)
    handler.executor.local_stats.restore(&snapshot);
    handler.buf = buf_backup;

    // 복원 후 로그
    // info!("[Reusing] Restored local_stats: exec={}, inputs={}, hangs={}, crashes={}",
    // handler.executor.local_stats.num_exec.0,
    // handler.executor.local_stats.num_inputs.0,
    // handler.executor.local_stats.num_hangs.0,
    // handler.executor.local_stats.num_crashes.0);

     // 7. 조건문이 해결되었는지 확인
     if handler.cond.is_done() {
        // info!("[Reusing] SUCCESS! Solved cmpid={}",handler.cond.base.cmpid);
        return true;
    }
    return false;
}

// magic byte 조건문 전용: 일반 reusing(insert_critical_value_with_merged)과
// 완전히 동일하게 값을 그대로 buf에 삽입만 함. 차이는 MAGIC_BYTE_MAP에서 후보를
// 가져온다는 것뿐 -- diff 보정 등은 여기서 하지 않음 (FnFuzz가 별도로 담당).
fn apply_magic_byte_pool(handler: &mut SearchHandler, pattern: &LabelPattern, iterations: usize) -> usize {
    // Slice forward from cond.reusing_record_index (same field/pattern as
    // LABEL_PATTERN_MAP's get_next_records) instead of collecting the whole
    // pool bucket and re-trying the same HashMap-iteration-order prefix on
    // every call -- pool.order is insertion-ordered and stable, so this
    // actually advances through the full candidate set across repeated
    // mutation attempts on the same cond, and only clones the slice it needs.
    let candidates: Vec<Vec<u8>> = {
        let map = MAGIC_BYTE_MAP.lock().unwrap();
        match map.get(pattern) {
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

    // 인접 그룹에 속해있으면 그룹 전체 span을 써야 pattern(N바이트)과
    // 실제로 buf에 삽입되는 범위가 맞음 -- 자기 자신의 1바이트 span만 쓰면
    // pool에서 꺼낸 N바이트 값을 1바이트만 덮어쓰게 됨.
    let merged_offsets = if !handler.cond.magic_byte_group.is_empty() {
        handler.cond.magic_byte_group.clone()
    } else {
        merge_continuous_segments(&handler.cond.offsets)
    };
    // is_magic_byte_cmp()는 정확히 한쪽 라벨만 taint된 경우만 통과시키므로
    // cond.offsets(혹은 magic_byte_group)는 하나의 연속 영역으로 병합되는 게 정상.
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
    for magic in candidates.iter() {
        if handler.is_stopped_or_skip() {
            break;
        }

        let len = magic.len().min(end - begin);
        handler.buf[begin..begin + len].copy_from_slice(&magic[..len]);
        handler.executor.current_reusing_detail = vec![(seg.begin, seg.begin + len as u32, magic[..len].to_vec())];

        let buf = handler.buf.clone();
        handler.execute(&buf);
        execution_count += 1;
    }
    execution_count
}

// loop-counter로 확정된 magic byte 조건문 전용. MAGIC_BYTE_MAP처럼 길이(pattern)로
// 조회하지 않고 cmpid로 직접 조회함 -- 이 cond 자신이 관측한 값들만 담겨있어서
// (다른 cmpid 값과 안 섞임) apply_magic_byte_pool보다 더 타겟팅된 candidate pool임.
// 나머지 로직(인덱스 슬라이싱, offset에 그대로 삽입)은 apply_magic_byte_pool과 동일.
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