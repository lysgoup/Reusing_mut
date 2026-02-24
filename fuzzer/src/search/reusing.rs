use crate::depot::{LABEL_PATTERN_MAP, extract_pattern_merged, CondRecord, get_next_records, merge_continuous_segments};
use crate::search::SearchHandler;
use rand::seq::SliceRandom;
use angora_common::tag::TagSeg;
use crate::stats::REUSING_STATS;

pub struct ReusingFuzz<'a> {
    handler: SearchHandler<'a>,
}

impl<'a> ReusingFuzz<'a> {
    pub fn new(handler: SearchHandler<'a>) -> Self {
        Self { handler }
    }

    /// Reusing mutation을 실행
    pub fn run(mut self) {
        self.apply_reusing_mutation();
    }

    fn apply_reusing_mutation(&mut self) -> bool {
        // 0. 이미 해결된 조건이면 스킵
        if self.handler.cond.is_done() {
            return false;
        }

        // 1. local_stats 전체 백업
        let snapshot = self.handler.executor.local_stats.snapshot();
        let buf_backup = self.handler.buf.clone();

        // 2. pattern 추출
        let pattern = extract_pattern_merged(&self.handler.cond.offsets);
        if pattern.is_empty() {
            return false;
        }

        // 3. 병합된 오프셋 미리 계산
        let merged_offsets = merge_continuous_segments(&self.handler.cond.offsets);

        // 4. 모든 저장된 레코드를 다 사용 (Stage 1: 전체 패턴)
        if let Some(selected_records) = get_next_records(&mut self.handler.cond, &pattern, usize::MAX) {
            for record in selected_records.iter() {
                if self.handler.is_stopped_or_skip() {
                    break;
                }

                if self.insert_critical_value_with_merged(&record, &merged_offsets) {
                    let buf = self.handler.buf.clone();
                    self.handler.execute(&buf);
                }

                if self.handler.cond.is_done() {
                    break;
                }
            }
        }

        // 5. Stage 2: 세그먼트 조합 mutation (세그먼트가 2개 이상일 때만)
        if merged_offsets.len() >= 2 && !self.handler.cond.is_done() {
            for seg_idx in 0..merged_offsets.len() {
                if self.handler.is_stopped_or_skip() {
                    break;
                }

                let seg = merged_offsets[seg_idx];
                let segment_size = seg.end - seg.begin;
                let single_pattern = vec![segment_size];

                // LABEL_PATTERN_MAP에서 해당 세그먼트 크기의 레코드들 가져오기
                let records = {
                    let map = match LABEL_PATTERN_MAP.lock() {
                        Ok(guard) => guard,
                        Err(poisoned) => {
                            error!("❌ CRITICAL: [Reusing] LABEL_PATTERN_MAP poisoned in segment combination!");
                            poisoned.into_inner()
                        }
                    };
                    map.get(&single_pattern).cloned().unwrap_or_default()
                };

                let start_index = self.handler.cond.reusing_segment_index[seg_idx];

                // start_index부터 시작해서 남은 레코드들 처리
                for (rec_idx, record) in records.iter().enumerate().skip(start_index) {
                    if self.handler.is_stopped_or_skip() {
                        break;
                    }

                    // 이 세그먼트의 critical value만 사용
                    if !record.critical_values.is_empty() {
                        let value = &record.critical_values[0];
                        let begin = seg.begin as usize;
                        let end = seg.end as usize;

                        // 버퍼 크기 조정
                        if end > self.handler.buf.len() {
                            self.handler.buf.resize(end, 0);
                        }

                        // 이 세그먼트에만 critical value 복사
                        let copy_len = value.len().min(end - begin);
                        self.handler.buf[begin..begin + copy_len].copy_from_slice(&value[..copy_len]);

                        let buf = self.handler.buf.clone();
                        self.handler.execute(&buf);
                    }

                    if self.handler.cond.is_done() {
                        break;
                    }

                    // 이 세그먼트의 처리 위치 업데이트
                    self.handler.cond.reusing_segment_index[seg_idx] = rec_idx + 1;
                }

                if self.handler.cond.is_done() {
                    break;
                }
            }
        }

        // 7. reusing 종료 후, local_stats의 증가량을 REUSING_STATS로 복사
        {
            let mut reusing_stats = REUSING_STATS.lock().unwrap();

            // 증가량 계산
            let exec_delta = self.handler.executor.local_stats.num_exec.0 - snapshot.num_exec.0;
            let inputs_delta = self.handler.executor.local_stats.num_inputs.0 - snapshot.num_inputs.0;
            let hangs_delta = self.handler.executor.local_stats.num_hangs.0 - snapshot.num_hangs.0;
            let crashes_delta = self.handler.executor.local_stats.num_crashes.0 - snapshot.num_crashes.0;

            // REUSING_STATS에 누적
            reusing_stats.num_exec.0 += exec_delta;
            reusing_stats.num_inputs.0 += inputs_delta;
            reusing_stats.num_hangs.0 += hangs_delta;
            reusing_stats.num_crashes.0 += crashes_delta;
        }

        // 8. local_stats를 백업으로 복원
        self.handler.executor.local_stats.restore(&snapshot);
        self.handler.buf = buf_backup;

        // 9. 조건문이 해결되었는지 확인
        if self.handler.cond.is_done() {
            return true;
        }
        return false;
    }

    fn insert_critical_value_with_merged(
        &mut self,
        record: &CondRecord,
        merged_offsets: &[TagSeg],
    ) -> bool {
        let critical_values = &record.critical_values;

        if merged_offsets.len() != critical_values.len() {
            return false;
        }

        // 필요한 최대 크기를 한 번에 계산
        let max_end = merged_offsets.iter().map(|s| s.end as usize).max().unwrap_or(0);
        if max_end > self.handler.buf.len() {
            self.handler.buf.resize(max_end, 0);
        }

        for (seg, value) in merged_offsets.iter().zip(critical_values.iter()) {
            let begin = seg.begin as usize;
            let end = seg.end as usize;
            let copy_len = value.len().min(end - begin);

            self.handler.buf[begin..begin + copy_len].copy_from_slice(&value[..copy_len]);
        }

        true
    }
}