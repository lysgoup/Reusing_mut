use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use lazy_static::lazy_static;
use angora_common::tag::TagSeg;
use crate::cond_stmt::CondStmt;
use std::fs::File;
use std::io::{self, Write};
use std::path::Path;
use serde_derive::{Serialize, Deserialize};
use super::depot::Depot;

pub type LabelPattern = Vec<u32>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CondRecord {
    pub cmpid: u32,
    // pub order: u32,
    // pub context: u32,
    // pub op: u32,
    // pub lb1: u32,
    // pub lb2: u32,
    // pub condition: u32,
    // pub belong: u32,
    // pub arg1: u64,
    // pub arg2: u64,
    pub offsets: Vec<TagSeg>,
    pub critical_values: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReusingPatternStats {
    pub pattern: Vec<u32>,
    pub total_records: usize,
    pub max_index_reached: usize,
    pub times_executed: usize,
    pub stage1_attempts: usize,
    pub stage2_attempts: usize,
    pub success_count: usize,
    pub combined_segment_success: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CondStmtReusingStats {
    pub cmpid: u32,
    pub context: u32,
    pub order: u32,
    pub pattern: Vec<u32>,
    pub stage1_attempts: usize,
    pub stage2_attempts: usize,
}

lazy_static! {
    pub static ref LABEL_PATTERN_MAP: Mutex<HashMap<LabelPattern, Vec<CondRecord>>> =
      Mutex::new(HashMap::new());

    pub static ref PATTERN_REUSING_STATS: Mutex<HashMap<Vec<u32>, ReusingPatternStats>> =
      Mutex::new(HashMap::new());

    pub static ref CONDSTMT_REUSING_STATS: Mutex<HashMap<(u32, u32, u32), CondStmtReusingStats>> =
      Mutex::new(HashMap::new());
}

pub fn extract_pattern(offsets: &Vec<TagSeg>) -> LabelPattern {
  offsets.iter().map(|seg| seg.end - seg.begin).collect()
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

pub fn extract_pattern_merged(offsets: &Vec<TagSeg>) -> LabelPattern {
  let merged = merge_continuous_segments(offsets);
  merged.iter().map(|seg| seg.end - seg.begin).collect()
}

fn extract_value_from_label(offsets: &Vec<TagSeg>, input_buf: &Vec<u8>) -> Vec<Vec<u8>> {
  let merged_offsets = merge_continuous_segments(offsets);
  let mut critical_values = Vec::new();

  for seg in &merged_offsets {
      let begin = seg.begin as usize;
      let end = seg.end as usize;

      if end <= input_buf.len() {
        critical_values.push(input_buf[begin..end].to_vec());
      } else if begin < input_buf.len() {
          let mut bytes = input_buf[begin..].to_vec();
          bytes.resize(end - begin, 0);
          critical_values.push(bytes);
      } else {
        critical_values.push(vec![0u8; end - begin]);
      }
  }

  critical_values
}

fn create_record_for_offsets(
  offsets: &Vec<TagSeg>,
  cond: &CondStmt,
  depot: &Depot,
  operand_num: u8,
) {
  if offsets.is_empty() {
      return;
  }

  // 병합된 세그먼트 추출
  let merged_offsets = merge_continuous_segments(offsets);
  let pattern = extract_pattern_merged(offsets);
  let input_buf = depot.get_input_buf(cond.base.belong as usize);
  let critical_values = extract_value_from_label(offsets, &input_buf);

  // 1. 전체 패턴 레코드 생성 (기존 로직)
  create_single_record(
      &pattern,
      offsets,
      &critical_values,
      cond,
      operand_num,
  );

  // 2. 패턴이 2개 이상의 세그먼트로 구성되어 있다면 개별 세그먼트도 추가
  if merged_offsets.len() > 1 {
      for i in 0..merged_offsets.len() {
          let single_segment = vec![merged_offsets[i]];
          let single_pattern = vec![merged_offsets[i].end - merged_offsets[i].begin];
          let single_critical_values = vec![critical_values[i].clone()];

          create_single_record(
              &single_pattern,
              &single_segment,
              &single_critical_values,
              cond,
              operand_num,
          );
      }
  }
}

// 헬퍼 함수: 실제 레코드 생성 로직
fn create_single_record(
  pattern: &LabelPattern,
  offsets: &Vec<TagSeg>,
  critical_values: &Vec<Vec<u8>>,
  cond: &CondStmt,
  operand_num: u8,
) {
  let mut map = LABEL_PATTERN_MAP.lock().unwrap();

  // 중복 체크
  if let Some(existing_records) = map.get(pattern) {
      for existing in existing_records.iter() {
          if existing.critical_values == *critical_values {
              return;
          }
      }
  }

  let record = CondRecord {
      cmpid: cond.base.cmpid,
      // order: cond.base.order,
      // context: cond.base.context,
      // op: cond.base.op,
      // lb1: cond.base.lb1,
      // lb2: cond.base.lb2,
      // condition: cond.base.condition,
      // belong: cond.base.belong,
      // arg1: cond.base.arg1,
      // arg2: cond.base.arg2,
      offsets: offsets.clone(),
      critical_values: critical_values.clone(),
  };

  map.entry(pattern.clone()).or_insert_with(Vec::new).push(record);
}

fn add_single_label_record(cond: &CondStmt, depot: &Depot) {
    create_record_for_offsets(&cond.offsets, cond, depot, 0);
}

fn add_dual_label_records(cond: &CondStmt, depot: &Depot) {
    if cond.offsets_opt.is_empty() {
        return;
    }

    create_record_for_offsets(&cond.offsets, cond, depot, 1);
    create_record_for_offsets(&cond.offsets_opt, cond, depot, 2);
}

pub fn add_cond_to_pattern_map(cond: &CondStmt, depot: &Depot) {
  if cond.base.lb1 > 0 && cond.base.lb2 == 0 {
      add_single_label_record(cond, depot);
  }
  else if cond.base.lb1 == 0 && cond.base.lb2 > 0 {
      add_single_label_record(cond, depot);
  }
  else if cond.base.lb1 > 0 && cond.base.lb2 > 0 {
      add_dual_label_records(cond, depot);
  }
}

pub fn get_stats() -> (usize, usize) {
  let map = LABEL_PATTERN_MAP.lock().unwrap();
  let num_patterns = map.len();
  let num_records: usize = map.values().map(|v| v.len()).sum();
  (num_patterns, num_records)
}

pub fn print_stats() {
  let (num_patterns, num_records) = get_stats();
  // info!("[LabelPattern] Total patterns: {}, Total records: {}", num_patterns, num_records);
}

fn check_continuous(offsets: &Vec<TagSeg>) -> bool {
  if offsets.len() <= 1 {
      return true;
  }

  for i in 0..offsets.len()-1 {
      if offsets[i].end != offsets[i+1].begin {
          return false;
      }
  }
  true
}

pub fn save_to_text(path: &Path) -> io::Result<()> {
  let map = LABEL_PATTERN_MAP.lock().unwrap();
  let mut file = File::create(path)?;

  writeln!(file, "# Angora Label Pattern Map")?;
  writeln!(file, "# Generated at: {}", chrono::Local::now())?;
  writeln!(file, "# Total patterns: {}", map.len())?;
  writeln!(file, "# Total records: {}", map.values().map(|v| v.len()).sum::<usize>())?;
  writeln!(file)?;

  let mut sorted_patterns: Vec<_> = map.iter().collect();
  sorted_patterns.sort_by_key(|(pattern, _)| pattern.clone());

  for (pattern, records) in sorted_patterns {
      writeln!(file, "Pattern: {:?} (size: {})", pattern, pattern.iter().sum::<u32>())?;
      writeln!(file, "  Records: {}", records.len())?;

      for (i, record) in records.iter().enumerate() {
        // writeln!(file, "    [{}] cmpid={}, order={}, context={}, op={:#x}, lb1={}, lb2={}, condition={}, belong={}, arg1={}, arg2={}", i, record.cmpid, record.order, record.context, record.op, record.lb1, record.lb2, record.condition, record.belong, record.arg1, record.arg2)?;
        writeln!(file, "        Cmpid: {:?}", record.cmpid)?;
        writeln!(file, "        Offsets: {:?}", record.offsets)?;
        writeln!(file, "        Critical values: {:?}", record.critical_values)?;
      }
      writeln!(file)?;
  }

  info!("[LabelPattern] Saved to {:?}", path);
  Ok(())
}

pub fn get_next_records(
  cond: &mut CondStmt,
  pattern: &LabelPattern,
  iterations: usize
) -> Option<Vec<CondRecord>> {
  let selected = {
    let map = LABEL_PATTERN_MAP.lock().unwrap();
    let records = map.get(pattern)?;

    let total = records.len();
    let start = cond.reusing_record_index;

    if start >= total {
        return None;
    }

    let end = (start + iterations).min(total);
    cond.reusing_record_index = end;

    records[start..end].to_vec()
  };

  Some(selected)
}

// Check if any taint offset overlaps with mutated offsets
fn offsets_overlap(taint_offsets: &Vec<TagSeg>, mutated_offsets: &HashSet<u32>) -> bool {
  for seg in taint_offsets {
    for offset in seg.begin..seg.end {
      if mutated_offsets.contains(&offset) {
        return true;
      }
    }
  }
  false
}

// Add cond to pattern map only if its offsets overlap with mutated offsets
pub fn add_cond_to_pattern_map_with_filter(
  cond: &CondStmt,
  depot: &Depot,
  mutated_offsets: &HashSet<u32>
) {
  // If mutated_offsets is empty, add without filtering (for initial seeds or non-mutation cases)
  if mutated_offsets.is_empty() {
    debug!("[LabelPattern] mutated_offsets is empty, adding without filter");
    add_cond_to_pattern_map(cond, depot);
    return;
  }

  // Check if this cond's offsets overlap with mutated offsets
  let has_overlap = offsets_overlap(&cond.offsets, mutated_offsets) ||
                    (!cond.offsets_opt.is_empty() && offsets_overlap(&cond.offsets_opt, mutated_offsets));

  if !has_overlap {
    debug!("[LabelPattern] No overlap - cond offsets: {:?}, mutated: {:?}",
           cond.offsets, mutated_offsets);
    return;
  }

  debug!("[LabelPattern] Overlap found - adding to pattern map");
  // If overlaps, add to pattern map
  add_cond_to_pattern_map(cond, depot);
}

// ============ Reusing Statistics Functions ============

pub fn update_pattern_stats(
    pattern: &Vec<u32>,
    max_index: usize,
    stage1_executed: bool,
    stage2_executed: bool,
    is_success: bool,
) {
    let mut stats_map = PATTERN_REUSING_STATS.lock().unwrap();

    let total_records = {
        let map = LABEL_PATTERN_MAP.lock().unwrap();
        map.get(pattern).map(|v| v.len()).unwrap_or(0)
    };

    let stats = stats_map.entry(pattern.clone())
        .or_insert_with(|| ReusingPatternStats {
            pattern: pattern.clone(),
            total_records,
            max_index_reached: 0,
            times_executed: 0,
            stage1_attempts: 0,
            stage2_attempts: 0,
            success_count: 0,
            combined_segment_success: 0,
        });

    stats.max_index_reached = stats.max_index_reached.max(max_index);
    stats.times_executed += 1;
    if stage1_executed { stats.stage1_attempts += 1; }
    if stage2_executed { stats.stage2_attempts += 1; }
    if is_success { stats.success_count += 1; }
}

pub fn update_combined_success(pattern: &Vec<u32>) {
    let mut stats_map = PATTERN_REUSING_STATS.lock().unwrap();
    if let Some(stats) = stats_map.get_mut(pattern) {
        stats.combined_segment_success += 1;
    }
}

pub fn update_condstmt_stats(
    cmpid: u32,
    context: u32,
    order: u32,
    pattern: &Vec<u32>,
    stage1_executed: bool,
    stage2_executed: bool,
) {
    let mut stats_map = CONDSTMT_REUSING_STATS.lock().unwrap();

    let stats = stats_map.entry((cmpid, context, order))
        .or_insert_with(|| CondStmtReusingStats {
            cmpid,
            context,
            order,
            pattern: pattern.clone(),
            stage1_attempts: 0,
            stage2_attempts: 0,
        });

    if stage1_executed { stats.stage1_attempts += 1; }
    if stage2_executed { stats.stage2_attempts += 1; }
}

pub fn save_reusing_stats(path: &Path) -> io::Result<()> {
    let pattern_stats_map = PATTERN_REUSING_STATS.lock().unwrap();
    let condstmt_stats_map = CONDSTMT_REUSING_STATS.lock().unwrap();

    let mut file = File::create(path)?;
    writeln!(file, "# Reusing Statistics Report")?;
    writeln!(file, "# Generated at: {}", chrono::Local::now())?;
    writeln!(file)?;

    // ===== Pattern Statistics =====
    writeln!(file, "## Pattern-Level Statistics")?;
    writeln!(file)?;

    let mut sorted_patterns: Vec<_> = pattern_stats_map.values().collect();
    sorted_patterns.sort_by_key(|s| std::cmp::Reverse(s.success_count));

    writeln!(file, "{:<25} {:<15} {:<20} {:<12} {:<12} {:<12} {:<12} {:<15}",
        "Pattern", "Total Records", "Max Used", "Times Exec", "Stage1", "Stage2", "Success", "Combined")?;
    writeln!(file, "{:-<130}", "")?;

    for stats in sorted_patterns.iter() {
        let utilization = if stats.total_records > 0 {
            (stats.max_index_reached as f64 / stats.total_records as f64 * 100.0) as u32
        } else {
            0
        };

        let pattern_str = format!("{:?}", stats.pattern);
        let used_str = format!("{}/{} ({}%)", stats.max_index_reached, stats.total_records, utilization);

        writeln!(file, "{:<25} {:<15} {:<20} {:<12} {:<12} {:<12} {:<12} {:<15}",
            pattern_str,
            stats.total_records,
            used_str,
            stats.times_executed,
            stats.stage1_attempts,
            stats.stage2_attempts,
            stats.success_count,
            stats.combined_segment_success
        )?;
    }

    writeln!(file)?;
    writeln!(file, "Pattern Summary:")?;
    let total_patterns = pattern_stats_map.len();
    let total_records: usize = pattern_stats_map.values().map(|s| s.total_records).sum();
    let total_executed: usize = pattern_stats_map.values().map(|s| s.times_executed).sum();
    let total_success: usize = pattern_stats_map.values().map(|s| s.success_count).sum();
    let avg_success_rate = if total_executed > 0 {
        (total_success as f64 / total_executed as f64 * 100.0) as u32
    } else {
        0
    };

    writeln!(file, "  Total Patterns: {}", total_patterns)?;
    writeln!(file, "  Total Records: {}", total_records)?;
    writeln!(file, "  Total Executions: {}", total_executed)?;
    writeln!(file, "  Total Successes: {}", total_success)?;
    writeln!(file, "  Overall Success Rate: {}%", avg_success_rate)?;

    // ===== CondStmt Statistics =====
    writeln!(file)?;
    writeln!(file, "## CondStmt-Level Statistics")?;
    writeln!(file)?;

    let mut sorted_condstmts: Vec<_> = condstmt_stats_map.values().collect();
    sorted_condstmts.sort_by_key(|s| (std::cmp::Reverse(s.stage1_attempts + s.stage2_attempts), s.cmpid));

    writeln!(file, "{:<10} {:<10} {:<10} {:<20} {:<12} {:<12}",
        "cmpid", "context", "order", "Pattern", "Stage1", "Stage2")?;
    writeln!(file, "{:-<80}", "")?;

    for stats in sorted_condstmts.iter() {
        let pattern_str = format!("{:?}", stats.pattern);
        writeln!(file, "{:<10} {:<10} {:<10} {:<20} {:<12} {:<12}",
            stats.cmpid,
            stats.context,
            stats.order,
            pattern_str,
            stats.stage1_attempts,
            stats.stage2_attempts
        )?;
    }

    writeln!(file)?;
    writeln!(file, "CondStmt Summary:")?;
    let total_condstmts = condstmt_stats_map.len();
    let total_stage1: usize = condstmt_stats_map.values().map(|s| s.stage1_attempts).sum();
    let total_stage2: usize = condstmt_stats_map.values().map(|s| s.stage2_attempts).sum();

    writeln!(file, "  Total CondStmts: {}", total_condstmts)?;
    writeln!(file, "  Total Stage1 Attempts: {}", total_stage1)?;
    writeln!(file, "  Total Stage2 Attempts: {}", total_stage2)?;

    info!("[LabelPattern] Saved reusing statistics to {:?}", path);
    Ok(())
}