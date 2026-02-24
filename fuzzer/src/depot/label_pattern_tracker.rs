use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use lazy_static::lazy_static;
use angora_common::tag::TagSeg;
use crate::cond_stmt::CondStmt;
use crate::mut_input::offsets::merge_offsets;
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

lazy_static! {
    pub static ref LABEL_PATTERN_MAP: Mutex<HashMap<LabelPattern, Vec<CondRecord>>> =
      Mutex::new(HashMap::new());
}

pub fn merge_continuous_segments(offsets: &Vec<TagSeg>) -> Vec<TagSeg> {
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

fn add_single_record(
  pattern: &LabelPattern,
  offsets: &Vec<TagSeg>,
  critical_values: &Vec<Vec<u8>>,
  cond: &CondStmt,
) {
  let mut map = match LABEL_PATTERN_MAP.lock() {
    Ok(guard) => guard,
    Err(poisoned) => {
      error!("❌ CRITICAL: LABEL_PATTERN_MAP poisoned in add_single_record!");
      error!("This means a thread panicked while holding the lock.");
      error!("Pattern: {:?}, cond_cmpid: {}", pattern, cond.base.cmpid);
      return;
    }
  };

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
      offsets: offsets.clone(),
      critical_values: critical_values.clone(),
  };

  map.entry(pattern.clone()).or_insert_with(Vec::new).push(record);
}

pub fn add_cond_to_pattern_map(cond: &CondStmt, depot: &Depot) {
  if cond.offsets.is_empty() {
      return;
  }

  // offsets_opt가 존재하면 offsets과 합쳐서 새로운 offsets 생성
  let combined_offsets = merge_offsets(&cond.offsets, &cond.offsets_opt);

  // 병합된 세그먼트 추출
  let merged_offsets = merge_continuous_segments(&combined_offsets);
  let pattern = extract_pattern_merged(&combined_offsets);
  let input_buf = depot.get_input_buf(cond.base.belong as usize);
  let critical_values = extract_value_from_label(&combined_offsets, &input_buf);

  // 1. 전체 패턴 레코드 생성
  add_single_record(
      &pattern,
      &combined_offsets,
      &critical_values,
      cond,
  );

  // 2. 각 세그먼트별 레코드 생성
  for i in 0..merged_offsets.len() {
      let single_segment = vec![merged_offsets[i]];
      let single_pattern = vec![merged_offsets[i].end - merged_offsets[i].begin];
      let single_critical_values = vec![critical_values[i].clone()];

      add_single_record(
          &single_pattern,
          &single_segment,
          &single_critical_values,
          cond,
      );
  }
}

pub fn get_stats() -> (usize, usize) {
  let map = match LABEL_PATTERN_MAP.lock() {
    Ok(guard) => guard,
    Err(poisoned) => {
      error!("❌ CRITICAL: LABEL_PATTERN_MAP poisoned in get_stats!");
      poisoned.into_inner()
    }
  };
  let num_patterns = map.len();
  let num_records: usize = map.values().map(|v| v.len()).sum();
  (num_patterns, num_records)
}

pub fn print_stats() {
  let (num_patterns, num_records) = get_stats();
  // info!("[LabelPattern] Total patterns: {}, Total records: {}", num_patterns, num_records);
}

pub fn save_to_text(path: &Path) -> io::Result<()> {
  let map = match LABEL_PATTERN_MAP.lock() {
    Ok(guard) => guard,
    Err(poisoned) => {
      error!("❌ CRITICAL: LABEL_PATTERN_MAP poisoned in save_to_text!");
      return Ok(());
    }
  };
  let mut file = File::create(path)?;

  writeln!(file, "# Angora Label Pattern Map")?;
  writeln!(file, "# Generated at: {}", chrono::Local::now())?;
  writeln!(file, "# Total patterns: {}", map.len())?;
  writeln!(file, "# Total records: {}", map.values().map(|v| v.len()).sum::<usize>())?;
  writeln!(file)?;

  let mut sorted_patterns: Vec<_> = map.iter().collect();
  sorted_patterns.sort_by_key(|(pattern, _)| (*pattern).clone());

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
    let map = match LABEL_PATTERN_MAP.lock() {
      Ok(guard) => guard,
      Err(poisoned) => {
        error!("❌ CRITICAL: LABEL_PATTERN_MAP poisoned in get_next_records!");
        poisoned.into_inner()
      }
    };
    let records = map.get(pattern)?;

    let total = records.len();
    let mut start = cond.reusing_full_index;

    // Safety check: reusing_full_index가 total을 초과하지 않도록 제한
    if start >= total {
        return None;
    }

    let end = (start + iterations).min(total);

    // Safety: end가 start보다 작거나 같은 경우 방지
    if end <= start {
        return None;
    }

    cond.reusing_full_index = end;

    records[start..end].to_vec()
  };

  Some(selected)
}