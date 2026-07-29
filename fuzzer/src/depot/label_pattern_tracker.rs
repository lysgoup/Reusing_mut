use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use lazy_static::lazy_static;
use angora_common::{defs, tag::TagSeg};
use crate::{cond_stmt::CondStmt, mut_input};
use std::fs::File;
use std::io::{self, Write};
use std::path::Path;
use serde_derive::{Serialize, Deserialize};

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

    // magic-byte comparisons (cond.is_magic_byte) are pooled separately from
    // LABEL_PATTERN_MAP: pattern (tainted-side byte length) ->
    // (magic constant, taint value at first coverage) pairs.
    pub static ref MAGIC_BYTE_MAP: Mutex<HashMap<LabelPattern, HashSet<(Vec<u8>, Vec<u8>)>>> =
      Mutex::new(HashMap::new());
}

// The magic (constant) side of cond.variables. For FN_OP, cond.variables is
// [magic_bytes, tainted_bytes] concatenated (see fparser.rs / cmpfn.rs's
// FnFuzz, which splits it the same way for its diff-adjustment insertion);
// the magic prefix's length == cond.base.size (track.rs sets size to the
// OTHER/untainted operand's length). For plain int compares, cond.variables
// already IS just the magic bytes.
fn magic_value(cond: &CondStmt) -> &[u8] {
    if cond.base.op == defs::COND_FN_OP {
        let magic_len = (cond.base.size as usize).min(cond.variables.len());
        &cond.variables[..magic_len]
    } else {
        &cond.variables
    }
}

// Confirm the tainted operand's runtime value is a direct, untransformed copy
// of the input bytes at cond.offsets before trusting the (magic, tainted)
// pair as reusable (mirrors AFL++ cmplog's buf==pattern check before it
// commits to a direct patch).
//
// NOTE: for FN_OP this only verifies the VALUE; it does not fix the separate,
// still-open issue that track.rs's fn-compare hook collapses genuine dual-taint
// calls (memcmp(tainted_a, tainted_b, n)) into an apparent single label before
// this cond is even classified as magic-byte.
fn is_untransformed(cond: &CondStmt, actual_bytes: &[u8]) -> bool {
    if cond.base.op == defs::COND_FN_OP {
        let magic_len = magic_value(cond).len();
        return match cond.variables.get(magic_len..) {
            Some(tainted_captured) => tainted_captured == actual_bytes,
            None => true, // variables too short to split, can't verify -> don't block storage
        };
    }

    let tainted_arg = if cond.base.lb1 > 0 {
        cond.base.arg1
    } else {
        cond.base.arg2
    };

    match mut_input::read_as_ule(actual_bytes, cond.base.size as usize) {
        Some(actual_val) => actual_val == tainted_arg,
        None => true, // unsupported width, can't verify -> don't block storage
    }
}

fn add_magic_byte_record(cond: &CondStmt, buf: &Vec<u8>) {
    if cond.offsets.is_empty() || cond.variables.is_empty() {
        return;
    }

    let actual_bytes: Vec<u8> = extract_value_from_label(&cond.offsets, buf)
        .into_iter()
        .flatten()
        .collect();

    if !is_untransformed(cond, &actual_bytes) {
        return;
    }

    let pattern = extract_pattern_merged(&cond.offsets);
    let magic = magic_value(cond).to_vec();
    let mut map = MAGIC_BYTE_MAP.lock().unwrap();
    map.entry(pattern).or_insert_with(HashSet::new).insert((magic, actual_bytes));
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
  buf: &Vec<u8>,
  operand_num: u8,
) {
  if offsets.is_empty() {
      return;
  }

  // 병합된 세그먼트 추출
  let merged_offsets = merge_continuous_segments(offsets);
  let pattern = extract_pattern_merged(offsets);
  let critical_values = extract_value_from_label(offsets, buf);

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

fn add_single_label_record(cond: &CondStmt, buf: &Vec<u8>) {
    create_record_for_offsets(&cond.offsets, cond, buf, 0);
}

fn add_dual_label_records(cond: &CondStmt, buf: &Vec<u8>) {
    if cond.offsets_opt.is_empty() {
        return;
    }

    create_record_for_offsets(&cond.offsets, cond, buf, 1);
    create_record_for_offsets(&cond.offsets_opt, cond, buf, 2);
}

pub fn add_cond_to_pattern_map(cond: &CondStmt, buf: &Vec<u8>) {
  if cond.is_magic_byte {
      add_magic_byte_record(cond, buf);
      return;
  }

  if cond.base.lb1 > 0 && cond.base.lb2 == 0 {
      add_single_label_record(cond, buf);
  }
  else if cond.base.lb1 == 0 && cond.base.lb2 > 0 {
      add_single_label_record(cond, buf);
  }
  else if cond.base.lb1 > 0 && cond.base.lb2 > 0 {
      add_dual_label_records(cond, buf);
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

pub fn save_magic_bytes_to_text(path: &Path) -> io::Result<()> {
  let map = MAGIC_BYTE_MAP.lock().unwrap();
  let mut file = File::create(path)?;

  writeln!(file, "# Angora Magic Byte Map")?;
  writeln!(file, "# Generated at: {}", chrono::Local::now())?;
  writeln!(file, "# Total patterns: {}", map.len())?;
  writeln!(file, "# Total records: {}", map.values().map(|v| v.len()).sum::<usize>())?;
  writeln!(file)?;

  let mut sorted_patterns: Vec<_> = map.iter().collect();
  sorted_patterns.sort_by_key(|(pattern, _)| pattern.clone());

  for (pattern, records) in sorted_patterns {
      writeln!(file, "Pattern: {:?} (size: {})", pattern, pattern.iter().sum::<u32>())?;
      writeln!(file, "  Records: {}", records.len())?;

      for (magic, tainted_baseline) in records.iter() {
        writeln!(file, "        Magic: {:?}", magic)?;
        writeln!(file, "        Taint baseline: {:?}", tainted_baseline)?;
      }
      writeln!(file)?;
  }

  info!("[MagicByte] Saved to {:?}", path);
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
  buf: &Vec<u8>,
  mutated_offsets: &HashSet<u32>
) {
  // If mutated_offsets is empty, add without filtering (for initial seeds or non-mutation cases)
  if mutated_offsets.is_empty() {
    debug!("[LabelPattern] mutated_offsets is empty, adding without filter");
    add_cond_to_pattern_map(cond, buf);
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
  add_cond_to_pattern_map(cond, buf);
}