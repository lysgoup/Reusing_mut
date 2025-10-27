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
    pub order: u32,
    pub context: u32,
    pub op: u32,
    pub lb1: u32,
    pub lb2: u32,
    pub condition: u32,
    pub belong: u32,
    pub arg1: u64,
    pub arg2: u64,
    pub offsets: Vec<TagSeg>,
    pub critical_values: Vec<Vec<u8>>,
}

lazy_static! {
    pub static ref LABEL_PATTERN_MAP: Mutex<HashMap<LabelPattern, Vec<CondRecord>>> =
      Mutex::new(HashMap::new());

    static ref ADDED_COND_IDS: Mutex<HashSet<(u32, u32, u32, LabelPattern, u8)>> =
      Mutex::new(HashSet::new());
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

    let pattern = extract_pattern_merged(offsets);
    let cond_id = (
        cond.base.cmpid,
        cond.base.order >> 16,
        cond.base.condition,
        pattern.clone(),
        operand_num,
    );

    let mut added_ids = ADDED_COND_IDS.lock().unwrap();
    if added_ids.contains(&cond_id) {
        return;
    }

    added_ids.insert(cond_id);
    drop(added_ids);

    let belong_id = cond.base.belong as usize;
    let input_buf = depot.get_input_buf(belong_id);
    let critical_values = extract_value_from_label(offsets, &input_buf);

    let mut map = LABEL_PATTERN_MAP.lock().unwrap();
    
    //value가 존재하면 스킵
    if let Some(existing_records) = map.get(&pattern) {
      for existing in existing_records.iter() {
          if existing.critical_values == critical_values {
              // info!("[LabelPattern] Skipped duplicate critical_value: pattern={:?}, values={:?}", pattern, critical_value);
              return;
          }
      }
    }

    let record = CondRecord {
      cmpid: cond.base.cmpid,
      order: cond.base.order,
      context: cond.base.context,
      op: cond.base.op,
      lb1: cond.base.lb1,
      lb2: cond.base.lb2,
      condition: cond.base.condition,
      belong: cond.base.belong,
      arg1: cond.base.arg1,
      arg2: cond.base.arg2,
      offsets: offsets.clone(),
      critical_values,
  };

    map.entry(pattern).or_insert_with(Vec::new).push(record);
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
        writeln!(file, "    [{}] cmpid={}, order={}, context={}, op={:#x}, lb1={}, lb2={}, condition={}, belong={}, arg1={}, arg2={}",
         i, record.cmpid, record.order, record.context, record.op, record.lb1, record.lb2, record.condition, record.belong, record.arg1, record.arg2)?;

        writeln!(file, "        Offsets: {:?}", record.offsets)?;
        writeln!(file, "        Critical values: {:?}", record.critical_values)?;
      }
      writeln!(file)?;
  }

  info!("[LabelPattern] Saved to {:?}", path);
  Ok(())
}
