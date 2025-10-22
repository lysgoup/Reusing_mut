use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use lazy_static::lazy_static;
use angora_common::tag::TagSeg;
use crate::cond_stmt::CondStmt;
use std::fs::File;
use std::io::{self, Write};
use std::path::Path;
use serde_derive::{Serialize, Deserialize};

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
}

lazy_static! {
    pub static ref LABEL_PATTERN_MAP: Mutex<HashMap<LabelPattern, Vec<CondRecord>>> =
      Mutex::new(HashMap::new());

    static ref ADDED_COND_IDS: Mutex<HashSet<(u32, u32, u32, LabelPattern)>> =
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

pub fn add_cond_to_pattern_map(cond: &CondStmt) {
  if (cond.base.lb1 > 0) != (cond.base.lb2 > 0) {
      if cond.offsets.is_empty() {
          return;
      }

      let pattern = extract_pattern_merged(&cond.offsets);
      let cond_id = (cond.base.cmpid, cond.base.order >> 16, cond.base.condition, pattern.clone());

      let mut added_ids = ADDED_COND_IDS.lock().unwrap();
       if added_ids.contains(&cond_id) {
           info!("[LabelPattern] Skipped duplicate: cmpid={}, order_high={}, condition={}",
                 cond.base.cmpid, cond.base.order >> 16, cond.base.condition);
           return;
       }

       added_ids.insert(cond_id);

      let pattern = extract_pattern_merged(&cond.offsets);
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
          offsets: cond.offsets.clone(),
      };

      let mut map = LABEL_PATTERN_MAP.lock().unwrap();
      map.entry(pattern.clone()).or_insert_with(Vec::new).push(record.clone());

      let original_pattern = extract_pattern(&cond.offsets);
      let merged_pattern = pattern.clone();

      // info!("[LabelPattern] Added: pattern={:?} (original: {:?}), cmpid={}, order={} (high={}), context={}, op={:#x}, lb1={}, lb2={}, condition={}, belong={}, arg1={}, arg2={}", merged_pattern, original_pattern, record.cmpid, record.order, record.order >> 16, record.context, record.op, record.lb1, record.lb2, record.condition, record.belong, record.arg1, record.arg2);
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
  info!("[LabelPattern] Total patterns: {}, Total records: {}", num_patterns, num_records);
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

        // writeln!(file, "        Offsets: {:?}", record.offsets)?;
      }
      writeln!(file)?;
  }

  info!("[LabelPattern] Saved to {:?}", path);
  Ok(())
}
