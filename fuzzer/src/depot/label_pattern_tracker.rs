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
    pub op: u32,
    pub lb1: u32,
    pub lb2: u32,
    pub condition: u32,
    pub belong: u32,
    pub offsets: Vec<TagSeg>,
}

lazy_static! {
    pub static ref LABEL_PATTERN_MAP: Mutex<HashMap<LabelPattern, Vec<CondRecord>>> =
      Mutex::new(HashMap::new());

    static ref ADDED_COND_IDS: Mutex<HashSet<(u32, u32)>> =
      Mutex::new(HashSet::new());
}

pub fn extract_pattern(offsets: &Vec<TagSeg>) -> LabelPattern {
  offsets.iter().map(|seg| seg.end - seg.begin).collect()
}

// 연속된 TagSeg를 합치는 함수
fn merge_continuous_segments(offsets: &Vec<TagSeg>) -> Vec<TagSeg> {
  if offsets.is_empty() {
      return vec![];
  }

  let mut merged = Vec::new();
  let mut current = offsets[0];

  for i in 1..offsets.len() {
      let next = offsets[i];

      // 현재 segment와 다음 segment가 연속되는지 확인
      if current.end == next.begin && current.sign == next.sign {
          // 연속되면 합치기
          current.end = next.end;
      } else {
          // 연속되지 않으면 현재 segment 저장하고 새로 시작
          merged.push(current);
          current = next;
      }
  }

  // 마지막 segment 추가
  merged.push(current);

  merged
}

// 합쳐진 offsets로부터 패턴 추출 (새 함수)
pub fn extract_pattern_merged(offsets: &Vec<TagSeg>) -> LabelPattern {
  let merged = merge_continuous_segments(offsets);
  merged.iter().map(|seg| seg.end - seg.begin).collect()
}

pub fn add_cond_to_pattern_map(cond: &CondStmt) {
  // lb1 XOR lb2: 둘 중 하나만 0이 아닌 경우
  if (cond.base.lb1 > 0) != (cond.base.lb2 > 0) {
      if cond.offsets.is_empty() {
          return;
      }

       // 중복 체크: (cmpid, order) 조합이 이미 있는지 확인
       let cond_id = (cond.base.cmpid, cond.base.order);

       let mut added_ids = ADDED_COND_IDS.lock().unwrap();
       if added_ids.contains(&cond_id) {
           // 이미 같은 cmpid+order가 추가됨 (context만 다름)
           info!("[LabelPattern] Skipped duplicate: cmpid={}, order={} (context differs)",
                 cond.base.cmpid, cond.base.order);
           return;
       }

       // 새로운 cmpid+order 조합 추가
       added_ids.insert(cond_id);

      let pattern = extract_pattern_merged(&cond.offsets);
      let record = CondRecord {
          cmpid: cond.base.cmpid,
          op: cond.base.op,
          lb1: cond.base.lb1,
          lb2: cond.base.lb2,
          condition: cond.base.condition,
          belong: cond.base.belong,
          offsets: cond.offsets.clone(),
      };

      let mut map = LABEL_PATTERN_MAP.lock().unwrap();
      map.entry(pattern.clone()).or_insert_with(Vec::new).push(record.clone());

      let original_pattern = extract_pattern(&cond.offsets);
      let merged_pattern = pattern.clone();

      info!("[LabelPattern] Added: pattern={:?} (original: {:?}), cmpid={}, op={:#x}, lb1={}, lb2={}, condition={}, belong={}",
            merged_pattern, original_pattern, record.cmpid, record.op, record.lb1, record.lb2, record.condition, record.belong);
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
      // 다음 segment가 바로 이어지는지 확인
      if offsets[i].end != offsets[i+1].begin {
          return false;  // 중간에 gap 있음
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

  // 패턴별로 정렬해서 출력
  let mut sorted_patterns: Vec<_> = map.iter().collect();
  sorted_patterns.sort_by_key(|(pattern, _)| pattern.clone());

  for (pattern, records) in sorted_patterns {
      writeln!(file, "Pattern: {:?} (size: {})", pattern, pattern.iter().sum::<u32>())?;
      writeln!(file, "  Records: {}", records.len())?;

      for (i, record) in records.iter().enumerate() {
        writeln!(file, "    [{}] cmpid={}, op={:#x}, lb1={}, lb2={}, condition={}, belong={}",
        i, record.cmpid, record.op, record.lb1, record.lb2, record.condition, record.belong)?;

        // offsets 상세 출력
        writeln!(file, "        Offsets: {:?}", record.offsets)?;

        // 연속성 체크
        let is_continuous = check_continuous(&record.offsets);
        writeln!(file, "        Continuous: {}", is_continuous)?;
      }
      writeln!(file)?;
  }

  info!("[LabelPattern] Saved to {:?}", path);
  Ok(())
}

