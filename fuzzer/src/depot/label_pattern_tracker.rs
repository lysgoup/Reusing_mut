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

#[derive(Debug, Default, Clone)]
pub struct LabelPatternPool {
    // O(1) dedup by critical_values (Vec<Vec<u8>> is Hash+Eq since Vec<u8>
    // is) -- replaces the old design's O(n) linear scan through every
    // existing record on every single insert (see create_single_record).
    seen: HashSet<Vec<Vec<u8>>>,
    // insertion order, so get_next_records can slice forward from
    // cond.reusing_record_index instead of re-scanning from the start --
    // same reasoning as MagicBytePool.order (see label_pattern_tracker.rs).
    pub records: Vec<CondRecord>,
}

lazy_static! {
    pub static ref LABEL_PATTERN_MAP: Mutex<HashMap<LabelPattern, LabelPatternPool>> =
      Mutex::new(HashMap::new());

    // magic-byte comparisons (cond.is_magic_byte) are pooled separately from
    // LABEL_PATTERN_MAP: pattern (tainted-side byte length) -> a pool of
    // distinct magic (constant-side) values and distinct taint (tainted-side,
    // at first coverage) values, each deduplicated independently.
    pub static ref MAGIC_BYTE_MAP: Mutex<HashMap<LabelPattern, MagicBytePool>> =
      Mutex::new(HashMap::new());

    // Quarantine for magic-byte cmpids that turned out to be loop counters /
    // accumulated positions, not real constants (untainted != compile-time
    // constant is an is_magic_byte_cmp() blind spot -- see
    // flag_loop_counters_in_batch). Kept for inspection rather than
    // discarded, same spirit as MAGIC_BYTE_MAP itself.
    //
    // Keyed by cmpid (not LabelPattern like MAGIC_BYTE_MAP) -- this map IS
    // the "known loop-counter cmpid" cache: insert_magic_byte_value checks
    // membership via contains_key(&cmpid) directly, so there's no separate
    // HashSet<u32> to keep in sync with it. Grouping loop-counter junk by
    // cmpid is also more useful for inspection than by byte-length, since
    // length mixes together unrelated cmpids that just happen to match.
    pub static ref LOOP_COUNTER_MAP: Mutex<HashMap<u32, MagicBytePool>> =
      Mutex::new(HashMap::new());
}

// A cmpid's observed distinct integer values are treated as a loop counter
// (or similar accumulated-position variable) if there are enough samples and
// they're packed too densely to be a set of independent, unrelated
// constants. density = span / count, where span = max-min+1 -- a loop
// counter's values cluster near 1 (mostly consecutive integers, since
// that's literally what a counter produces, modulo sampling gaps from
// MAX_COND_ORDER capping how many iterations get recorded per input);
// genuine constants/table values are scattered far more sparsely. Validated
// empirically across jq/tiffsplit/infotocap/imginfo/exiv2: every confirmed
// loop-counter cmpid had density <= 1.30, every confirmed genuine
// constant/table cmpid had density >= 2.12 (94 samples, no overlap).
const LOOP_COUNTER_MIN_SAMPLES: usize = 4;
const LOOP_COUNTER_MAX_DENSITY: f64 = 1.5;

// logging only -- not part of dedup identity (see MagicBytePool.values).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ValueOrigin {
    Magic,
    Tainted,
}

#[derive(Debug, Default, Clone)]
pub struct MagicBytePool {
    // both the magic (constant) side and the tainted side go into one pool,
    // keyed only by pattern (they're the same byte-length now, see
    // magic_value_if_untransformed). Deduplicated purely on the byte value
    // (the HashMap key); (origin, cmpid) is logging/traceability metadata only
    // (source cmpid -> file/line via cmpid_track.txt) -- first observation
    // wins, not an exhaustive history.
    pub values: HashMap<Vec<u8>, (ValueOrigin, u32)>,
    // insertion order of the same distinct values as `values` (pushed once,
    // exactly when a value is newly inserted into `values`) -- lets reusing
    // mutation slice forward from a stored index (cond.reusing_record_index,
    // same field LABEL_PATTERN_MAP's get_next_records uses) instead of
    // re-collecting the whole pool and re-trying the same HashMap-iteration-
    // order prefix every call. See apply_magic_byte_pool in search/reusing.rs.
    pub order: Vec<Vec<u8>>,
}

// Verify the comparison is untransformed AND derive the magic (constant) value
// at the SAME byte-length as `actual_bytes` (the tainted side's real length,
// per cond.offsets/pattern) -- not cond.base.size, the compiled comparison's
// bit-width. Those two lengths differ whenever a narrow value (e.g. a single
// tainted byte) gets implicitly widened before the compare (`char c; c ==
// '\n'` compiles to an i32 compare in C) -- extremely common, and previously
// caused magic/tainted to be stored at mismatched lengths, and caused
// verification to silently no-op (see git history for the old size-based
// version) whenever actual_bytes was shorter than cond.base.size.
//
// Returns None if the comparison isn't a direct, untransformed copy of
// actual_bytes under EITHER byte order (mirrors AFL++ cmplog's buf==pattern
// check before it commits to a direct patch), or if a same-length magic
// value can't be produced.
//
// NOTE: for FN_OP this only verifies the VALUE; it does not fix the separate,
// still-open issue that track.rs's fn-compare hook collapses genuine dual-taint
// calls (memcmp(tainted_a, tainted_b, n)) into an apparent single label before
// this cond is even classified as magic-byte.
fn magic_value_if_untransformed(cond: &CondStmt, actual_bytes: &[u8]) -> Option<Vec<u8>> {
    let len = actual_bytes.len();
    if len == 0 {
        return None;
    }

    if cond.base.op == defs::COND_FN_OP {
        // cond.variables is [magic_bytes, tainted_bytes]; the magic prefix's
        // natural length is cond.base.size (track.rs sets size to the
        // OTHER/untainted operand's length).
        let natural_magic_len = (cond.base.size as usize).min(cond.variables.len());
        let tainted_captured = cond.variables.get(natural_magic_len..)?;
        if tainted_captured != actual_bytes || len > natural_magic_len {
            return None;
        }
        Some(cond.variables[..len].to_vec())
    } else {
        let (magic_arg, tainted_arg) = if cond.base.lb1 > 0 {
            (cond.base.arg2, cond.base.arg1)
        } else {
            (cond.base.arg1, cond.base.arg2)
        };

        // actual_bytes is raw, verbatim input bytes (via cond.offsets), so it's
        // always in true buffer order. tainted_arg is the operand's runtime
        // integer value -- but source code can assemble a multi-byte value
        // either via a native typed load (little-endian on x86) or manual
        // bit-shifts (`(buf[0]<<8)|buf[1]`, big-endian; e.g. jasper's PGX/RAS
        // magic checks). Nothing in the track data says which, so interpret
        // actual_bytes both ways and accept whichever matches -- then encode
        // magic_arg with that SAME byte order, so the derived magic value is
        // actually insertable (matches git history: assuming little-endian
        // unconditionally silently mismatched real file byte order here).
        if mut_input::read_as_ule(actual_bytes) == Some(tainted_arg) {
            let magic = mut_input::write_as_ule(magic_arg, len);
            if magic.len() != len {
                return None; // unsupported width (only 1/2/4/8)
            }
            Some(magic)
        } else if mut_input::read_as_ube(actual_bytes) == Some(tainted_arg) {
            let magic = mut_input::write_as_ube(magic_arg, len);
            if magic.len() != len {
                return None;
            }
            Some(magic)
        } else {
            None
        }
    }
}

// Inserts into both `values` (dedup + metadata) and `order` (insertion-order
// list for index-based slicing), but only pushes to `order` when this value
// is genuinely new to the pool -- mirrors HashMap::entry().or_insert()'s
// "first observation wins" semantics without duplicating `order` entries for
// values that are already present.
fn pool_insert(pool: &mut MagicBytePool, value: Vec<u8>, origin: ValueOrigin, cmpid: u32) {
    use std::collections::hash_map::Entry;
    if let Entry::Vacant(e) = pool.values.entry(value.clone()) {
        e.insert((origin, cmpid));
        pool.order.push(value);
    }
}

fn insert_magic_byte_value(pattern: LabelPattern, magic: Vec<u8>, tainted: Vec<u8>, cmpid: u32) {
    // known loop-counter cmpids skip MAGIC_BYTE_MAP entirely -- flagged by
    // flag_loop_counters_in_batch before this ever runs. LOOP_COUNTER_MAP's
    // own keys ARE the "known loop-counter cmpid" set, so this is a plain
    // O(1) membership check, no separate cache to keep in sync.
    let mut loop_map = LOOP_COUNTER_MAP.lock().unwrap();
    if let Some(pool) = loop_map.get_mut(&cmpid) {
        // the "magic" side here is really just the counter's own value at
        // whatever iteration this observation came from, not a real constant
        // -- not useful to keep. the tainted side is a real input byte
        // (e.g. hdr->width), still meaningful, so that one's kept.
        pool_insert(pool, tainted, ValueOrigin::Tainted, cmpid);
        return;
    }
    drop(loop_map);

    let mut map = MAGIC_BYTE_MAP.lock().unwrap();
    let pool = map.entry(pattern).or_insert_with(MagicBytePool::default);
    pool_insert(pool, magic, ValueOrigin::Magic, cmpid);
    pool_insert(pool, tainted, ValueOrigin::Tainted, cmpid);
}

fn density_flags_loop_counter(values: &HashSet<u64>) -> bool {
    if values.len() < LOOP_COUNTER_MIN_SAMPLES {
        return false;
    }
    let min = *values.iter().min().unwrap();
    let max = *values.iter().max().unwrap();
    let span = (max - min + 1) as f64;
    let density = span / values.len() as f64;
    density <= LOOP_COUNTER_MAX_DENSITY
}

// Flags loop-counter cmpids using only THIS ONE batch (one input's whole
// cond_stmts, i.e. one execution) -- no periodic full-pool re-scan needed.
// This works because a genuine loop re-executes the same cmpid multiple
// times WITHIN a single execution (see runtime/src/logger.rs::get_order,
// which pushes a new cond_list entry per repeat, capped at
// MAX_COND_ORDER=16) -- so a loop that iterates enough times already gives
// density_flags_loop_counter enough same-execution samples to decide. Loops
// that iterate too few times in EVERY single execution (or single-shot
// accumulated-position checks like `start == size`) never accumulate enough
// same-batch samples and won't get caught here -- accepted gap, not worth
// cross-execution bookkeeping to close for those.
//
// Must run BEFORE the main per-cond loop below: it only touches
// LOOP_COUNTER_MAP (creating empty entries for newly-flagged cmpids), so
// insert_magic_byte_value's contains_key(&cmpid) check sees them in time to
// route this same batch's values correctly.
fn flag_loop_counters_in_batch(conds: &Vec<CondStmt>) {
    let mut by_cmpid: HashMap<u32, HashSet<u64>> = HashMap::new();
    for cond in conds.iter() {
        // FN_OP has no simple integer arg (see magic_value_if_untransformed) --
        // the loop-counter blind spot only exists for the ICMP EQ/NE branch.
        if !cond.is_magic_byte || cond.base.op == defs::COND_FN_OP {
            continue;
        }
        // check the MAGIC (untainted) side's density -- that's the operand
        // is_magic_byte_cmp() is trusting to be a constant. The tainted side
        // is real input data and is EXPECTED to vary widely (e.g. every
        // distinct character a classifier loop happens to see) -- checking
        // that side instead would misfire on legitimate character/byte
        // classification comparisons whose real observed inputs happen to
        // cluster in a narrow range, not just genuine loop counters.
        let magic_arg = if cond.base.lb1 > 0 { cond.base.arg2 } else { cond.base.arg1 };
        by_cmpid.entry(cond.base.cmpid).or_insert_with(HashSet::new).insert(magic_arg);
    }

    let newly_flagged: Vec<u32> = by_cmpid
        .into_iter()
        .filter(|(_, vals)| density_flags_loop_counter(vals))
        .map(|(cmpid, _)| cmpid)
        .collect();

    if newly_flagged.is_empty() {
        return;
    }

    let mut loop_map = LOOP_COUNTER_MAP.lock().unwrap();
    for cmpid in newly_flagged {
        if loop_map.contains_key(&cmpid) {
            continue; // already flagged by an earlier batch, nothing to sweep
        }
        loop_map.insert(cmpid, MagicBytePool::default());

        // This cmpid just crossed the sample threshold for the first time.
        // Earlier batches may have each individually had too few samples of
        // it to trip this check, and so quietly went into MAGIC_BYTE_MAP --
        // sweep those out now too, same tainted-only policy as everywhere
        // else. One-time, per-cmpid, only on the rare batch that newly
        // flags something -- not a periodic full-pool scan.
        let mut main_map = MAGIC_BYTE_MAP.lock().unwrap();
        for pool in main_map.values_mut() {
            let mut keep = HashMap::new();
            for (v, meta) in pool.values.drain() {
                if meta.1 != cmpid {
                    keep.insert(v, meta);
                } else if meta.0 == ValueOrigin::Tainted {
                    let dest = loop_map.get_mut(&cmpid).unwrap();
                    pool_insert(dest, v, meta.0, meta.1);
                }
            }
            // order must track values 1:1 -- drop anything that just moved out.
            pool.order.retain(|v| keep.contains_key(v));
            pool.values = keep;
        }
        main_map.retain(|_, pool| !pool.values.is_empty());
    }
}

// Per-cond magic/tainted extraction, shared by the direct (>1 byte pattern)
// path and the 1-byte adjacency-merge path below.
fn extract_magic_and_tainted(cond: &CondStmt, buf: &Vec<u8>) -> Option<(Vec<u8>, Vec<u8>)> {
    if cond.offsets.is_empty() || cond.variables.is_empty() {
        return None;
    }
    let actual_bytes: Vec<u8> = extract_value_from_label(&cond.offsets, buf)
        .into_iter()
        .flatten()
        .collect();
    let magic = magic_value_if_untransformed(cond, &actual_bytes)?;
    Some((magic, actual_bytes))
}

// Handle every magic-byte cond from ONE input's whole cond_stmts batch.
//
// A single tainted byte often isn't compared all at once (memcmp of a whole
// magic string) but one byte at a time (`buf[0]=='P' && buf[1]=='N' && ...`),
// each compiling to its OWN 1-byte-pattern cond. Storing those in isolation is
// useless (a single byte's "magic pool" is mostly noise), so they get merged
// into one combined multi-byte record instead.
//
// The grouping itself (which 1-byte conds are adjacent: same
// cond.base.context, contiguous offsets) is decided once, right after taint
// tracking, in fparser.rs::group_adjacent_one_byte_magic_bytes -- every member
// cond carries the result in cond.magic_byte_group. That's required so the
// SAME grouping is still visible later, at reusing-mutation time, when a
// single member cond is pulled out of the depot queue on its own and its
// siblings from this batch are no longer around. Here we just use that
// pre-computed grouping to build the combined record; a 1-byte cond with no
// tagged group (no adjacent same-context sibling in this input) is dropped,
// matching prior behavior.
pub fn add_magic_byte_records(conds: &Vec<CondStmt>, buf: &Vec<u8>) {
    flag_loop_counters_in_batch(conds);

    let mut groups: HashMap<(u32, u32, u32), Vec<&CondStmt>> = HashMap::new();

    for cond in conds.iter() {
        if !cond.is_magic_byte {
            continue;
        }

        if !cond.magic_byte_group.is_empty() {
            let span = cond.magic_byte_group[0];
            groups
                .entry((cond.base.context, span.begin, span.end))
                .or_insert_with(Vec::new)
                .push(cond);
            continue;
        }

        let pattern = extract_pattern_merged(&cond.offsets);
        if pattern.len() == 1 && pattern[0] == 1 {
            // isolated one-byte magic-byte cond, no adjacent sibling in this
            // input -- not useful on its own.
            continue;
        }

        if let Some((magic, tainted)) = extract_magic_and_tainted(cond, buf) {
            insert_magic_byte_value(pattern, magic, tainted, cond.base.cmpid);
        }
    }

    for members in groups.values_mut() {
        members.sort_by_key(|c| c.offsets[0].begin);

        // A run's members must all pass extract_magic_and_tainted's LE/BE
        // untransformed check to be combined -- but one failing member (a
        // genuinely transformed comparison) shouldn't sink the whole run.
        // Flush whatever passed so far as its own record (if long enough to
        // be worth it) and start a fresh run right after the failure, so the
        // group splits around it instead of being discarded wholesale.
        let mut run_magic: Vec<u8> = Vec::new();
        let mut run_tainted: Vec<u8> = Vec::new();
        let mut run_cmpid: u32 = 0;

        for cond in members.iter() {
            match extract_magic_and_tainted(cond, buf) {
                Some((m, t)) => {
                    if run_magic.is_empty() {
                        run_cmpid = cond.base.cmpid;
                    }
                    run_magic.extend_from_slice(&m);
                    run_tainted.extend_from_slice(&t);
                },
                None => {
                    if run_magic.len() >= 2 {
                        let pattern = vec![run_magic.len() as u32];
                        insert_magic_byte_value(pattern, run_magic.clone(), run_tainted.clone(), run_cmpid);
                    }
                    run_magic.clear();
                    run_tainted.clear();
                },
            }
        }
        if run_magic.len() >= 2 {
            let pattern = vec![run_magic.len() as u32];
            insert_magic_byte_value(pattern, run_magic, run_tainted, run_cmpid);
        }
    }
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
  let pool = map.entry(pattern.clone()).or_insert_with(LabelPatternPool::default);

  // 중복 체크 -- O(1), 더 이상 기존 레코드 전체를 선형탐색하지 않음
  if !pool.seen.insert(critical_values.clone()) {
      return;
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

  pool.records.push(record);
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
  // magic-byte conds are handled batch-wide by add_magic_byte_records()
  // (needs sibling conds from the same input for offset-adjacency merging).
  if cond.is_magic_byte {
      return;
  }

  if cond.base.lb1 > 0 && cond.base.lb2 > 0 {
      add_dual_label_records(cond, buf);
  }
  else if cond.base.lb1 > 0 || cond.base.lb2 > 0 {
      add_single_label_record(cond, buf);
  }
}

pub fn get_stats() -> (usize, usize) {
  let map = LABEL_PATTERN_MAP.lock().unwrap();
  let num_patterns = map.len();
  let num_records: usize = map.values().map(|p| p.records.len()).sum();
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
  writeln!(file, "# Total records: {}", map.values().map(|p| p.records.len()).sum::<usize>())?;
  writeln!(file)?;

  let mut sorted_patterns: Vec<_> = map.iter().collect();
  sorted_patterns.sort_by_key(|(pattern, _)| pattern.clone());

  for (pattern, pool) in sorted_patterns {
      writeln!(file, "Pattern: {:?} (size: {})", pattern, pattern.iter().sum::<u32>())?;
      writeln!(file, "  Records: {}", pool.records.len())?;

      for (i, record) in pool.records.iter().enumerate() {
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
  writeln!(file, "# Total values: {}", map.values().map(|p| p.values.len()).sum::<usize>())?;
  writeln!(file)?;

  let mut sorted_patterns: Vec<_> = map.iter().collect();
  sorted_patterns.sort_by_key(|(pattern, _)| pattern.clone());

  for (pattern, pool) in sorted_patterns {
      writeln!(file, "Pattern: {:?} (size: {})", pattern, pattern.iter().sum::<u32>())?;
      writeln!(file, "  Values ({}):", pool.values.len())?;
      for (value, (origin, cmpid)) in pool.values.iter() {
        writeln!(file, "        [{:?}] cmpid={} {:?}", origin, cmpid, value)?;
      }
      writeln!(file)?;
  }

  info!("[MagicByte] Saved to {:?}", path);
  Ok(())
}

pub fn save_loop_counter_map_to_text(path: &Path) -> io::Result<()> {
  let map = LOOP_COUNTER_MAP.lock().unwrap();
  let mut file = File::create(path)?;

  writeln!(file, "# Angora Loop Counter Quarantine")?;
  writeln!(file, "# cmpids whose magic-byte values turned out to be loop counters / accumulated")?;
  writeln!(file, "# positions, not real constants (see density_flags_loop_counter) -- kept here")?;
  writeln!(file, "# for inspection, excluded from MAGIC_BYTE_MAP / reusing mutation.")?;
  writeln!(file, "# Generated at: {}", chrono::Local::now())?;
  writeln!(file, "# Total cmpids: {}", map.len())?;
  writeln!(file, "# Total values: {}", map.values().map(|p| p.values.len()).sum::<usize>())?;
  writeln!(file)?;

  let mut sorted_cmpids: Vec<_> = map.iter().collect();
  sorted_cmpids.sort_by_key(|(cmpid, _)| **cmpid);

  for (cmpid, pool) in sorted_cmpids {
      writeln!(file, "Cmpid: {}", cmpid)?;
      writeln!(file, "  Values ({}):", pool.values.len())?;
      for (value, (origin, _)) in pool.values.iter() {
        writeln!(file, "        [{:?}] {:?}", origin, value)?;
      }
      writeln!(file)?;
  }

  info!("[LoopCounter] Saved to {:?}", path);
  Ok(())
}

pub fn get_next_records(
  cond: &mut CondStmt,
  pattern: &LabelPattern,
  iterations: usize
) -> Option<Vec<CondRecord>> {
  let selected = {
    let map = LABEL_PATTERN_MAP.lock().unwrap();
    let records = &map.get(pattern)?.records;

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