use std::collections::HashMap;
use std::sync::RwLock;
use angora_common::tag::TagSeg;
use crate::cond_stmt::CondStmt;
use std::fs::File;
use std::io::{self, Write};
use std::path::Path;
use serde_derive::{Serialize, Deserialize};

pub type ReusePattern = Vec<u32>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReuseEntry {
    pub cmpid: u32,
    pub context: u32,
    pub condition: u32,
    pub belong: u32,
    pub offsets: Vec<TagSeg>,
    pub bytes: Vec<u8>,
}

impl ReuseEntry {
    pub fn segment_values(&self) -> Vec<&[u8]> {
        let mut result = Vec::with_capacity(self.offsets.len());
        let mut cursor = 0;
        for seg in &self.offsets {
            let len = (seg.end - seg.begin) as usize;
            result.push(&self.bytes[cursor..cursor + len]);
            cursor += len;
        }
        result
    }
}

pub struct ReusePool {
    pool: RwLock<HashMap<ReusePattern, Vec<ReuseEntry>>>,
}

impl ReusePool {
    pub fn new() -> Self {
        Self {
            pool: RwLock::new(HashMap::new()),
        }
    }

    fn merge_segments(offsets: &[TagSeg]) -> Vec<TagSeg> {
        if offsets.is_empty() {
            return vec![];
        }

        let mut sorted = offsets.to_vec();
        sorted.sort_by_key(|seg| seg.begin);

        let mut merged = Vec::new();
        let mut current = sorted[0];

        for &next in &sorted[1..] {
            if current.end >= next.begin {
                current.end = current.end.max(next.end);
            } else {
                merged.push(current);
                current = next;
            }
        }

        merged.push(current);
        merged
    }

    fn read_segment_bytes(merged: &[TagSeg], input_buf: &[u8]) -> Vec<u8> {
        let total: usize = merged.iter().map(|s| (s.end - s.begin) as usize).sum();
        let mut bytes = Vec::with_capacity(total);
        for seg in merged {
            let begin = seg.begin as usize;
            let end = seg.end as usize;
            if end <= input_buf.len() {
                bytes.extend_from_slice(&input_buf[begin..end]);
            } else if begin < input_buf.len() {
                bytes.extend_from_slice(&input_buf[begin..]);
                bytes.resize(bytes.len() + (end - input_buf.len()), 0);
            } else {
                bytes.resize(bytes.len() + (end - begin), 0);
            }
        }
        bytes
    }

    fn insert(&self, pattern: ReusePattern, entry: ReuseEntry) {
        let mut pool = self.pool.write().unwrap();
        let entries = pool.entry(pattern).or_insert_with(Vec::new);
        if !entries.iter().any(|e| e.bytes == entry.bytes) {
            entries.push(entry);
        }
    }

    fn add_from_offsets(&self, offsets: &[TagSeg], cond: &CondStmt, input_buf: &[u8]) {
        let merged = Self::merge_segments(offsets);
        let pattern: ReusePattern = merged.iter().map(|s| s.end - s.begin).collect();
        let bytes = Self::read_segment_bytes(&merged, input_buf);

        if merged.len() > 1 {
            for &seg in &merged {
                let bytes = Self::read_segment_bytes(&[seg], input_buf);
                self.insert(vec![seg.end - seg.begin], ReuseEntry {
                    cmpid: cond.base.cmpid,
                    context: cond.base.context,
                    condition: cond.base.condition,
                    belong: cond.base.belong,
                    offsets: vec![seg],
                    bytes,
                });
            }
        }

        self.insert(pattern, ReuseEntry {
            cmpid: cond.base.cmpid,
            context: cond.base.context,
            condition: cond.base.condition,
            belong: cond.base.belong,
            offsets: merged,
            bytes,
        });
    }

    pub fn collect_reuse_entries(&self, cond: &CondStmt, input_buf: &[u8]) {
        if cond.offsets.is_empty() {
            return;
        }
        // offsets 한번
        self.add_from_offsets(&cond.offsets, cond, input_buf);
        if !cond.offsets_opt.is_empty() {
            //offsets_opt 한번
            self.add_from_offsets(&cond.offsets_opt, cond, input_buf);
            // 둘이 합쳐서 한번
            let combined: Vec<_> = cond.offsets.iter().chain(cond.offsets_opt.iter()).cloned().collect();
            self.add_from_offsets(&combined, cond, input_buf);
        }
    }

    pub fn get_entries_from(
        &self,
        pattern: &ReusePattern,
        start: usize,
        count: usize,
    ) -> Option<(Vec<ReuseEntry>, usize)> {
        let pool = self.pool.read().unwrap();
        let entries = pool.get(pattern)?;
        let total = entries.len();
        if start >= total {
            return None;
        }
        let end = (start + count).min(total);
        Some((entries[start..end].to_vec(), end))
    }

    pub fn record_count(&self, pattern: &ReusePattern) -> usize {
        let pool = self.pool.read().unwrap();
        pool.get(pattern).map(|v| v.len()).unwrap_or(0)
    }

    pub fn get_single_segment_values(&self, segment_size: u32) -> Vec<Vec<u8>> {
        let pool = self.pool.read().unwrap();
        pool.get(&vec![segment_size])
            .map(|entries| entries.iter().map(|e| e.bytes.clone()).collect())
            .unwrap_or_default()
    }

    pub fn stats(&self) -> (usize, usize) {
        let pool = self.pool.read().unwrap();
        let num_patterns = pool.len();
        let num_entries = pool.values().map(|v| v.len()).sum();
        (num_patterns, num_entries)
    }

    pub fn save_to_text(&self, path: &Path) -> io::Result<()> {
        let pool = self.pool.read().unwrap();
        let mut file = File::create(path)?;

        writeln!(file, "# Angora Reuse Pool")?;
        writeln!(file, "# Generated at: {}", chrono::Local::now())?;
        writeln!(file, "# Total patterns: {}", pool.len())?;
        writeln!(file, "# Total entries: {}", pool.values().map(|v| v.len()).sum::<usize>())?;
        writeln!(file)?;

        let mut sorted: Vec<_> = pool.iter().collect();
        sorted.sort_by_key(|(k, _)| k.clone());

        for (pattern, entries) in sorted {
            writeln!(file, "Pattern: {:?} (size: {})", pattern, pattern.iter().sum::<u32>())?;
            writeln!(file, "  Entries: {}", entries.len())?;
            for entry in entries {
                writeln!(file, "    Cmpid: {}", entry.cmpid)?;
                writeln!(file, "    Context: {}", entry.context)?;
                writeln!(file, "    Condition: {}", entry.condition)?;
                writeln!(file, "    Belong: {}", entry.belong)?;
                writeln!(file, "    Offsets: {:?}", entry.offsets)?;
                writeln!(file, "    Bytes: {:?}", entry.bytes)?;
            }
            writeln!(file)?;
        }

        info!("[ReusePool] Saved to {:?}", path);
        Ok(())
    }
}

pub fn extract_pattern_merged(offsets: &[TagSeg]) -> ReusePattern {
    ReusePool::merge_segments(offsets).iter().map(|s| s.end - s.begin).collect()
}
