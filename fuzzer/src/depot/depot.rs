use super::*;
use crate::{cond_stmt::CondStmt, executor::StatusType};
use crate::depot::label_pattern_tracker;
use rand;
use std::{
    collections::{HashMap, HashSet},
    fs,
    io::prelude::*,
    mem,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    },
};
// https://crates.io/crates/priority-queue
use angora_common::{config, defs};
use priority_queue::PriorityQueue;

use super::queue_restorer::{load_restore_map, RestoreMap};

pub const NO_PARENT: usize = usize::MAX;

pub struct Depot {
    pub queue: Mutex<PriorityQueue<CondStmt, QPriority>>,
    pub num_inputs: AtomicUsize,
    pub num_hangs: AtomicUsize,
    pub num_crashes: AtomicUsize,
    pub dirs: DepotDir,
    pub parent_map: Mutex<HashMap<usize, usize>>,
    restore_map: Option<RestoreMap>,
    restore_total: AtomicUsize,
    restore_not_found: AtomicUsize,
}

impl Depot {
    pub fn new(in_dir: PathBuf, out_dir: &Path) -> Self {
        let csv_path = in_dir.join(defs::COND_QUEUE_FILE);
        let restore_map = if csv_path.exists() {
            let map = load_restore_map(&csv_path);
            if let Err(e) = fs::remove_file(&csv_path) {
                warn!("Failed to remove {:?} after loading: {:?}", csv_path, e);
            }
            Some(map)
        } else {
            None
        };

        Self {
            queue: Mutex::new(PriorityQueue::new()),
            num_inputs: AtomicUsize::new(0),
            num_hangs: AtomicUsize::new(0),
            num_crashes: AtomicUsize::new(0),
            dirs: DepotDir::new(in_dir, out_dir),
            parent_map: Mutex::new(HashMap::new()),
            restore_map,
            restore_total: AtomicUsize::new(0),
            restore_not_found: AtomicUsize::new(0),
        }
    }

    fn save_input(
        status: &StatusType,
        buf: &Vec<u8>,
        num: &AtomicUsize,
        cmpid: u32,
        dir: &Path,
    ) -> usize {
        let id = num.fetch_add(1, Ordering::Relaxed);
        trace!(
            "Find {} th new {:?} input by fuzzing {}.",
            id,
            status,
            cmpid
        );
        let new_path = get_file_name(dir, id);
        let mut f = fs::File::create(new_path.as_path()).expect("Could not save new input file.");
        f.write_all(buf)
            .expect("Could not write seed buffer to file.");
        f.flush().expect("Could not flush file I/O.");
        id
    }

    pub fn save(&self, status: StatusType, buf: &Vec<u8>, cmpid: u32, parent_id: usize) -> usize {
        let id = match status {
            StatusType::Normal => {
                Self::save_input(&status, buf, &self.num_inputs, cmpid, &self.dirs.inputs_dir)
            },
            StatusType::Timeout => {
                Self::save_input(&status, buf, &self.num_hangs, cmpid, &self.dirs.hangs_dir)
            },
            StatusType::Crash => Self::save_input(
                &status,
                buf,
                &self.num_crashes,
                cmpid,
                &self.dirs.crashes_dir,
            ),
            _ => return 0,
        };
        if status == StatusType::Normal {
            if let Ok(mut map) = self.parent_map.lock() {
                map.insert(id, parent_id);
            }
        }
        id
    }

    pub fn write_parent_map(&self, path: &Path) {
        let map = match self.parent_map.lock() {
            Ok(m) => m,
            Err(e) => {
                warn!("Failed to lock parent_map: {:?}", e);
                return;
            },
        };
        let mut file = match fs::File::create(path) {
            Ok(f) => f,
            Err(e) => {
                warn!("Failed to create parent map file: {:?}", e);
                return;
            },
        };
        let mut entries: Vec<(&usize, &usize)> = map.iter().collect();
        entries.sort_by_key(|&(id, _)| id);
        for (child, parent) in entries {
            let parent_str = if *parent == NO_PARENT {
                "none".to_string()
            } else {
                parent.to_string()
            };
            if let Err(e) = writeln!(file, "{} {}", child, parent_str) {
                warn!("Failed to write parent map entry: {:?}", e);
                return;
            }
        }
        info!("Parent map written to {:?}", path);
    }

    pub fn empty(&self) -> bool {
        self.num_inputs.load(Ordering::Relaxed) == 0
    }

    pub fn next_random(&self) -> usize {
        rand::random::<usize>() % self.num_inputs.load(Ordering::Relaxed)
    }

    pub fn get_input_buf(&self, id: usize) -> Vec<u8> {
        let path = get_file_name(&self.dirs.inputs_dir, id);
        read_from_file(&path)
    }

    pub fn get_entry(&self) -> Option<(CondStmt, QPriority)> {
        let mut q = match self.queue.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!("Mutex poisoned! Results may be incorrect. Continuing...");
                poisoned.into_inner()
            },
        };
        q.peek()
            .and_then(|x| Some((x.0.clone(), x.1.clone())))
            .and_then(|x| {
                if !x.1.is_done() {
                    let q_inc = x.1.inc(x.0.base.op);
                    q.change_priority(&(x.0), q_inc);
                }
                Some(x)
            })
    }

    pub fn add_entries(&self, conds: Vec<CondStmt>) {
        let mut q = match self.queue.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!("Mutex poisoned! Results may be incorrect. Continuing...");
                poisoned.into_inner()
            },
        };

        let mut restored = 0usize;
        let mut not_found = 0usize;

        for mut cond in conds {
            // DEBUG: Print lb1 and lb2 before adding to depot
            // if cond.base.lb1 > 0 || cond.base.lb2 > 0 {
            //     info!("[DEPOT] Adding CondStmt - cmpid: {}, ctx: {}, ord: {}, lb1: {}, lb2: {}, op: {:#x}, size: {}, arg1: {}, arg2: {}, offsets: {:?}, desirable: {}",
            //            cond.base.cmpid, cond.base.context, cond.base.order,
            //            cond.base.lb1, cond.base.lb2,
            //            cond.base.op, cond.base.size,
            //            cond.base.arg1, cond.base.arg2,
            //            cond.offsets, cond.is_desirable);
            // }

            if cond.is_desirable {
                if let Some(v) = q.get_mut(&cond) {
                    if !v.0.is_done() {
                        // If existed one and our new one has two different conditions,
                        // this indicate that it is explored.
                        if v.0.base.condition != cond.base.condition {
                            label_pattern_tracker::add_cond_to_pattern_map(&cond, self);
                            v.0.mark_as_done();
                            q.change_priority(&cond, QPriority::done());
                        } else {
                            // Existed, but the new one are better
                            // If the cond is faster than the older one, we prefer the faster,
                            if config::PREFER_FAST_COND && v.0.speed > cond.speed {
                                mem::swap(v.0, &mut cond);
                                let priority = QPriority::init(cond.base.op);
                                q.change_priority(&cond, priority);
                            }
                        }
                    }
                } else {
                    let priority = if !cond.base.is_afl() {
                        if let Some(ref rm) = self.restore_map {
                            if let Some(entry) = rm.get(&(cond.base.cmpid, cond.base.context, cond.base.order)) {
                                cond.state = entry.state.clone();
                                cond.fuzz_times = entry.fuzz_times;
                                if !entry.variables.is_empty() {
                                    cond.variables = entry.variables.clone();
                                }
                                restored += 1;
                                trace!(
                                    "[Restore] cmpid={} ctx={} ord={} state={:?} p={} fuzz_times={}",
                                    cond.base.cmpid, cond.base.context, cond.base.order,
                                    cond.state, entry.priority, entry.fuzz_times
                                );
                                QPriority::from_u16(entry.priority)
                            } else {
                                not_found += 1;
                                QPriority::init(cond.base.op)
                            }
                        } else {
                            QPriority::init(cond.base.op)
                        }
                    } else {
                        QPriority::init(cond.base.op)
                    };
                    label_pattern_tracker::add_cond_to_pattern_map(&cond, self);
                    q.push(cond, priority);
                }
            }
        }

        if self.restore_map.is_some() && (restored > 0 || not_found > 0) {
            let total = self.restore_total.fetch_add(restored, Ordering::Relaxed) + restored;
            let total_not_found = self.restore_not_found.fetch_add(not_found, Ordering::Relaxed) + not_found;
            info!("[Restore] total_restored={}, total_not_found={}", total, total_not_found);
        }

        label_pattern_tracker::print_stats();
    }

    pub fn add_entries_with_filter(&self, conds: Vec<CondStmt>, mutated_offsets: &HashSet<u32>) {
        let mut q = match self.queue.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!("Mutex poisoned! Results may be incorrect. Continuing...");
                poisoned.into_inner()
            },
        };

        let mut restored = 0usize;
        let mut not_found = 0usize;

        for mut cond in conds {
            if cond.is_desirable {
                if let Some(v) = q.get_mut(&cond) {
                    if !v.0.is_done() {
                        // If existed one and our new one has two different conditions,
                        // this indicate that it is explored.
                        if v.0.base.condition != cond.base.condition {
                            label_pattern_tracker::add_cond_to_pattern_map_with_filter(&cond, self, mutated_offsets);
                            v.0.mark_as_done();
                            q.change_priority(&cond, QPriority::done());
                        } else {
                            // Existed, but the new one are better
                            // If the cond is faster than the older one, we prefer the faster,
                            if config::PREFER_FAST_COND && v.0.speed > cond.speed {
                                mem::swap(v.0, &mut cond);
                                let priority = QPriority::init(cond.base.op);
                                q.change_priority(&cond, priority);
                            }
                        }
                    }
                } else {
                    let priority = if !cond.base.is_afl() {
                        if let Some(ref rm) = self.restore_map {
                            if let Some(entry) = rm.get(&(cond.base.cmpid, cond.base.context, cond.base.order)) {
                                cond.state = entry.state.clone();
                                cond.fuzz_times = entry.fuzz_times;
                                if !entry.variables.is_empty() {
                                    cond.variables = entry.variables.clone();
                                }
                                restored += 1;
                                trace!(
                                    "[Restore] cmpid={} ctx={} ord={} state={:?} p={} fuzz_times={}",
                                    cond.base.cmpid, cond.base.context, cond.base.order,
                                    cond.state, entry.priority, entry.fuzz_times
                                );
                                QPriority::from_u16(entry.priority)
                            } else {
                                not_found += 1;
                                QPriority::init(cond.base.op)
                            }
                        } else {
                            QPriority::init(cond.base.op)
                        }
                    } else {
                        QPriority::init(cond.base.op)
                    };
                    label_pattern_tracker::add_cond_to_pattern_map_with_filter(&cond, self, mutated_offsets);
                    q.push(cond, priority);
                }
            }
        }

        if self.restore_map.is_some() && (restored > 0 || not_found > 0) {
            let total = self.restore_total.fetch_add(restored, Ordering::Relaxed) + restored;
            let total_not_found = self.restore_not_found.fetch_add(not_found, Ordering::Relaxed) + not_found;
            info!("[Restore] total_restored={}, total_not_found={}", total, total_not_found);
        }

        label_pattern_tracker::print_stats();
    }

    pub fn update_entry(&self, cond: CondStmt) {
        let mut q = match self.queue.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!("Mutex poisoned! Results may be incorrect. Continuing...");
                poisoned.into_inner()
            },
        };
        if let Some(v) = q.get_mut(&cond) {
            v.0.clone_from(&cond);
        } else {
            warn!("Update entry: can not find this cond");
        }
        if cond.is_discarded() {
            q.change_priority(&cond, QPriority::done());
        }
    }
}
