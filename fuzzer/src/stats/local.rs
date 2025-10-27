use super::*;
use crate::{cond_stmt::CondStmt, executor::StatusType, fuzz_type::FuzzType};

#[derive(Default)]
pub struct LocalStats {
    pub fuzz_type: FuzzType,

    pub num_exec: Counter,
    pub num_inputs: Counter,
    pub num_hangs: Counter,
    pub num_crashes: Counter,

    pub track_time: TimeDuration,
    pub start_time: TimeIns,

    pub avg_exec_time: SyncAverage,
    pub avg_edge_num: SyncAverage,
}

// LocalStats 백업용 구조체
#[derive(Clone)]
pub struct LocalStatsSnapshot {
    pub num_exec: Counter,
    pub num_inputs: Counter,
    pub num_hangs: Counter,
    pub num_crashes: Counter,
}

impl LocalStats {
    pub fn register(&mut self, cond: &CondStmt) {
        self.fuzz_type = cond.get_fuzz_type();
        self.clear();
    }

    pub fn clear(&mut self) {
        self.num_exec = Default::default();
        self.num_inputs = Default::default();
        self.num_hangs = Default::default();
        self.num_crashes = Default::default();

        self.start_time = Default::default();
        self.track_time = Default::default();
    }

    pub fn find_new(&mut self, status: &StatusType) {
        match status {
            StatusType::Normal => {
                self.num_inputs.count();
            },
            StatusType::Timeout => {
                self.num_hangs.count();
            },
            StatusType::Crash => {
                self.num_crashes.count();
            },
            _ => {},
        }
    }

    // 백업 생성
    pub fn snapshot(&self) -> LocalStatsSnapshot {
        LocalStatsSnapshot {
            num_exec: self.num_exec,
            num_inputs: self.num_inputs,
            num_hangs: self.num_hangs,
            num_crashes: self.num_crashes,
        }
    }

    // 백업으로부터 복원
    pub fn restore(&mut self, snapshot: &LocalStatsSnapshot) {
        self.num_exec = snapshot.num_exec;
        self.num_inputs = snapshot.num_inputs;
        self.num_hangs = snapshot.num_hangs;
        self.num_crashes = snapshot.num_crashes;
    }
}