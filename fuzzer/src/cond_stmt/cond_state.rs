use crate::{cond_stmt::CondStmt, mut_input::offsets::*, depot::merge_continuous_segments};
use angora_common::{config, defs};
use serde_derive::{Deserialize, Serialize};
use std;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub enum CondState {
    Offset,
    OffsetOpt,
    OffsetAll,
    OffsetAllEnd,

    OneByte,
    Unsolvable,
    Deterministic,
    Reusing,
    Timeout,
}

impl Default for CondState {
    fn default() -> Self {
        CondState::Offset
    }
}

impl CondStmt {
    pub fn is_time_expired(&self) -> bool {
        ((self.state.is_det() || self.state.is_one_byte()) && !self.is_first_time())
            || self.fuzz_times >= config::LONG_FUZZ_TIME
    }
}

impl CondState {
    pub fn is_initial(&self) -> bool {
        self == &Default::default() || self.is_one_byte()
    }

    pub fn is_det(&self) -> bool {
        match self {
            CondState::Deterministic => true,
            _ => false,
        }
    }

    pub fn is_one_byte(&self) -> bool {
        match self {
            CondState::OneByte => true,
            _ => false,
        }
    }

    pub fn is_unsolvable(&self) -> bool {
        match self {
            CondState::Unsolvable => true,
            _ => false,
        }
    }

    pub fn is_timeout(&self) -> bool {
        match self {
            CondState::Timeout => true,
            _ => false,
        }
    }
}

pub trait NextState {
    fn next_state(&mut self);

    fn to_offsets_opt(&mut self);
    fn to_offsets_all(&mut self);
    fn to_offsets_all_end(&mut self);
    fn to_det(&mut self);
    fn to_unsolvable(&mut self);
    fn to_reusing(&mut self);
    fn to_timeout(&mut self);
}

impl NextState for CondStmt {
    fn next_state(&mut self) {
        match self.state {
            CondState::Offset => {
                if self.offsets_opt.len() > 0 {
                    self.to_offsets_opt();
                } else {
                    self.to_det();
                }
            },
            CondState::OneByte => {
                if self.offsets_opt.len() > 0 {
                    self.to_offsets_opt();
                } else {
                    self.to_reusing();
                }
            },
            CondState::OffsetOpt => {
                self.to_offsets_all();
            },
            CondState::OffsetAll => {
                self.to_det();
            },
            CondState::Deterministic => {
                self.to_reusing();
            },
            _ => {},
        }
    }

    fn to_offsets_opt(&mut self) {
        self.state = CondState::OffsetOpt;
        std::mem::swap(&mut self.offsets, &mut self.offsets_opt);
    }

    fn to_offsets_all(&mut self) {
        self.state = CondState::OffsetAll;
        self.offsets = merge_offsets(&self.offsets, &self.offsets_opt);
        self.offsets_opt.clear();  // Clear after merge
    }

    fn to_det(&mut self) {
        self.state = CondState::Deterministic;
    }

    fn to_offsets_all_end(&mut self) {
        debug!("to_all_end");
        self.state = CondState::OffsetAllEnd;
    }

    fn to_unsolvable(&mut self) {
        debug!("to unsovable");
        self.state = CondState::Unsolvable;
    }

    fn to_reusing(&mut self) {
        debug!("to reusing");
        // offsets_opt가 있으면 merge
        if self.offsets_opt.len() > 0 {
            self.offsets = merge_offsets(&self.offsets, &self.offsets_opt);
        }

        // 세그먼트 개수만큼 reusing_segment_index 초기화
        let merged_segments = merge_continuous_segments(&self.offsets);
        self.reusing_segment_index = vec![0; merged_segments.len()];

        self.state = CondState::Reusing;
    }

    fn to_timeout(&mut self) {
        debug!("to timeout");
        self.speed = defs::SLOW_SPEED;
        self.state = CondState::Timeout;
    }
}
