use super::*;
use serde_derive::Serialize;
use std::sync::Mutex;

#[derive(Clone, Default, Serialize)]
pub struct ReusingStats {
    pub num_exec: Counter,
    pub num_inputs: Counter,
    pub num_hangs: Counter,
    pub num_crashes: Counter,
}

impl ReusingStats {
    pub fn new() -> Self {
        Default::default()
    }
}

impl fmt::Display for ReusingStats {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let zero_counter = Counter(0);
        write!(
            f,
            "CONDS: {}, EXEC: {}, TIME: {}, FOUND: {} - {} - {}",
            zero_counter,  // reusing은 CONDS 0
            self.num_exec,
            "[--:--:--]",  // TIME은 추적 안 함
            self.num_inputs,
            self.num_hangs,
            self.num_crashes,
        )
    }
}

lazy_static::lazy_static! {
    pub static ref REUSING_STATS: Mutex<ReusingStats> = Mutex::new(ReusingStats::new());
}