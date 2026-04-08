use crate::cond_stmt::CondState;
use std::{
    collections::HashMap,
    fs,
    io::{BufRead, BufReader},
    path::Path,
};

pub struct RestoredEntry {
    pub state: CondState,
    pub priority: u16,
    pub fuzz_times: usize,
    pub variables: Vec<u8>,
}

pub type RestoreMap = HashMap<(u32, u32, u32), RestoredEntry>;

pub fn load_restore_map(csv_path: &Path) -> RestoreMap {
    let mut map = HashMap::new();
    let file = match fs::File::open(csv_path) {
        Ok(f) => f,
        Err(e) => {
            warn!("Could not open {:?} for queue restoration: {:?}", csv_path, e);
            return map;
        },
    };

    let reader = BufReader::new(file);
    let mut count = 0;

    for (i, line) in reader.lines().enumerate() {
        if i == 0 {
            continue; // skip header
        }
        let line = match line {
            Ok(l) => l,
            Err(_) => continue,
        };

        // header: cmpid, context, order, belong, p, op, condition, arg1, arg2,
        //         is_desirable, offsets, state, fuzz_times, variables
        let cols: Vec<&str> = line.split(", ").collect();
        if cols.len() < 14 {
            continue;
        }

        let cmpid: u32 = match cols[0].trim().parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        let context: u32 = match cols[1].trim().parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        let order: u32 = match cols[2].trim().parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        let priority: u16 = cols[4].trim().parse().unwrap_or(0);
        let state = parse_cond_state(cols[11].trim());
        let fuzz_times: usize = cols[12].trim().parse().unwrap_or(0);
        let variables = parse_hex_bytes(cols[13].trim());

        map.insert(
            (cmpid, context, order),
            RestoredEntry { state, priority, fuzz_times, variables },
        );
        count += 1;
    }

    warn!("Loaded {} entries from {:?} for queue restoration", count, csv_path);
    map
}

fn parse_cond_state(s: &str) -> CondState {
    match s {
        "Offset" => CondState::Offset,
        "OffsetOpt" => CondState::OffsetOpt,
        "OffsetAll" => CondState::OffsetAll,
        "OffsetAllEnd" => CondState::OffsetAllEnd,
        "OneByte" => CondState::OneByte,
        "Unsolvable" => CondState::Unsolvable,
        "Deterministic" => CondState::Deterministic,
        "Timeout" => CondState::Timeout,
        _ => CondState::Offset,
    }
}

fn parse_hex_bytes(s: &str) -> Vec<u8> {
    if s.is_empty() {
        return vec![];
    }
    (0..s.len())
        .step_by(2)
        .filter_map(|i| s.get(i..i + 2).and_then(|h| u8::from_str_radix(h, 16).ok()))
        .collect()
}
