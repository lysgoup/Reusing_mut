use super::{filter, load_pin_data::get_log_data_pin};
use crate::{
    cond_stmt::{CondState, CondStmt},
    mut_input,
};
use angora_common::{defs, tag::TagSeg};
use runtime::get_log_data;
use std::{collections::HashMap, io, path::Path};

pub fn read_and_parse(
    out_f: &Path,
    is_pin_mode: bool,
    enable_exploitation: bool,
) -> io::Result<Vec<CondStmt>> {
    let log_data = {
        if is_pin_mode {
            get_log_data_pin(out_f)?
        } else {
            get_log_data(out_f)?
        }
    };

    let mut cond_list: Vec<CondStmt> = Vec::new();
    // assign taint labels and magic_bytes to cond list
    for (i, cond_base) in log_data.cond_list.iter().enumerate() {
        if !enable_exploitation {
            if cond_base.is_exploitable() {
                continue;
            }
        }
        let mut cond = CondStmt::from(*cond_base);
        if cond_base.op != defs::COND_LEN_OP && (cond_base.lb1 > 0 || cond_base.lb2 > 0) {
            if cond_base.size == 0 {
                debug!("cond: {:?}", cond_base);
            }
            get_offsets_and_variables(&log_data.tags, &mut cond, &log_data.magic_bytes.get(&i));
        }

        cond_list.push(cond);
    }
    Ok(cond_list)
}

fn get_offsets_and_variables(
    m: &HashMap<u32, Vec<TagSeg>>,
    cond: &mut CondStmt,
    magic_bytes: &Option<&(Vec<u8>, Vec<u8>)>,
) {
    let empty_offsets: Vec<TagSeg> = vec![];
    let offsets1 = m.get(&cond.base.lb1).unwrap_or(&empty_offsets);
    let offsets2 = m.get(&cond.base.lb2).unwrap_or(&empty_offsets);
    if offsets2.len() == 0 || (offsets1.len() > 0 && offsets1.len() <= offsets2.len()) {
        cond.offsets = offsets1.clone();
        if cond.base.lb2 > 0 && cond.base.lb1 != cond.base.lb2 {
            cond.offsets_opt = offsets2.clone();
        }
        cond.variables = if let Some(args) = magic_bytes {
            [&args.1[..], &args.0[..]].concat()
        } else {
            // if it is integer comparison, we use the bytes of constant as magic bytes.
            mut_input::write_as_ule(cond.base.arg2, cond.base.size as usize)
        };
    } else {
        cond.offsets = offsets2.clone();
        if cond.base.lb1 > 0 && cond.base.lb1 != cond.base.lb2 {
            cond.offsets_opt = offsets1.clone();
        }
        cond.variables = if let Some(args) = magic_bytes {
            [&args.0[..], &args.1[..]].concat()
        } else {
            mut_input::write_as_ule(cond.base.arg1, cond.base.size as usize)
        };
    }
}

pub fn load_track_data(
    out_f: &Path,
    id: u32,
    speed: u32,
    is_pin_mode: bool,
    enable_exploitation: bool,
) -> Vec<CondStmt> {
    let mut cond_list = match read_and_parse(out_f, is_pin_mode, enable_exploitation) {
        Result::Ok(val) => val,
        Result::Err(err) => {
            error!("parse track file error!! {:?}", err);
            vec![]
        },
    };

    for cond in cond_list.iter_mut() {
        cond.base.belong = id;
        cond.speed = speed;
        if cond.offsets.len() == 1 && cond.offsets[0].end - cond.offsets[0].begin == 1 {
            cond.state = CondState::OneByte;
        }
    }

    tag_adjacent_one_byte_groups(&mut cond_list);

    filter::filter_cond_list(&mut cond_list);

    cond_list
}

// Finds runs of one-byte is_const_eq_shape conds that are adjacent (same
// context, contiguous offsets, same FN_OP-ness) in this single input's cond
// list, and stamps every member of a run with the run's merged offset span
// via `magic_byte_group`. Nothing is merged or removed here -- cond_list is
// unchanged and each cond keeps its own offsets.
//
// Adjacency is decided on OFFSETS, not on execution order: cond_list position
// only approximates execution order (untainted compares are never logged,
// MAX_COND_ORDER drops repeats past 16, threads interleave), and measured on
// real corpora only 0-63% of runs are contiguous in it, per target.
//
// Runs once right after taint tracking, while all sibling conds from this
// input are still together -- once a cond is stored individually (e.g. in the
// depot queue) its siblings are gone, so this is the only point where the
// full run is visible.
fn tag_adjacent_one_byte_groups(cond_list: &mut Vec<CondStmt>) {
    let mut merge_candidates: Vec<usize> = cond_list
        .iter()
        .enumerate()
        .filter(|(_, c)| c.is_const_eq_shape && c.state == CondState::OneByte)
        .map(|(i, _)| i)
        .collect();
    merge_candidates.sort_by_key(|&i| (cond_list[i].base.context, cond_list[i].offsets[0].begin));

    let mut k = 0;
    while k < merge_candidates.len() {
        let mut j = k;
        while j + 1 < merge_candidates.len() {
            let cur = &cond_list[merge_candidates[j]];
            let next = &cond_list[merge_candidates[j + 1]];
            // is_const_eq_shape only lets FN_OP (memcmp/strcmp/...) or ICMP EQ/NE
            // through -- don't glue a memcmp-style byte check to a plain
            // integer-compare byte check just because they're adjacent, they
            // aren't part of the same logical comparison.
            let same_kind = (cur.base.op == defs::COND_FN_OP) == (next.base.op == defs::COND_FN_OP);
            if same_kind
                && next.base.context == cur.base.context
                && next.offsets[0].begin == cur.offsets[0].end
            {
                j += 1;
            } else {
                break;
            }
        }
        if j > k {
            let mut group_span = cond_list[merge_candidates[k]].offsets[0];
            group_span.end = cond_list[merge_candidates[j]].offsets[0].end;
            let group = vec![group_span];
            for &idx in &merge_candidates[k..=j] {
                cond_list[idx].magic_byte_group = group.clone();
            }
        }
        k = j + 1;
    }
}
