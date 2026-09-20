// Converts Angora's own native track file (bincode-serialized LogData,
// written by runtime::logger::Logger::fini -- see runtime/src/logger.rs)
// into AFLplusplus_reusing's dtaint.h wire format.
//
// Why this exists: AFLplusplus_reusing's dtaint_cond_record/dtaint_tag_record/
// dtaint_magic_bytes_record structs (include/dtaint.h, in the AFLplusplus_reusing
// repo) were themselves designed as a field-for-field mirror of Angora's own
// CondStmtBase/LogData -- so converting is a straight re-serialization of data
// Angora already computes, via Angora's own (already-tested) get_log_data
// parser, not a reimplementation of any taint-tracking logic. This lets both
// fuzzers' taint output for the *same* seed be parsed with one shared tool and
// diffed byte-offset-for-byte-offset, to cross-validate that the two
// independently-built DFSan integrations agree.
//
// Usage: dump_dtaint <angora_track_file> <output.dtaint>
use angora_common::log_data::LogData;
use runtime::get_log_data;
use std::{
    env,
    fs::File,
    io::{BufWriter, Write},
    path::PathBuf,
};

const DTAINT_FILE_MAGIC: u32 = 0x444e_5454;
const DTAINT_FILE_VERSION: u32 = 2;

fn write_u32<W: Write>(w: &mut W, v: u32) {
    w.write_all(&v.to_le_bytes()).expect("write u32");
}

fn write_u64<W: Write>(w: &mut W, v: u64) {
    w.write_all(&v.to_le_bytes()).expect("write u64");
}

fn convert(log_data: &LogData, w: &mut impl Write) {
    write_u32(w, DTAINT_FILE_MAGIC);
    write_u32(w, DTAINT_FILE_VERSION);
    write_u32(w, log_data.cond_list.len() as u32);
    write_u32(w, log_data.tags.len() as u32);
    write_u32(w, log_data.magic_bytes.len() as u32);

    // dtaint_cond_record: cmpid, context, order, belong, condition, level,
    // op, size (all u32), lb1, lb2 (u32), arg1, arg2 (u64) -- field-for-
    // field identical to CondStmtBase.
    for cond in &log_data.cond_list {
        write_u32(w, cond.cmpid);
        write_u32(w, cond.context);
        write_u32(w, cond.order);
        write_u32(w, cond.belong);
        write_u32(w, cond.condition);
        write_u32(w, cond.level);
        write_u32(w, cond.op);
        write_u32(w, cond.size);
        write_u32(w, cond.lb1);
        write_u32(w, cond.lb2);
        write_u64(w, cond.arg1);
        write_u64(w, cond.arg2);
    }

    // dtaint_tag_record: label, n_segs, followed inline by n_segs *
    // dtaint_tag_seg_wire { sign (bool widened to u32), begin, end }.
    // Iteration order over the HashMap doesn't matter: the consumer
    // resolves lb1/lb2 by scanning for a matching label, not by position.
    for (label, segs) in &log_data.tags {
        write_u32(w, *label);
        write_u32(w, segs.len() as u32);
        for seg in segs {
            write_u32(w, seg.sign as u32);
            write_u32(w, seg.begin);
            write_u32(w, seg.end);
        }
    }

    // dtaint_magic_bytes_record: cond_index, len1, len2, followed by len1
    // raw bytes (arg1's snapshot) then len2 raw bytes (arg2's snapshot) --
    // matches runtime/src/track.rs's `lc.save_magic_bytes((arg1, arg2))`
    // tuple order (.0 = arg1, .1 = arg2).
    for (cond_index, (buf1, buf2)) in &log_data.magic_bytes {
        write_u32(w, *cond_index as u32);
        write_u32(w, buf1.len() as u32);
        write_u32(w, buf2.len() as u32);
        w.write_all(buf1).expect("write magic bytes buf1");
        w.write_all(buf2).expect("write magic bytes buf2");
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: dump_dtaint <angora_track_file> <output.dtaint>");
        std::process::exit(1);
    }

    let in_path = PathBuf::from(&args[1]);
    let out_path = PathBuf::from(&args[2]);

    let log_data = match get_log_data(&in_path) {
        Ok(v) => v,
        Err(err) => {
            eprintln!("failed to parse angora track file {:?}: {:?}", in_path, err);
            std::process::exit(1);
        },
    };

    let out_file = File::create(&out_path).expect("could not create output file");
    let mut w = BufWriter::new(out_file);
    convert(&log_data, &mut w);
    w.flush().expect("flush output file");

    eprintln!(
        "wrote {} conds, {} tags, {} magic_bytes entries to {:?}",
        log_data.cond_list.len(),
        log_data.tags.len(),
        log_data.magic_bytes.len(),
        out_path
    );
}
