// Converts an Angora bincode track file (ANGORA_TRACK_OUTPUT) into the
// AFLplusplus_reusing dtaint wire format (include/dtaint.h in that repo:
// magic 'DTNT' header + fixed-width dtaint_cond_record/dtaint_tag_record/
// dtaint_magic_bytes_record), so both fuzzers' taint logs can be diffed with
// the same tooling. Field semantics already match 1:1 -- dtaint.h was ported
// from this exact LogData/CondStmtBase/TagSeg shape -- so this is a pure
// re-encode, no data transformation.

use angora_common::log_data::LogData;
use std::{
    env,
    fs::File,
    io::{self, BufReader, BufWriter, Write},
    path::Path,
    process,
};

const DTAINT_FILE_MAGIC: u32 = 0x444e_5454; // 'DTNT'
const DTAINT_FILE_VERSION: u32 = 2;

fn read_log_data(path: &Path) -> io::Result<LogData> {
    let f = File::open(path)?;
    if f.metadata()?.len() == 0 {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "empty angora track file (no tainted conditions recorded)",
        ));
    }
    let mut reader = BufReader::new(f);
    bincode::deserialize_from(&mut reader)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("bincode parse error: {e}")))
}

fn write_u32(w: &mut impl Write, v: u32) -> io::Result<()> {
    w.write_all(&v.to_ne_bytes())
}

fn write_u64(w: &mut impl Write, v: u64) -> io::Result<()> {
    w.write_all(&v.to_ne_bytes())
}

// Mirrors struct dtaint_cond_record field-for-field (dtaint.h) -- same
// field order as CondStmtBase itself, so this is a straight passthrough.
fn write_cond(w: &mut impl Write, c: &angora_common::cond_stmt_base::CondStmtBase) -> io::Result<()> {
    write_u32(w, c.cmpid)?;
    write_u32(w, c.context)?;
    write_u32(w, c.order)?;
    write_u32(w, c.belong)?;
    write_u32(w, c.condition)?;
    write_u32(w, c.level)?;
    write_u32(w, c.op)?;
    write_u32(w, c.size)?;
    write_u32(w, c.lb1)?;
    write_u32(w, c.lb2)?;
    write_u64(w, c.arg1)?;
    write_u64(w, c.arg2)
}

// dtaint_tag_seg_wire widens TagSeg.sign from Rust's 1-byte bool to a
// fixed-width u32 -- see dtaint.h's comment on dtaint_tag_seg_wire.
fn write_tag_seg(w: &mut impl Write, seg: &angora_common::tag::TagSeg) -> io::Result<()> {
    write_u32(w, seg.sign as u32)?;
    write_u32(w, seg.begin)?;
    write_u32(w, seg.end)
}

fn convert(data: &LogData, out: &mut impl Write) -> io::Result<()> {
    let n_conds = data.cond_list.len() as u32;
    let n_tags = data.tags.len() as u32;
    let n_magic_bytes = data.magic_bytes.len() as u32;

    write_u32(out, DTAINT_FILE_MAGIC)?;
    write_u32(out, DTAINT_FILE_VERSION)?;
    write_u32(out, n_conds)?;
    write_u32(out, n_tags)?;
    write_u32(out, n_magic_bytes)?;

    for c in &data.cond_list {
        write_cond(out, c)?;
    }

    // HashMap iteration order isn't insertion order (unlike the C runtime's
    // append-only tags[] table), but the dtaint file format doesn't require
    // any particular tag order -- consumers key off dtaint_tag_record.label.
    for (label, segs) in &data.tags {
        write_u32(out, *label)?;
        write_u32(out, segs.len() as u32)?;
        for seg in segs {
            write_tag_seg(out, seg)?;
        }
    }

    // Angora's magic_bytes key is the index into cond_list the snapshot
    // belongs to (Logger::save_magic_bytes) -- exactly dtaint_magic_bytes_
    // record.cond_index's meaning, so no reindexing needed.
    for (cond_index, (buf1, buf2)) in &data.magic_bytes {
        write_u32(out, *cond_index as u32)?;
        write_u32(out, buf1.len() as u32)?;
        write_u32(out, buf2.len() as u32)?;
        out.write_all(buf1)?;
        out.write_all(buf2)?;
    }

    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: {} <angora-track-file> <output.dtaint>", args[0]);
        process::exit(1);
    }

    let in_path = Path::new(&args[1]);
    let out_path = Path::new(&args[2]);

    let data = read_log_data(in_path).unwrap_or_else(|e| {
        eprintln!("failed to read '{}': {e}", in_path.display());
        process::exit(1);
    });

    let out_file = File::create(out_path).unwrap_or_else(|e| {
        eprintln!("failed to create '{}': {e}", out_path.display());
        process::exit(1);
    });
    let mut writer = BufWriter::new(out_file);

    if let Err(e) = convert(&data, &mut writer) {
        eprintln!("failed to write '{}': {e}", out_path.display());
        process::exit(1);
    }
    if let Err(e) = writer.flush() {
        eprintln!("failed to flush '{}': {e}", out_path.display());
        process::exit(1);
    }

    println!(
        "wrote {} conds, {} tags, {} magic_bytes -> {}",
        data.cond_list.len(),
        data.tags.len(),
        data.magic_bytes.len(),
        out_path.display()
    );
}
