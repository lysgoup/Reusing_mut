use byteorder::{BigEndian, ByteOrder, LittleEndian, WriteBytesExt};

// pub unsafe fn repr_as_raw_bytes<T: Sized>(p: &T) -> &[u8] {
//     std::slice::from_raw_parts(
//         (p as *const T) as *const u8,
//         std::mem::size_of::<T>(),
//     )
// }

// pub unsafe fn repr_as_raw_bytes_mut<T: Sized>(p: &mut T) -> &mut [u8] {
//     std::slice::from_raw_parts_mut((p as *const T) as *mut u8, std::mem::size_of::<T>())
// }

pub fn write_as_ule(val: u64, size: usize) -> Vec<u8> {
    let mut wtr = vec![];
    match size {
        1 => {
            wtr.write_u8(val as u8).unwrap();
        },
        2 => {
            wtr.write_u16::<LittleEndian>(val as u16).unwrap();
        },
        4 => {
            wtr.write_u32::<LittleEndian>(val as u32).unwrap();
        },
        8 => {
            wtr.write_u64::<LittleEndian>(val as u64).unwrap();
        },
        _ => {
            debug!("wrong size: {:?}", size);
            // panic!("strange arg size: {}", size);
        },
    }

    wtr
}

pub fn write_as_ube(val: u64, size: usize) -> Vec<u8> {
    let mut wtr = vec![];
    match size {
        1 => {
            wtr.write_u8(val as u8).unwrap();
        },
        2 => {
            wtr.write_u16::<BigEndian>(val as u16).unwrap();
        },
        4 => {
            wtr.write_u32::<BigEndian>(val as u32).unwrap();
        },
        8 => {
            wtr.write_u64::<BigEndian>(val as u64).unwrap();
        },
        _ => {
            debug!("wrong size: {:?}", size);
        },
    }

    wtr
}

// Interprets `buf` as an unsigned integer of its own length (1/2/4/8 bytes
// only, matching write_as_ule/write_as_ube) -- used to check whether a
// tainted operand's runtime value matches the raw input bytes under either
// byte-order assumption, since source code may assemble a multi-byte value
// via a native typed load (little-endian on x86) OR manual bit-shifts
// (`(buf[0]<<8)|buf[1]`, i.e. big-endian), and nothing in the taint/track
// data says which.
pub fn read_as_ule(buf: &[u8]) -> Option<u64> {
    match buf.len() {
        1 => Some(buf[0] as u64),
        2 => Some(LittleEndian::read_u16(buf) as u64),
        4 => Some(LittleEndian::read_u32(buf) as u64),
        8 => Some(LittleEndian::read_u64(buf)),
        _ => None,
    }
}

pub fn read_as_ube(buf: &[u8]) -> Option<u64> {
    match buf.len() {
        1 => Some(buf[0] as u64),
        2 => Some(BigEndian::read_u16(buf) as u64),
        4 => Some(BigEndian::read_u32(buf) as u64),
        8 => Some(BigEndian::read_u64(buf)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_write_as_ule() {
        let n: u32 = 1934642260;
        let v = write_as_ule(n as u64, 4);
        println!("{:?}", v);
        assert!(v.len() == 4);
    }
}
