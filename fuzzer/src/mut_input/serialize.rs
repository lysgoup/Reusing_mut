use byteorder::{LittleEndian, WriteBytesExt};

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

// Little-endian counterpart to write_as_ule: raw bytes -> integer value.
// None if buf is shorter than size or size isn't one of the supported widths.
pub fn read_as_ule(buf: &[u8], size: usize) -> Option<u64> {
    if buf.len() < size {
        return None;
    }
    match size {
        1 => Some(buf[0] as u64),
        2 => Some(u16::from_le_bytes([buf[0], buf[1]]) as u64),
        4 => Some(u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as u64),
        8 => Some(u64::from_le_bytes([
            buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
        ])),
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
