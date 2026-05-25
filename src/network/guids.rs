use wdk_sys::GUID;

pub const PROVIDER_GUID: GUID = guid_from_str("{f41ad05c-5df1-4ae6-81f3-71d1eda6ba0a}");

pub const fn guid_from_str(s: &str) -> GUID {
    let bytes = s.as_bytes();

    // remove { }
    let (start, len) = if bytes[0] == b'{' { (1, 36) } else { (0, 36) };

    // verify len and -
    if bytes.len() < start + len
        || bytes[start + 8] != b'-'
        || bytes[start + 13] != b'-'
        || bytes[start + 18] != b'-'
        || bytes[start + 23] != b'-'
    {
        panic!("Invalid GUID format: Incorrect length or hyphen position");
    }

    // convert hex to u8
    const fn hex_to_u8(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => panic!("Invalid hex character in GUID"),
        }
    }

    // parse specified range of hex to u32/u16 (big-endian parsing)
    const fn parse_hex(b: &[u8], start: usize, len: usize) -> u64 {
        let mut val = 0u64;
        let mut i = 0;
        while i < len {
            val = (val << 4) | (hex_to_u8(b[start + i]) as u64);
            i += 1;
        }
        val
    }

    GUID {
        Data1: parse_hex(bytes, start, 8) as u32,
        Data2: parse_hex(bytes, start + 9, 4) as u16,
        Data3: parse_hex(bytes, start + 14, 4) as u16,
        Data4: [
            (parse_hex(bytes, start + 19, 2) as u8),
            (parse_hex(bytes, start + 21, 2) as u8),
            (parse_hex(bytes, start + 24, 2) as u8),
            (parse_hex(bytes, start + 26, 2) as u8),
            (parse_hex(bytes, start + 28, 2) as u8),
            (parse_hex(bytes, start + 30, 2) as u8),
            (parse_hex(bytes, start + 32, 2) as u8),
            (parse_hex(bytes, start + 34, 2) as u8),
        ],
    }
}
