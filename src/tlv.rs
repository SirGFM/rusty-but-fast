// Tag/Type Length Value encoder/decoder.
//
// The length is usually inferred from the type, except from array (which
// has a u32 for the number of elements following the tag).
pub mod tlv {
    enum Tag {
        I8(i8),
        U8(u8),
        I16(i16),
        U16(u16),
        I32(i32),
        U32(u32),
        I64(i64),
        U64(u64),
        I128(i128),
        U128(u128),
        Char(char),
        Bool(bool),
        Array(u32, u8),
        Invalid,
    }

    impl std::cmp::PartialEq for Tag {
        fn eq(&self, other: &Self) -> bool {
            match (self, other) {
                (Tag::I8(a), Tag::I8(b)) => a == b,
                (Tag::U8(a), Tag::U8(b)) => a == b,
                (Tag::I16(a), Tag::I16(b)) => a == b,
                (Tag::U16(a), Tag::U16(b)) => a == b,
                (Tag::I32(a), Tag::I32(b)) => a == b,
                (Tag::U32(a), Tag::U32(b)) => a == b,
                (Tag::I64(a), Tag::I64(b)) => a == b,
                (Tag::U64(a), Tag::U64(b)) => a == b,
                (Tag::I128(a), Tag::I128(b)) => a == b,
                (Tag::U128(a), Tag::U128(b)) => a == b,
                (Tag::Char(a), Tag::Char(b)) => a == b,
                (Tag::Bool(a), Tag::Bool(b)) => a == b,
                (Tag::Array(la, va), Tag::Array(lb, vb)) => la == lb && va == vb,
                _ => false,
            }
        }
    }

    impl std::fmt::Debug for Tag {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            match self {
                Tag::I8(v) => {
                    f.write_fmt(format_args!("Tag-i8 {}", v))
                },
                Tag::U8(v) => {
                    f.write_fmt(format_args!("Tag-u8 {}", v))
                },
                Tag::I16(v) => {
                    f.write_fmt(format_args!("Tag-i16 {}", v))
                },
                Tag::U16(v) => {
                    f.write_fmt(format_args!("Tag-u16 {}", v))
                },
                Tag::I32(v) => {
                    f.write_fmt(format_args!("Tag-i32 {}", v))
                },
                Tag::U32(v) => {
                    f.write_fmt(format_args!("Tag-u32 {}", v))
                },
                Tag::I64(v) => {
                    f.write_fmt(format_args!("Tag-i64 {}", v))
                },
                Tag::U64(v) => {
                    f.write_fmt(format_args!("Tag-u64 {}", v))
                },
                Tag::I128(v) => {
                    f.write_fmt(format_args!("Tag-i128 {}", v))
                },
                Tag::U128(v) => {
                    f.write_fmt(format_args!("Tag-u128 {}", v))
                },
                Tag::Char(v) => {
                    f.write_fmt(format_args!("Tag-char {}", v))
                },
                Tag::Bool(v) => {
                    f.write_fmt(format_args!("Tag-bool {}", v))
                },
                Tag::Array(l, t) => {
                    let tag = Tag::from(*t);
                    f.write_fmt(format_args!("Tag-array [{}, {}]", *t, *l))
                },
                Tag::Invalid => {
                    f.write_fmt(format_args!("Tag-invalid"))
                },
            }
        }
    }

    impl std::convert::From<u8> for Tag {
        fn from(v: u8) -> Self {
            match v {
                0x00 => Tag::I8(0),
                0x01 => Tag::U8(0),
                0x02 => Tag::I16(0),
                0x03 => Tag::U16(0),
                0x04 => Tag::I32(0),
                0x05 => Tag::U32(0),
                0x06 => Tag::I64(0),
                0x07 => Tag::U64(0),
                0x08 => Tag::I128(0),
                0x09 => Tag::U128(0),
                0x0A => Tag::Char('\0'),
                0x0B => Tag::Bool(false),
                0x0C => Tag::Array(0, 0),
                _    => Tag::Invalid,
            }
        }
    }

    impl Tag {
        pub fn required_length(&self) -> usize {
            match self {
                Tag::I8(_) => 1,
                Tag::U8(_) => 1,
                Tag::I16(_) => 2,
                Tag::U16(_) => 2,
                Tag::I32(_) => 4,
                Tag::U32(_) => 4,
                Tag::I64(_) => 8,
                Tag::U64(_) => 8,
                Tag::I128(_) => 16,
                Tag::U128(_) => 16,
                Tag::Char(_) => 1,
                Tag::Bool(_) => 1,
                Tag::Array(_, _) => 4 + 1,
                _ => return 0,
            }
        }
    }

    pub struct TagParser<'a> {
        cur: Tag,
        next: &'a[u8],
    }

    impl<'a> std::convert::TryFrom<&'a[u8]> for TagParser<'a> {
        type Error = &'static str;

        fn try_from(buf: &'a[u8]) -> Result<Self, Self::Error> {
            if buf.len() < 1 {
                return Err("Cannot retrieve Tag from u8");
            }
            let tag = Tag::from(buf[0]);
            let buf = &buf[1..];
            let len = tag.required_length();
            if buf.len() < len {
                return Err("Missing data in buffer");
            }

            let cur: Tag;
            match tag {
                Tag::I8(_) => {
                    let arr = [ buf[0] ];
                    let v = i8::from_be_bytes(arr);
                    cur = Tag::I8(v);
                },
                Tag::U8(_) => {
                    cur = Tag::U8(buf[0]);
                },
                Tag::I16(_) => {
                    let arr = [buf[0], buf[1]];
                    let v = i16::from_be_bytes(arr);
                    cur = Tag::I16(v);
                },
                Tag::U16(_) => {
                    let arr = [buf[0], buf[1]];
                    let v = u16::from_be_bytes(arr);
                    cur = Tag::U16(v);
                },
                Tag::I32(_) => {
                    let arr = [buf[0], buf[1], buf[2], buf[3]];
                    let v = i32::from_be_bytes(arr);
                    cur = Tag::I32(v);
                },
                Tag::U32(_) => {
                    let arr = [buf[0], buf[1], buf[2], buf[3]];
                    let v = u32::from_be_bytes(arr);
                    cur = Tag::U32(v);
                },
                Tag::I64(_) => {
                    let arr = [buf[0], buf[1], buf[2], buf[3],
                               buf[4], buf[5], buf[6], buf[7]];
                    let v = i64::from_be_bytes(arr);
                    cur = Tag::I64(v);
                },
                Tag::U64(_) => {
                    let arr = [buf[0], buf[1], buf[2], buf[3],
                               buf[4], buf[5], buf[6], buf[7]];
                    let v = u64::from_be_bytes(arr);
                    cur = Tag::U64(v);
                },
                Tag::I128(_) => {
                    let arr = [buf[0], buf[1], buf[2], buf[3],
                               buf[4], buf[5], buf[6], buf[7],
                               buf[8], buf[9], buf[10], buf[11],
                               buf[12], buf[13], buf[14], buf[15]];
                    let v = i128::from_be_bytes(arr);
                    cur = Tag::I128(v);
                },
                Tag::U128(_) => {
                    let arr = [buf[0], buf[1], buf[2], buf[3],
                               buf[4], buf[5], buf[6], buf[7],
                               buf[8], buf[9], buf[10], buf[11],
                               buf[12], buf[13], buf[14], buf[15]];
                    let v = u128::from_be_bytes(arr);
                    cur = Tag::U128(v);
                },
                Tag::Char(_) => {
                    let v: char = buf[0] as char;
                    cur = Tag::Char(v);
                },
                Tag::Bool(_) => {
                    let v = buf[0] != 0;
                    cur = Tag::Bool(v);
                },
                Tag::Array(_, _) => {
                    let arr = [buf[0], buf[1], buf[2], buf[3]];
                    let len = u32::from_be_bytes(arr);
                    let v = buf[4];
                    cur = Tag::Array(len, v);
                },
                _ => {
                    return Err("Not implemented yet...");
                }
            }

            let tp = TagParser{
                cur: cur,
                next: &buf[len..],
            };
            return Ok(tp);
        }
    }

    impl TagParser<'_> {
        fn read_arr_i8(&mut self, out: &mut [i8]) {
            if let Tag::Array(l, t) = self.cur {
                if let Tag::I8(0) = Tag::from(t) {
                    let l = l as usize;
                    if out.len() < l {
                        panic!("Output buffer too small for i8-array");
                    }

                    let buf = &self.next[..l];
                    self.next = &self.next[l..];

                    for i in 0..buf.len() {
                        out[i] = buf[i] as i8;
                    }
                }
            }
            panic!("Invalid i8-array tag!");
        }

        fn read_arr_u8(&mut self, out: &mut [u8]) {
            if let Tag::Array(l, t) = self.cur {
                if let Tag::U8(0) = Tag::from(t) {
                    let l = l as usize;
                    if out.len() < l {
                        panic!("Output buffer too small for u8-array");
                    }

                    let buf = &self.next[..l];
                    self.next = &self.next[l..];

                    for i in 0..buf.len() {
                        out[i] = buf[i] as u8;
                    }
                    return;
                }
            }
            panic!("Invalid u8-array tag!");
        }

        fn read_arr_i16(&mut self, out: &mut [i16]) {
            if let Tag::Array(l, t) = self.cur {
                if let Tag::I16(0) = Tag::from(t) {
                    let l = l as usize;
                    let s = std::mem::size_of::<i16>();
                    let ret_size = l * s;
                    if out.len() < l {
                        panic!("Output buffer too small for i16-array");
                    }

                    let buf = &self.next[..ret_size];
                    self.next = &self.next[ret_size..];

                    for i in 0..l {
                        let j = i * s;
                        let arr = [buf[j], buf[j+1]];
                        out[i] = i16::from_be_bytes(arr);
                    }
                    return;
                }
            }
            panic!("Invalid i16-array tag!");
        }

        fn read_arr_u16(&mut self, out: &mut [u16]) {
            if let Tag::Array(l, t) = self.cur {
                if let Tag::U16(0) = Tag::from(t) {
                    let l = l as usize;
                    let s = std::mem::size_of::<u16>();
                    let ret_size = l * s;
                    if out.len() < l {
                        panic!("Output buffer too small for u16-array");
                    }

                    let buf = &self.next[..ret_size];
                    self.next = &self.next[ret_size..];

                    for i in 0..l {
                        let j = i * s;
                        let arr = [buf[j], buf[j+1]];
                        out[i] = u16::from_be_bytes(arr);
                    }
                    return;
                }
            }
            panic!("Invalid u16-array tag!");
        }

        fn read_arr_i32(&mut self, out: &mut [i32]) {
            if let Tag::Array(l, t) = self.cur {
                if let Tag::I32(0) = Tag::from(t) {
                    let l = l as usize;
                    let s = std::mem::size_of::<i32>();
                    let ret_size = l * s;
                    if out.len() < l {
                        panic!("Output buffer too small for i32-array");
                    }

                    let buf = &self.next[..ret_size];
                    self.next = &self.next[ret_size..];

                    for i in 0..l {
                        let j = i * s;
                        let arr = [buf[j], buf[j+1], buf[j+2], buf[j+3]];
                        out[i] = i32::from_be_bytes(arr);
                    }
                    return;
                }
            }
            panic!("Invalid i32-array tag!");
        }

        fn read_arr_u32(&mut self, out: &mut [u32]) {
            if let Tag::Array(l, t) = self.cur {
                if let Tag::U32(0) = Tag::from(t) {
                    let l = l as usize;
                    let s = std::mem::size_of::<u32>();
                    let ret_size = l * s;
                    if out.len() < l {
                        panic!("Output buffer too small for u32-array");
                    }

                    let buf = &self.next[..ret_size];
                    self.next = &self.next[ret_size..];

                    for i in 0..l {
                        let j = i * s;
                        let arr = [buf[j], buf[j+1], buf[j+2], buf[j+3]];
                        out[i] = u32::from_be_bytes(arr);
                    }
                    return;
                }
            }
            panic!("Invalid u32-array tag!");
        }

        fn read_arr_i64(&mut self, out: &mut [i64]) {
            if let Tag::Array(l, t) = self.cur {
                if let Tag::I64(0) = Tag::from(t) {
                    let l = l as usize;
                    let s = std::mem::size_of::<i64>();
                    let ret_size = l * s;
                    if out.len() < l {
                        panic!("Output buffer too small for i64-array");
                    }

                    let buf = &self.next[..ret_size];
                    self.next = &self.next[ret_size..];

                    for i in 0..l {
                        let j = i * s;
                        let arr = [buf[j], buf[j+1], buf[j+2], buf[j+3],
                                   buf[j+4], buf[j+5], buf[j+6], buf[j+7]];
                        out[i] = i64::from_be_bytes(arr);
                    }
                    return;
                }
            }
            panic!("Invalid i64-array tag!");
        }

        fn read_arr_u64(&mut self, out: &mut [u64]) {
            if let Tag::Array(l, t) = self.cur {
                if let Tag::U64(0) = Tag::from(t) {
                    let l = l as usize;
                    let s = std::mem::size_of::<u64>();
                    let ret_size = l * s;
                    if out.len() < l {
                        panic!("Output buffer too small for u64-array");
                    }

                    let buf = &self.next[..ret_size];
                    self.next = &self.next[ret_size..];

                    for i in 0..l {
                        let j = i * s;
                        let arr = [buf[j], buf[j+1], buf[j+2], buf[j+3],
                                   buf[j+4], buf[j+5], buf[j+6], buf[j+7]];
                        out[i] = u64::from_be_bytes(arr);
                    }
                    return;
                }
            }
            panic!("Invalid u64-array tag!");
        }

        fn read_arr_i128(&mut self, out: &mut [i128]) {
            if let Tag::Array(l, t) = self.cur {
                if let Tag::I128(0) = Tag::from(t) {
                    let l = l as usize;
                    let s = std::mem::size_of::<i128>();
                    let ret_size = l * s;
                    if out.len() < l {
                        panic!("Output buffer too small for i128-array");
                    }

                    let buf = &self.next[..ret_size];
                    self.next = &self.next[ret_size..];

                    for i in 0..l {
                        let j = i * s;
                        let arr = [buf[j], buf[j+1], buf[j+2], buf[j+3],
                                   buf[j+4], buf[j+5], buf[j+6], buf[j+7],
                                   buf[j+8], buf[j+9], buf[j+10], buf[j+11],
                                   buf[j+12], buf[j+13], buf[j+14], buf[j+15]];
                        out[i] = i128::from_be_bytes(arr);
                    }
                    return;
                }
            }
            panic!("Invalid i128-array tag!");
        }

        fn read_arr_u128(&mut self, out: &mut [u128]) {
            if let Tag::Array(l, t) = self.cur {
                if let Tag::U128(0) = Tag::from(t) {
                    let l = l as usize;
                    let s = std::mem::size_of::<u128>();
                    let ret_size = l * s;
                    if out.len() < l {
                        panic!("Output buffer too small for u128-array");
                    }

                    let buf = &self.next[..ret_size];
                    self.next = &self.next[ret_size..];

                    for i in 0..l {
                        let j = i * s;
                        let arr = [buf[j], buf[j+1], buf[j+2], buf[j+3],
                                   buf[j+4], buf[j+5], buf[j+6], buf[j+7],
                                   buf[j+8], buf[j+9], buf[j+10], buf[j+11],
                                   buf[j+12], buf[j+13], buf[j+14], buf[j+15]];
                        out[i] = u128::from_be_bytes(arr);
                    }
                    return;
                }
            }
            panic!("Invalid u128-array tag!");
        }

        fn read_arr_char(&mut self, out: &mut [char]) {
            if let Tag::Array(l, t) = self.cur {
                if let Tag::Char('\0') = Tag::from(t) {
                    let l = l as usize;
                    if out.len() < l {
                        panic!("Output buffer too small for char-array");
                    }

                    let buf = &self.next[..l];
                    self.next = &self.next[l..];

                    for i in 0..l {
                        out[i] = (buf[i] as char);
                    }
                    return;
                }
            }
            panic!("Invalid char-array tag!");
        }

        fn read_arr_bool(&mut self, out: &mut [bool]) {
            if let Tag::Array(l, t) = self.cur {
                if let Tag::Bool(false) = Tag::from(t) {
                    let l = l as usize;
                    if out.len() < l {
                        panic!("Output buffer too small for bool-array");
                    }

                    let buf = &self.next[..l];
                    self.next = &self.next[l..];

                    for i in 0..l {
                        out[i] = (buf[i] != 0);
                    }
                    return;
                }
            }
            panic!("Invalid bool-array tag!");
        }
    }

    #[test]
    fn tag_eq() {
        assert_eq!(Tag::I8(10), Tag::I8(10));
        assert_ne!(Tag::I8(8), Tag::I8(10));
        assert_ne!(Tag::U8(10), Tag::I8(10));
    }

    #[test]
    fn buf2tag() {
        let buf = [0, 0xff, // I8(-1)
                   0, 0x01, // I8(1)
                   1, 0xff, // U8(255)
                   1, 0x10, // U8(16)
                   2, 0xff, 0xff, // I16(-1)
                   2, 0x01, 0x00, // I16(256)
                   3, 0xff, 0xff, // U16(65535)
                   3, 0x10, 0x00, // U16(4096)
                   4, 0xff, 0xff, 0xff, 0xff, // I32(-1)
                   4, 0x01, 0x00, 0x20, 0x00, // I32(16785408)
                   5, 0xff, 0xff, 0xff, 0xff, // U32(4294967295)
                   5, 0x10, 0x02, 0x30, 0x00, // U32(268578816)
                   6, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // I64(-1)
                   6, 0x01, 0x00, 0x20, 0x00, 0x03, 0x00, 0x40, 0x00, // I64(72092778460364800)
                   7, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // U64(18446744073709551615)
                   7, 0x10, 0x02, 0x30, 0x04, 0x50, 0x06, 0x07, 0x00, // U64(1153537249640843008)
                   8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // I128(-1)
                   8, 0x01, 0x00, 0x20, 0x00, 0x03, 0x00, 0x40, 0x00, 0x05, 0x00, 0x60, 0x00, 0x07, 0x00, 0x80, 0x00, // I128(1329877033820989987636705759212896256)
                   9, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // U128(340282366920938463463374607431768211455)
                   9, 0x10, 0x02, 0x30, 0x04, 0x50, 0x06, 0x70, 0x08, 0x90, 0x0a, 0xb0, 0x0c, 0xd0, 0x0e, 0xf0, 0x00, // U128(21279006423615932362580302922658017280)
                   10, 0x61, // ord('a')
                   10, 0x41, // ord('A')
                   10, 0x00, // ord('\0')
                   10, 0x0a, // ord('\n')
                   10, 0x0d, // ord('\r')
                   11, 1,
                   11, 0,
                   11, 0x17,
                   12, 0x00, 0x00, 0x00, 0x07, 1 /* U8-Array */, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                   12, 0x00, 0x00, 0x00, 0x01, 5 /* U32-Array */, 0xff, 0x00, 0x00, 0x01,
                   12, 0x01, 0x02, 0x03, 0x04, 17, // NOTE: The tag isn't checked in the array
                  ];
        let res = [Tag::I8(-1),
                   Tag::I8(1),
                   Tag::U8(255),
                   Tag::U8(16),
                   Tag::I16(-1),
                   Tag::I16(256),
                   Tag::U16(65535),
                   Tag::U16(4096),
                   Tag::I32(-1),
                   Tag::I32(16785408),
                   Tag::U32(4294967295),
                   Tag::U32(268578816),
                   Tag::I64(-1),
                   Tag::I64(72092778460364800),
                   Tag::U64(18446744073709551615),
                   Tag::U64(1153537249640843008),
                   Tag::I128(-1),
                   Tag::I128(1329877033820989987636705759212896256),
                   Tag::U128(340282366920938463463374607431768211455),
                   Tag::U128(21279006423615932362580302922658017280),
                   Tag::Char('a'),
                   Tag::Char('A'),
                   Tag::Char('\0'),
                   Tag::Char('\n'),
                   Tag::Char('\r'),
                   Tag::Bool(true),
                   Tag::Bool(false),
                   Tag::Bool(true),
                   Tag::Array(7, 1),
                   Tag::Array(1, 5),
                   Tag::Array(16909060, 17), // NOTE: The tag isn't checked in the array
                  ];
        let extra_data = [
                          vec![Tag::U8(0x01), Tag::U8(0x02), Tag::U8(0x03), Tag::U8(0x04),
                               Tag::U8(0x05), Tag::U8(0x06), Tag::U8(0x07)],
                          vec![Tag::U32(0xff000001)],
                         ];
        let mut extra_data_idx = 0;
        use std::convert::TryFrom;
        let mut test_buf = &buf[..];
        for i in 0..res.len() {
            assert!(test_buf.len() > 0);
            let tp = TagParser::try_from(test_buf).expect("Invalid conversion");
            assert_eq!(tp.cur, res[i]);
            match tp.cur {
                Tag::Array(l, 1) => {
                    let l = l as usize;
                    let mut buf = std::vec::Vec::<u8>::with_capacity(l);
                    buf.resize(l, 0);
                    let mut tp = tp;
                    tp.read_arr_u8(&mut buf);
                    assert_eq!(buf.len(), extra_data[extra_data_idx].len());
                    for j in 0..buf.len() {
                        if let Tag::U8(v) = extra_data[extra_data_idx][j] {
                            assert_eq!(buf[j], v);
                        } else {
                            panic!("Invalid u8-array!");
                        }
                    }
                    test_buf = tp.next;
                    extra_data_idx += 1;
                },
                Tag::Array(l, 5) => {
                    let l = l as usize;
                    let mut buf = std::vec::Vec::<u32>::with_capacity(l);
                    buf.resize(l, 0);
                    let mut tp = tp;
                    tp.read_arr_u32(&mut buf);
                    assert_eq!(buf.len(), extra_data[extra_data_idx].len());
                    for j in 0..buf.len() {
                        if let Tag::U32(v) = extra_data[extra_data_idx][j] {
                            assert_eq!(buf[j], v);
                        } else {
                            panic!("Invalid u32-array!");
                        }
                    }
                    test_buf = tp.next;
                    extra_data_idx += 1;
                },
                _ => {
                    test_buf = tp.next;
                },
            }
        }
    }
}
