// Tag/Type Length Value encoder/decoder.
//
// The length is usually inferred from the type, except from array (which
// has a u32 for the number of elements following the tag).

use std::io::Write as _;

/// Valid types and their associated values.
///
/// A tag is encoded as a `u8` followed by its values, which is encoded
/// in big endian. For example, `Tag::u16(128)` would be encoded as
/// `[0x03, 0x00, 0x80]`, where the first `u8`, the value `0x03`, is
/// the tag, followed by the value 128.
///
/// Arrays are slightly different from other types. The first encoded
/// value is still the tag, but it's followed by the number of entries,
/// as an `u32`, followed by the type of the tag, as an `u8`. This type
/// may be converted into a zero-valued tag with the method
/// `Tag::from(v: u8)`. For example:
///
/// ```
/// let tag = Tag::Array(7, 5); // an u32 array with 7 values
/// if let Tag::Array(_, ut) = tag {
///     assert_eq!(Tag::U32(0), Tag::from(ut));
/// }
/// ```
///
/// After the tag, the content of the array is encoded in-place, in big
/// endian as well.
///
/// See the [TagParser] for descriptions and examples on how to decode
/// data.
pub enum Tag {
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
    Array(u32, u8),
    Invalid,
}

/// Enable generic decoding implementation of tags.
pub trait TagParseHelper<T> {
    /// Wraps `T` into a [Tag] of the given type.
    fn get_tag(v: T) -> Tag where T: Sized;
    /// Retrieves the zero [Tag] for the given type `T`.
    fn get_zero_tag() -> Tag;
    /// Retrieves the size in bytes of type `T`, when encoded.
    fn get_size() -> usize;
    /// Type's name (useful for more meaningful error messages).
    fn name() -> &'static str;
    /// Decodes a value `T` from an `u8` slice.
    fn from_buf(buf: &[u8]) -> T where T: Sized;
    /// Encodes a value `T` from into an `u8` slice, return the slice
    /// right after the encoded value.
    fn to_buf<'a>(v: T, buf: &'a mut [u8]) -> &'a mut [u8] where T: Sized;
}

impl TagParseHelper<u8> for u8 {
    fn get_tag(v: u8) -> Tag { Tag::U8(v) }
    fn get_zero_tag() -> Tag { Tag::U8(0) }
    fn get_size() -> usize { std::mem::size_of::<u8>() }
    fn name() -> &'static str { "u8" }
    fn from_buf(buf: &[u8]) -> u8 { buf[0] }
    fn to_buf<'a>(v: u8, buf: &'a mut [u8]) -> &'a mut [u8] {
        buf[0] = v;
        &mut buf[std::mem::size_of::<u8>()..]
    }
}
impl TagParseHelper<i8> for i8 {
    fn get_tag(v: i8) -> Tag { Tag::I8(v) }
    fn get_zero_tag() -> Tag { Tag::I8(0) }
    fn get_size() -> usize { std::mem::size_of::<i8>() }
    fn name() -> &'static str { "i8" }
    fn from_buf(buf: &[u8]) -> i8 { buf[0] as i8 }
    fn to_buf<'a>(v: i8, buf: &'a mut [u8]) -> &'a mut [u8] {
        buf[0] = v as u8;
        &mut buf[std::mem::size_of::<i8>()..]
    }
}
impl TagParseHelper<u16> for u16 {
    fn get_tag(v: u16) -> Tag { Tag::U16(v) }
    fn get_zero_tag() -> Tag { Tag::U16(0) }
    fn get_size() -> usize { std::mem::size_of::<u16>() }
    fn name() -> &'static str { "u16" }
    fn from_buf(buf: &[u8]) -> u16 {
        let arr = [buf[0], buf[1]];
        u16::from_be_bytes(arr)
    }
    fn to_buf<'a>(v: u16, buf: &'a mut [u8]) -> &'a mut [u8] {
        let mut writer = &mut buf[..];
        writer.write(&v.to_be_bytes()[..]).expect("Encoding failed for u16");
        &mut buf[std::mem::size_of::<u16>()..]
    }
}
impl TagParseHelper<i16> for i16 {
    fn get_tag(v: i16) -> Tag { Tag::I16(v) }
    fn get_zero_tag() -> Tag { Tag::I16(0) }
    fn get_size() -> usize { std::mem::size_of::<i16>() }
    fn name() -> &'static str { "i16" }
    fn from_buf(buf: &[u8]) -> i16 {
        let arr = [buf[0], buf[1]];
        i16::from_be_bytes(arr)
    }
    fn to_buf<'a>(v: i16, buf: &'a mut [u8]) -> &'a mut [u8] {
        let mut writer = &mut buf[..];
        writer.write(&v.to_be_bytes()[..]).expect("Encoding failed for i16");
        &mut buf[std::mem::size_of::<i16>()..]
    }
}
impl TagParseHelper<u32> for u32 {
    fn get_tag(v: u32) -> Tag { Tag::U32(v) }
    fn get_zero_tag() -> Tag { Tag::U32(0) }
    fn get_size() -> usize { std::mem::size_of::<u32>() }
    fn name() -> &'static str { "u32" }
    fn from_buf(buf: &[u8]) -> u32 {
        let arr = [buf[0], buf[1], buf[2], buf[3]];
        u32::from_be_bytes(arr)
    }
    fn to_buf<'a>(v: u32, buf: &'a mut [u8]) -> &'a mut [u8] {
        let mut writer = &mut buf[..];
        writer.write(&v.to_be_bytes()[..]).expect("Encoding failed for u32");
        &mut buf[std::mem::size_of::<u32>()..]
    }
}
impl TagParseHelper<i32> for i32 {
    fn get_tag(v: i32) -> Tag { Tag::I32(v) }
    fn get_zero_tag() -> Tag { Tag::I32(0) }
    fn get_size() -> usize { std::mem::size_of::<i32>() }
    fn name() -> &'static str { "i32" }
    fn from_buf(buf: &[u8]) -> i32 {
        let arr = [buf[0], buf[1], buf[2], buf[3]];
        i32::from_be_bytes(arr)
    }
    fn to_buf<'a>(v: i32, buf: &'a mut [u8]) -> &'a mut [u8] {
        let mut writer = &mut buf[..];
        writer.write(&v.to_be_bytes()[..]).expect("Encoding failed for i32");
        &mut buf[std::mem::size_of::<i32>()..]
    }
}
impl TagParseHelper<u64> for u64 {
    fn get_tag(v: u64) -> Tag { Tag::U64(v) }
    fn get_zero_tag() -> Tag { Tag::U64(0) }
    fn get_size() -> usize { std::mem::size_of::<u64>() }
    fn name() -> &'static str { "u64" }
    fn from_buf(buf: &[u8]) -> u64 {
        let arr = [buf[0], buf[1], buf[2], buf[3],
                   buf[4], buf[5], buf[6], buf[7]];
        u64::from_be_bytes(arr)
    }
    fn to_buf<'a>(v: u64, buf: &'a mut [u8]) -> &'a mut [u8] {
        let mut writer = &mut buf[..];
        writer.write(&v.to_be_bytes()[..]).expect("Encoding failed for u64");
        &mut buf[std::mem::size_of::<u64>()..]
    }
}
impl TagParseHelper<i64> for i64 {
    fn get_tag(v: i64) -> Tag { Tag::I64(v) }
    fn get_zero_tag() -> Tag { Tag::I64(0) }
    fn get_size() -> usize { std::mem::size_of::<i64>() }
    fn name() -> &'static str { "i64" }
    fn from_buf(buf: &[u8]) -> i64 {
        let arr = [buf[0], buf[1], buf[2], buf[3],
                   buf[4], buf[5], buf[6], buf[7]];
        i64::from_be_bytes(arr)
    }
    fn to_buf<'a>(v: i64, buf: &'a mut [u8]) -> &'a mut [u8] {
        let mut writer = &mut buf[..];
        writer.write(&v.to_be_bytes()[..]).expect("Encoding failed for i64");
        &mut buf[std::mem::size_of::<i64>()..]
    }
}
impl TagParseHelper<u128> for u128 {
    fn get_tag(v: u128) -> Tag { Tag::U128(v) }
    fn get_zero_tag() -> Tag { Tag::U128(0) }
    fn get_size() -> usize { std::mem::size_of::<u128>() }
    fn name() -> &'static str { "u128" }
    fn from_buf(buf: &[u8]) -> u128 {
        let arr = [buf[0], buf[1], buf[2], buf[3],
                   buf[4], buf[5], buf[6], buf[7],
                   buf[8], buf[9], buf[10], buf[11],
                   buf[12], buf[13], buf[14], buf[15]];
        u128::from_be_bytes(arr)
    }
    fn to_buf<'a>(v: u128, buf: &'a mut [u8]) -> &'a mut [u8] {
        let mut writer = &mut buf[..];
        writer.write(&v.to_be_bytes()[..]).expect("Encoding failed for u128");
        &mut buf[std::mem::size_of::<u128>()..]
    }
}
impl TagParseHelper<i128> for i128 {
    fn get_tag(v: i128) -> Tag { Tag::I128(v) }
    fn get_zero_tag() -> Tag { Tag::I128(0) }
    fn get_size() -> usize { std::mem::size_of::<i128>() }
    fn name() -> &'static str { "i128" }
    fn from_buf(buf: &[u8]) -> i128 {
        let arr = [buf[0], buf[1], buf[2], buf[3],
                   buf[4], buf[5], buf[6], buf[7],
                   buf[8], buf[9], buf[10], buf[11],
                   buf[12], buf[13], buf[14], buf[15]];
        i128::from_be_bytes(arr)
    }
    fn to_buf<'a>(v: i128, buf: &'a mut [u8]) -> &'a mut [u8] {
        let mut writer = &mut buf[..];
        writer.write(&v.to_be_bytes()[..]).expect("Encoding failed for i128");
        &mut buf[std::mem::size_of::<i128>()..]
    }
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

/// Converts an `u8` into its zero-valued tag.
///
/// This method is mostly useful to retrieve the tag of a decoded
/// array. See [Tag] for an example.
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
            0x0A => Tag::Array(0, 0),
            _    => Tag::Invalid,
        }
    }
}

impl Tag {
    /// Retrieves the length in bytes required by the value encoded by
    /// this Tag.
    ///
    /// For `Tag::Array`, this only represents the length of the tag
    /// object (i.e., the number of items and the type of the items).
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
            Tag::Array(_, _) => 4 + 1,
            _ => return 0,
        }
    }

    /// Retrieves the enumeration identifier, as used to encode it.
    pub fn enum_id(&self) -> u8 {
        match self {
            Tag::I8(0) => 0x00,
            Tag::U8(0) => 0x01,
            Tag::I16(0) => 0x02,
            Tag::U16(0) => 0x03,
            Tag::I32(0) => 0x04,
            Tag::U32(0) => 0x05,
            Tag::I64(0) => 0x06,
            Tag::U64(0) => 0x07,
            Tag::I128(0) => 0x08,
            Tag::U128(0) => 0x09,
            Tag::Array(0, 0) => 0x0A,
            _    => 0,
        }
    }
}

/// Converts the given `u8` slice into a tag of the requested type.
fn tag_from_buf<T>(buf: &[u8]) -> Tag
where
    T: TagParseHelper<T>
{
    T::get_tag(T::from_buf(buf))
}

/// Retrieves the size of the buffer required to encode the given type.
pub fn get_encoded_size<T>() -> usize
where
    T: TagParseHelper<T>
{
    1 + T::get_size()
}

/// Retrieves the size of the buffer required to encode the given array.
pub fn get_encoded_arr_size<T>(v: &[T]) -> usize
where
    T: TagParseHelper<T>
{
    1 + u32::get_size() + 1 + v.len() * T::get_size()
}

/// Generate a Vec::<u8> big enough to hold tags of the supplied types.
#[macro_export]
macro_rules! gen_buffer {
    ( $( $x:ty ),* ) => {
        {
            let mut size = 0;
            $(
                size = size + tlv::get_encoded_size::<$x>();
            )*
            let mut buf = std::vec::Vec::<u8>::with_capacity(size);
            buf.resize(size, 0);
            buf
        }
    };
}

/// Encodes a value into a buffer, and returns the slice where more data
/// may be encoded.
///
/// # Panics
///
/// Panics if the buffer isn't big enough. Use [get_encoded_size] when
/// reserving memory for the buffer.
///
/// # Examples
///
/// ```
/// // Encode an u8 followed by an i32
/// let size = get_encoded_size::<u8>() + get_encoded_size::<u32>();
/// let mut buf = std::vec::Vec::<u8>::with_capacity(size);
/// buf.resize(size, 0);
///
/// let next = buf.as_mut_slice();
/// let next = encode::<u8>(0, next);
/// encode::<i32>(-1, next);
/// ```
fn encode<'a, T>(v: T, buf: &'a mut [u8]) -> &'a mut [u8]
where
    T: TagParseHelper<T>
{
    if buf.len() < get_encoded_size::<T>() {
        panic!("Buffer too small for {}-tag", T::name());
    }
    let next = u8::to_buf(T::get_zero_tag().enum_id(), buf);
    let next = T::to_buf(v, next);
    return next;
}

/// Encodes an array into a buffer, and returns the slice where more data
/// may be encoded.
///
/// # Panics
///
/// Panics if the buffer isn't big enough. Use [get_encoded_arr_size] when
/// reserving memory for the buffer.
///
/// # Examples
///
/// ```
/// // Encode an array of u64 followed by an i16
/// let arr: [u64; 3] = [0; 3];
/// let size = get_encoded_arr_size::<u64>(&arr[..]);
/// let size = size + get_encoded_size::<i16>();
/// let mut buf = std::vec::Vec::<u8>::with_capacity(size);
/// buf.resize(size, 0);
///
/// let next = buf.as_mut_slice();
/// let next = encode_arr::<u64>(&arr[..], next);
/// encode::<i16>(-1, next);
/// ```
fn encode_arr<'a, T>(v: &[T], buf: &'a mut [u8]) -> &'a mut [u8]
where
    T: TagParseHelper<T> + Copy
{
    let exp = get_encoded_arr_size::<T>(v);
    if buf.len() < exp {
        panic!("Buffer too small for {}-tag'ed array (exp: {}, got: {})",
                T::name(), exp, buf.len());
    }
    let next = u8::to_buf(Tag::Array(0, 0).enum_id(), buf);
    let next = u32::to_buf(v.len() as u32, next);
    let next = u8::to_buf(T::get_zero_tag().enum_id(), next);
    let mut next = next;
    for i in 0..v.len() {
        next = T::to_buf(v[i], next);
    }
    return next;
}

impl std::convert::From<&Tag> for i8 {
    fn from(t: &Tag) -> Self {
        match t {
            Tag::I8(v) => *v,
            _ => panic!("Not an i8 tag!"),
        }
    }
}
impl std::convert::From<&Tag> for u8 {
    fn from(t: &Tag) -> Self {
        match t {
            Tag::U8(v) => *v,
            _ => panic!("Not an u8 tag!"),
        }
    }
}
impl std::convert::From<&Tag> for i16 {
    fn from(t: &Tag) -> Self {
        match t {
            Tag::I16(v) => *v,
            _ => panic!("Not an i16 tag!"),
        }
    }
}
impl std::convert::From<&Tag> for u16 {
    fn from(t: &Tag) -> Self {
        match t {
            Tag::U16(v) => *v,
            _ => panic!("Not an u16 tag!"),
        }
    }
}
impl std::convert::From<&Tag> for i32 {
    fn from(t: &Tag) -> Self {
        match t {
            Tag::I32(v) => *v,
            _ => panic!("Not an i32 tag!"),
        }
    }
}
impl std::convert::From<&Tag> for u32 {
    fn from(t: &Tag) -> Self {
        match t {
            Tag::U32(v) => *v,
            _ => panic!("Not an u32 tag!"),
        }
    }
}
impl std::convert::From<&Tag> for i64 {
    fn from(t: &Tag) -> Self {
        match t {
            Tag::I64(v) => *v,
            _ => panic!("Not an i64 tag!"),
        }
    }
}
impl std::convert::From<&Tag> for u64 {
    fn from(t: &Tag) -> Self {
        match t {
            Tag::U64(v) => *v,
            _ => panic!("Not an u64 tag!"),
        }
    }
}
impl std::convert::From<&Tag> for i128 {
    fn from(t: &Tag) -> Self {
        match t {
            Tag::I128(v) => *v,
            _ => panic!("Not an i128 tag!"),
        }
    }
}
impl std::convert::From<&Tag> for u128 {
    fn from(t: &Tag) -> Self {
        match t {
            Tag::U128(v) => *v,
            _ => panic!("Not an u128 tag!"),
        }
    }
}

/// Value decoded from a buffer and any trailing data still in the
/// buffer.
///
/// `TagParser` should only be retrieved by calling
/// `TagParser::try_from`. On success, this will retrieve the decoded
/// tag, in `TagParser.cur`, and the unread portion of the buffer, in
/// `TagParser.next`.
///
/// For integer built-in types (i.e., u8, i32 etc), the decoded value shall
/// be retrieved directly from the decoded tag. However, arrays require an
/// extra call to [TagParser.read_arr], which read the array and advances
/// the buffer to the next unread portion.
///
/// #Example
///
/// ```
/// use std::convert::TryFrom;
///
/// // Input buffer, with values to be decoded
/// let buf = [1, 0xff, // U8(255)
///            4, 0xff, 0xff, 0xff, 0xff, // I32(-1)
///            10, 0x00, 0x00, 0x00, 0x02, 5, // U32-Array
///                0xff, 0x00, 0x00, 0x01,    // first item
///                0x01, 0x02, 0x03, 0x04,    // second item
///            2, 0xff, 0xff, // I16(-1)
///           ];
///
/// // Try to decode the basic values
/// let tp = TagParser::try_from(&buf[..]).unwrap();
/// assert_eq!(tp.cur, Tag::U8(255));
/// let tp = TagParser::try_from(tp.next).unwrap();
/// assert_eq!(tp.cur, Tag::I32(-1));
///
/// // Try to decode, and check the type (in a redundant way), an array
/// let tp = TagParser::try_from(tp.next).unwrap();
/// assert_eq!(tp.cur, Tag::Array(2, 5));
/// if let Tag::Array(_, t) = tp.cur {
///     assert_eq!(Tag::U32(0), Tag::from(t));
/// } else {
///     assert!(false);
/// }
/// // Read the array's content
/// let mut u32arr: [u32; 2] = [0, 0];
/// let mut tp = tp;
/// tp.read_arr::<u32>(&mut u32arr);
/// assert_eq!(u32arr[0], 0xff000001);
/// assert_eq!(u32arr[1], 0x01020304);
///
/// // Decode the rest of the buffer
/// let tp = TagParser::try_from(tp.next).unwrap();
/// assert_eq!(tp.cur, Tag::I16(-1));
///
/// // Ensure that the buffer was completely consume
/// assert_eq!(tp.next.len(), 0);
/// ```
pub struct TagParser<'a: 'b, 'b> {
    /// The tag decoded from the buffer, and its value.
    cur: Tag,
    /// Unread portion of the buffer. Should be passed to
    /// `TagParser::try_from`, to continue decoding the buffer.
    next: &'a[u8],
    /// Forces the parser to have a smaller lifetime than the parsing
    /// slice.
    phanthom: std::marker::PhantomData<&'b()>,
}

impl std::convert::From<&TagParser<'_, '_>> for i8 {
    fn from(tp: &TagParser<'_, '_>) -> i8 {
        i8::from(&tp.cur)
    }
}
impl std::convert::From<&TagParser<'_, '_>> for u8 {
    fn from(tp: &TagParser<'_, '_>) -> u8 {
        u8::from(&tp.cur)
    }
}
impl std::convert::From<&TagParser<'_, '_>> for i16 {
    fn from(tp: &TagParser<'_, '_>) -> i16 {
        i16::from(&tp.cur)
    }
}
impl std::convert::From<&TagParser<'_, '_>> for u16 {
    fn from(tp: &TagParser<'_, '_>) -> u16 {
        u16::from(&tp.cur)
    }
}
impl std::convert::From<&TagParser<'_, '_>> for i32 {
    fn from(tp: &TagParser<'_, '_>) -> i32 {
        i32::from(&tp.cur)
    }
}
impl std::convert::From<&TagParser<'_, '_>> for u32 {
    fn from(tp: &TagParser<'_, '_>) -> u32 {
        u32::from(&tp.cur)
    }
}
impl std::convert::From<&TagParser<'_, '_>> for i64 {
    fn from(tp: &TagParser<'_, '_>) -> i64 {
        i64::from(&tp.cur)
    }
}
impl std::convert::From<&TagParser<'_, '_>> for u64 {
    fn from(tp: &TagParser<'_, '_>) -> u64 {
        u64::from(&tp.cur)
    }
}
impl std::convert::From<&TagParser<'_, '_>> for i128 {
    fn from(tp: &TagParser<'_, '_>) -> i128 {
        i128::from(&tp.cur)
    }
}
impl std::convert::From<&TagParser<'_, '_>> for u128 {
    fn from(tp: &TagParser<'_, '_>) -> u128 {
        u128::from(&tp.cur)
    }
}

impl<'a: 'b, 'b> std::convert::TryFrom<&'a[u8]> for TagParser<'a, 'b> {
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
            Tag::I8(_) => cur = tag_from_buf::<i8>(buf),
            Tag::U8(_) => cur = tag_from_buf::<u8>(buf),
            Tag::I16(_) => cur = tag_from_buf::<i16>(buf),
            Tag::U16(_) => cur = tag_from_buf::<u16>(buf),
            Tag::I32(_) => cur = tag_from_buf::<i32>(buf),
            Tag::U32(_) => cur = tag_from_buf::<u32>(buf),
            Tag::I64(_) => cur = tag_from_buf::<i64>(buf),
            Tag::U64(_) => cur = tag_from_buf::<u64>(buf),
            Tag::I128(_) => cur = tag_from_buf::<i128>(buf),
            Tag::U128(_) => cur = tag_from_buf::<u128>(buf),
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
            phanthom: std::marker::PhantomData,
        };
        return Ok(tp);
    }
}

impl<'a: 'b, 'b> TagParser<'a, 'b> {
    /// Reads the content of a `Tag::Array` into `out`, advancing
    /// `TagParser.next` to any trailing data after the last item.
    fn read_arr<T>(&mut self, out: &mut [T])
    where
        T: TagParseHelper<T>
    {
        if let Tag::Array(l, t) = self.cur {
            if T::get_zero_tag() == Tag::from(t) {
                let l = l as usize;
                let s = T::get_size();
                let ret_size = l * s;
                if out.len() < l {
                    panic!("Output buffer too small for {}-array", T::name());
                }

                let buf = &self.next[..ret_size];
                self.next = &self.next[ret_size..];

                for i in 0..l {
                    let j = i * s;
                    out[i] = T::from_buf(&buf[j..]);
                }
                return;
            }
        }
        panic!("Invalid {}-array tag!", T::name());
    }

    pub fn get_next(&'b self) -> &'a[u8] {
        return self.next;
    }
}

#[cfg(test)]
mod test {
    use crate::tlv::Tag;
    use crate::tlv::TagParser;
    use crate::tlv::get_encoded_size;
    use crate::tlv::get_encoded_arr_size;
    use crate::tlv::encode;
    use crate::tlv::encode_arr;
    use crate::tlv::TagParseHelper;

    static TEST_BUF : [u8; 167] = [
         0, 0xff, // I8(-1)
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
         6, 0xff, 0xff, 0xff, 0xff, // I64(-1)
            0xff, 0xff, 0xff, 0xff,
         6, 0x01, 0x00, 0x20, 0x00, // I64(72092778460364800)
            0x03, 0x00, 0x40, 0x00,
         7, 0xff, 0xff, 0xff, 0xff, // U64(18446744073709551615)
            0xff, 0xff, 0xff, 0xff,
         7, 0x10, 0x02, 0x30, 0x04, // U64(1153537249640843008)
            0x50, 0x06, 0x07, 0x00,
         8, 0xff, 0xff, 0xff, 0xff, // I128(-1)
            0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff,
         8, 0x01, 0x00, 0x20, 0x00, // I128(1329877033820989987636705759212896256)
            0x03, 0x00, 0x40, 0x00,
            0x05, 0x00, 0x60, 0x00,
            0x07, 0x00, 0x80, 0x00,
         9, 0xff, 0xff, 0xff, 0xff, // U128(340282366920938463463374607431768211455)
            0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff,
         9, 0x10, 0x02, 0x30, 0x04, // U128(21279006423615932362580302922658017280)
            0x50, 0x06, 0x70, 0x08,
            0x90, 0x0a, 0xb0, 0x0c,
            0xd0, 0x0e, 0xf0, 0x00,
        10, 0x00, 0x00, 0x00, 0x07, 1 /* U8-Array */,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        10, 0x00, 0x00, 0x00, 0x01, 5 /* U32-Array */,
            0xff, 0x00, 0x00, 0x01,
   ];

    #[test]
    fn tag_eq() {
        assert_eq!(Tag::I8(10), Tag::I8(10));
        assert_ne!(Tag::I8(8), Tag::I8(10));
        assert_ne!(Tag::U8(10), Tag::I8(10));
    }

    #[test]
    fn buf2tag() {
        let buf = TEST_BUF;
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
                   Tag::Array(7, 1),
                   Tag::Array(1, 5),
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
                    tp.read_arr::<u8>(&mut buf);
                    assert_eq!(buf.len(), extra_data[extra_data_idx].len());
                    for j in 0..buf.len() {
                        let tag = &extra_data[extra_data_idx][j];
                        let v = u8::from(tag);
                        assert_eq!(buf[j], v);
                    }
                    test_buf = tp.next;
                    extra_data_idx += 1;
                },
                Tag::Array(l, 5) => {
                    let l = l as usize;
                    let mut buf = std::vec::Vec::<u32>::with_capacity(l);
                    buf.resize(l, 0);
                    let mut tp = tp;
                    tp.read_arr::<u32>(&mut buf);
                    assert_eq!(buf.len(), extra_data[extra_data_idx].len());
                    for j in 0..buf.len() {
                        let tag = &extra_data[extra_data_idx][j];
                        let v = u32::from(tag);
                        assert_eq!(buf[j], v);
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

    #[test]
    fn try_from_example() {
        use std::convert::TryFrom;

        // Input buffer, with values to be decoded
        let buf = [1, 0xff, // U8(255)
                   4, 0xff, 0xff, 0xff, 0xff, // I32(-1)
                   10, 0x00, 0x00, 0x00, 0x02, 5, // U32-Array
                       0xff, 0x00, 0x00, 0x01,    // first item
                       0x01, 0x02, 0x03, 0x04,    // second item
                   2, 0xff, 0xff, // I16(-1)
                  ];

        // Try to decode the basic values
        let tp = TagParser::try_from(&buf[..]).unwrap();
        assert_eq!(tp.cur, Tag::U8(255));
        let tp = TagParser::try_from(tp.next).unwrap();
        assert_eq!(tp.cur, Tag::I32(-1));

        // Try to decode, and check the type (in a redundant way), an array
        let tp = TagParser::try_from(tp.next).unwrap();
        assert_eq!(tp.cur, Tag::Array(2, 5));
        if let Tag::Array(_, t) = tp.cur {
            assert_eq!(Tag::U32(0), Tag::from(t));
        } else {
            assert!(false);
        }
        // Read the array's content
        let mut u32arr: [u32; 2] = [0, 0];
        let mut tp = tp;
        tp.read_arr::<u32>(&mut u32arr);
        assert_eq!(u32arr[0], 0xff000001);
        assert_eq!(u32arr[1], 0x01020304);

        // Decode the rest of the buffer
        let tp = TagParser::try_from(tp.next).unwrap();
        assert_eq!(tp.cur, Tag::I16(-1));

        // Ensure that the buffer was completely consume
        assert_eq!(tp.next.len(), 0);
    }

    #[test]
    fn encode_example() {
        // fn encode example:

        // Encode an u8 followed by an i32
        let size = get_encoded_size::<u8>() + get_encoded_size::<u32>();
        let mut buf = std::vec::Vec::<u8>::with_capacity(size);
        buf.resize(size, 0);

        let next = buf.as_mut_slice();
        let next = encode::<u8>(0, next);
        encode::<i32>(-1, next);

        // fn encode_arr example:

        // Encode an array of u64 followed by an i16
        let arr: [u64; 3] = [0; 3];
        let size = get_encoded_arr_size::<u64>(&arr[..]);
        let size = size + get_encoded_size::<i16>();
        let mut buf = std::vec::Vec::<u8>::with_capacity(size);
        buf.resize(size, 0);

        let next = buf.as_mut_slice();
        let next = encode_arr::<u64>(&arr[..], next);
        encode::<i16>(-1, next);
    }

    #[test]
    fn encode_test() {
        let exp_buf = TEST_BUF;
        let mut buf = std::vec::Vec::<u8>::with_capacity(exp_buf.len());
        buf.resize(exp_buf.len(), 0);

        let next = buf.as_mut_slice();
        assert_eq!(exp_buf.len(), next.len());

        let last_len = next.len();
        let next = encode::<i8>(-1, next);
        assert_eq!(next.len(), (last_len - 1 - i8::get_size()));

        let last_len = next.len();
        let next = encode::<i8>(1, next);
        assert_eq!(next.len(), (last_len - 1 - i8::get_size()));

        let last_len = next.len();
        let next = encode::<u8>(0xff, next);
        assert_eq!(next.len(), (last_len - 1 - u8::get_size()));

        let last_len = next.len();
        let next = encode::<u8>(16, next);
        assert_eq!(next.len(), (last_len - 1 - u8::get_size()));

        let last_len = next.len();
        let next = encode::<i16>(-1, next);
        assert_eq!(next.len(), (last_len - 1 - i16::get_size()));

        let last_len = next.len();
        let next = encode::<i16>(256, next);
        assert_eq!(next.len(), (last_len - 1 - i16::get_size()));

        let last_len = next.len();
        let next = encode::<u16>(0xff_ff, next);
        assert_eq!(next.len(), (last_len - 1 - u16::get_size()));

        let last_len = next.len();
        let next = encode::<u16>(0x10_00, next);
        assert_eq!(next.len(), (last_len - 1 - u16::get_size()));

        let last_len = next.len();
        let next = encode::<i32>(-1, next);
        assert_eq!(next.len(), (last_len - 1 - i32::get_size()));

        let last_len = next.len();
        let next = encode::<i32>(0x01_00_20_00, next);
        assert_eq!(next.len(), (last_len - 1 - i32::get_size()));

        let last_len = next.len();
        let next = encode::<u32>(0xff_ff_ff_ff, next);
        assert_eq!(next.len(), (last_len - 1 - u32::get_size()));

        let last_len = next.len();
        let next = encode::<u32>(0x10_02_30_00, next);
        assert_eq!(next.len(), (last_len - 1 - u32::get_size()));

        let last_len = next.len();
        let next = encode::<i64>(-1, next);
        assert_eq!(next.len(), (last_len - 1 - i64::get_size()));

        let last_len = next.len();
        let next = encode::<i64>(0x01_00_20_00_03_00_40_00, next);
        assert_eq!(next.len(), (last_len - 1 - i64::get_size()));

        let last_len = next.len();
        let next = encode::<u64>(0xff_ff_ff_ff_ff_ff_ff_ff, next);
        assert_eq!(next.len(), (last_len - 1 - u64::get_size()));

        let last_len = next.len();
        let next = encode::<u64>(0x10_02_30_04_50_06_07_00, next);
        assert_eq!(next.len(), (last_len - 1 - u64::get_size()));

        let last_len = next.len();
        let next = encode::<i128>(-1, next);
        assert_eq!(next.len(), (last_len - 1 - i128::get_size()));

        let last_len = next.len();
        let next = encode::<i128>(0x01_00_20_00_03_00_40_00_05_00_60_00_07_00_80_00, next);
        assert_eq!(next.len(), (last_len - 1 - i128::get_size()));

        let last_len = next.len();
        let next = encode::<u128>(0xff_ff_ff_ff_ff_ff_ff_ff_ff_ff_ff_ff_ff_ff_ff_ff, next);
        assert_eq!(next.len(), (last_len - 1 - u128::get_size()));

        let last_len = next.len();
        let next = encode::<u128>(0x10_02_30_04_50_06_70_08_90_0a_b0_0c_d0_0e_f0_00, next);
        assert_eq!(next.len(), (last_len - 1 - u128::get_size()));

        let last_len = next.len();
        let _u8: [u8; 7] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let next = encode_arr::<u8>(&_u8[..], next);
        let exp = last_len - 2 - u32::get_size() - _u8.len();
        assert_eq!(next.len(), exp);

        let last_len = next.len();
        let _u32: [u32; 1] = [0xff_00_00_01];
        let next = encode_arr::<u32>(&_u32[..], next);
        let exp = last_len - 2 - u32::get_size() * (1 + _u32.len());
        assert_eq!(next.len(), exp);

        let cmp = buf.as_slice();
        for i in 0..cmp.len() {
            assert_eq!(cmp[i], exp_buf[i]);
        }
    }
}
