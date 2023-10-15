// copyright 2023 Remi Bernotavicius

use pretty_assertions::assert_eq;
use serde_smb::{DeserializeSmbEnum, DeserializeSmbStruct, SerializeSmbEnum, SerializeSmbStruct};

fn assert_bytes_equal(expected: &[u8], actual: &[u8]) {
    if expected != actual {
        assert_eq!(
            format!("{expected:x?}"),
            format!("{actual:x?}"),
            "expected != actual"
        );
    }
}

#[derive(Debug, PartialEq, SerializeSmbStruct, DeserializeSmbStruct)]
#[smb(size = "14 + self.e.len()")]
struct SimpleCollection {
    a: u16,
    b: u16,
    #[smb(pad = 4)]
    c: u16,
    d: u16,
    #[smb(collection(
        count(int_type = "u16", after = "c"),
        offset(int_type = "u16", after = "e_count", value = 0x10)
    ))]
    e: Vec<u8>,
}

#[test]
fn serialize_deserialize() {
    let f = SimpleCollection {
        a: 0x1122,
        b: 0xFFAA,
        c: 0xBBCC,
        d: 0xDDEE,
        e: vec![0x1, 0x2],
    };

    let actual = serde_smb::to_vec(&f).unwrap();

    let expected = [
        0x10, 0x00, // size
        0x22, 0x11, // a
        0xAA, 0xFF, // b
        0x00, 0x00, // padding
        0xCC, 0xBB, // c
        0x2, 0x0, // e_count
        0x10, 0x0, // e_offset
        0xEE, 0xDD, // d
        0x1, 0x2, // e
    ];
    assert_bytes_equal(&expected, &actual);

    let deserialized: SimpleCollection = serde_smb::from_slice(&expected[..]).unwrap();
    assert_eq!(deserialized, f);
}

#[derive(Debug, PartialEq, SerializeSmbStruct, DeserializeSmbStruct)]
#[smb(next_entry_offset = 12)]
struct Element {
    a: u32,
}

#[derive(Debug, PartialEq, SerializeSmbStruct, DeserializeSmbStruct)]
struct CollectionWithBytes {
    a: u16,
    #[smb(collection(count(
        int_type = "u16",
        after = "a",
        value = "self.e.len() * 12 - 4",
        as_bytes = true
    )))]
    e: Vec<Element>,
}

#[test]
fn collection_with_bytes() {
    let f = CollectionWithBytes {
        a: 0x1122,
        e: vec![Element { a: 0x33445566 }, Element { a: 0x778899aa }],
    };

    let actual = serde_smb::to_vec(&f).unwrap();

    let expected = [
        0x22, 0x11, // a
        0x14, 0x0, // e_count
        0xc, 0x0, 0x0, 0x0, // e[0] next_entry_offset
        0x66, 0x55, 0x44, 0x33, // e[0] a
        0x0, 0x0, 0x0, 0x0, // e[0] padding
        0x0, 0x0, 0x0, 0x0, // e[1] next_entry_offset
        0xaa, 0x99, 0x88, 0x77, // e[1] a
    ];
    assert_bytes_equal(&expected, &actual);

    let deserialized: CollectionWithBytes = serde_smb::from_slice(&expected[..]).unwrap();
    assert_eq!(deserialized, f);
}

#[derive(Debug, PartialEq, SerializeSmbStruct, DeserializeSmbStruct)]
struct StructWithString {
    a: u16,
    #[smb(collection(count(int_type = "u16", after = "a", element_size = 2)))]
    e: String,
}

#[test]
fn struct_with_string() {
    let f = StructWithString {
        a: 0x1122,
        e: "hi".into(),
    };

    let actual = serde_smb::to_vec(&f).unwrap();

    let expected = [
        0x22, 0x11, // a
        0x4, 0x0, // e_count
        0x68, 0x0, // e[0]
        0x69, 0x0, // e[1]
    ];
    assert_bytes_equal(&expected, &actual);

    let deserialized: StructWithString = serde_smb::from_slice(&expected[..]).unwrap();
    assert_eq!(deserialized, f);
}

#[derive(Debug, PartialEq, SerializeSmbStruct, DeserializeSmbStruct)]
struct ExtremeOffset {
    a: u16,
    #[smb(collection(
        count(int_type = "u16", after = "a"),
        offset(int_type = "u16", after = "e_count", value = 0x10)
    ))]
    e: Vec<u8>,
}

#[test]
fn extreme_offset() {
    let f = ExtremeOffset {
        a: 0x1122,
        e: vec![0x1, 0x2, 0x3],
    };

    let actual = serde_smb::to_vec(&f).unwrap();

    let expected = [
        0x22, 0x11, // a
        0x3, 0x0, // e_count
        0x10, 0x0, // e_offset
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // padding
        0x1, 0x2, 0x3, // e
    ];
    assert_bytes_equal(&expected, &actual);

    let deserialized: ExtremeOffset = serde_smb::from_slice(&expected[..]).unwrap();
    assert_eq!(deserialized, f);
}

#[derive(Debug, PartialEq, SerializeSmbStruct, DeserializeSmbStruct)]
#[smb(pad = 4)]
struct PaddedElement {
    a: u16,
}

#[derive(Debug, PartialEq, SerializeSmbStruct, DeserializeSmbStruct)]
struct InterestingPadding {
    a: u16,
    // e_count: u32
    b: u16,
    #[smb(pad = 4)]
    c: u16,
    #[smb(collection(count(int_type = "u32", after = "a")))]
    e: Vec<PaddedElement>,
}

#[test]
fn interesting_padding() {
    let f = InterestingPadding {
        a: 0x1122,
        b: 0x3344,
        c: 0x5566,
        e: vec![PaddedElement { a: 0x7788 }, PaddedElement { a: 0x99aa }],
    };

    let actual = serde_smb::to_vec(&f).unwrap();

    let expected = [
        0x22, 0x11, // a
        0x0, 0x0, // padding
        0x2, 0x0, 0x0, 0x0, // e_count
        0x44, 0x33, // b
        0x0, 0x0, // padding
        0x66, 0x55, // c
        0x0, 0x0, // padding
        0x88, 0x77, // e[0]
        0x0, 0x0, // padding
        0xaa, 0x99, // e[1]
    ];
    assert_bytes_equal(&expected, &actual);

    let deserialized: InterestingPadding = serde_smb::from_slice(&expected[..]).unwrap();
    assert_eq!(deserialized, f);
}

#[derive(Debug, PartialEq, SerializeSmbStruct, DeserializeSmbStruct)]
struct InsertReserved {
    a: u16,
    #[smb(insert_reserved(name = "foo", int_type = "u32"))]
    b: u16,
    #[smb(insert_reserved(name = "bar", int_type = "u16"))]
    c: u16,
}

#[test]
fn insert_reserved() {
    let f = InsertReserved {
        a: 0x1122,
        b: 0x3344,
        c: 0x5566,
    };

    let actual = serde_smb::to_vec(&f).unwrap();

    let expected = [
        0x22, 0x11, // a
        0x0, 0x0, // padding
        0x0, 0x0, 0x0, 0x0, // foo
        0x44, 0x33, // b
        0x0, 0x0, // bar
        0x66, 0x55, // c
    ];
    assert_bytes_equal(&expected, &actual);

    let deserialized: InsertReserved = serde_smb::from_slice(&expected[..]).unwrap();
    assert_eq!(deserialized, f);
}

#[derive(Debug, PartialEq, SerializeSmbStruct, DeserializeSmbStruct)]
struct InsertReservedAfter {
    a: u16,
    #[smb(insert_reserved(name = "foo", int_type = "u16", after = true))]
    b: u16,
    #[smb(insert_reserved(name = "bar", int_type = "u16", after = true))]
    c: u16,
}

#[test]
fn insert_reserved_after() {
    let f = InsertReservedAfter {
        a: 0x1122,
        b: 0x3344,
        c: 0x5566,
    };

    let actual = serde_smb::to_vec(&f).unwrap();

    let expected = [
        0x22, 0x11, // a
        0x44, 0x33, // b
        0x00, 0x00, // foo
        0x66, 0x55, // c
        0x0, 0x0, // bar
    ];
    assert_bytes_equal(&expected, &actual);

    let deserialized: InsertReservedAfter = serde_smb::from_slice(&expected[..]).unwrap();
    assert_eq!(deserialized, f);
}

#[derive(SerializeSmbEnum, DeserializeSmbEnum, Clone, Debug, PartialEq)]
pub enum TestEnum {
    #[smb(tag = "Fool", size = "2")]
    Foo(u16),
    #[smb(tag = "Barl", size = "4")]
    Bar([u16; 2]),
    #[smb(tag = "Baz", size = "8", reserved_value = "u64", offset = 1)]
    Baz,
    #[smb(tag = "Quxl", size = "0")]
    Qux,
}

#[test]
fn test_enum_foo() {
    let f = TestEnum::Foo(0x1122);

    let actual = serde_smb::to_vec(&f).unwrap();

    let expected = [
        0x0c, 0x00, // name offset
        0x04, 0x00, // name length
        0x00, 0x00, // padding
        16, 0x00, // data offset
        0x02, 0x00, 0x00, 0x00, // data length
        b'F', b'o', b'o', b'l', // name
        0x22, 0x11,
    ];
    assert_bytes_equal(&expected, &actual);

    let deserialized: TestEnum = serde_smb::from_slice(&expected[..]).unwrap();
    assert_eq!(deserialized, f);
}

#[test]
fn test_enum_bar() {
    let f = TestEnum::Bar([0x1122, 0x3344]);

    let actual = serde_smb::to_vec(&f).unwrap();

    let expected = [
        0x0c, 0x00, // name offset
        0x04, 0x00, // name length
        0x00, 0x00, // padding
        16, 0x00, // data offset
        0x04, 0x00, 0x00, 0x00, // data length
        b'B', b'a', b'r', b'l', // name
        0x22, 0x11, 0x44, 0x33,
    ];
    assert_bytes_equal(&expected, &actual);

    let deserialized: TestEnum = serde_smb::from_slice(&expected[..]).unwrap();
    assert_eq!(deserialized, f);
}

#[test]
fn test_enum_baz_reserved_value() {
    let f = TestEnum::Baz;

    let actual = serde_smb::to_vec(&f).unwrap();

    let expected = [
        0x0c, 0x00, // name offset
        0x03, 0x00, // name length
        0x00, 0x00, // padding
        16, 0x00, // data offset
        0x08, 0x00, 0x00, 0x00, // data length
        b'B', b'a', b'z', // name
        0x0,  // padding
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // reserved
    ];
    assert_bytes_equal(&expected, &actual);

    let deserialized: TestEnum = serde_smb::from_slice(&expected[..]).unwrap();
    assert_eq!(deserialized, f);
}

#[test]
fn test_enum_qux_no_value() {
    let f = TestEnum::Qux;

    let actual = serde_smb::to_vec(&f).unwrap();

    let expected = [
        0x0c, 0x00, // name offset
        0x04, 0x00, // name length
        0x00, 0x00, // padding
        0x00, 0x00, // data offset
        0x00, 0x00, 0x00, 0x00, // data length
        b'Q', b'u', b'x', b'l', // name
    ];
    assert_bytes_equal(&expected, &actual);

    let deserialized: TestEnum = serde_smb::from_slice(&expected[..]).unwrap();
    assert_eq!(deserialized, f);
}
