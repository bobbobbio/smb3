// copyright 2023 Remi Bernotavicius

use pretty_assertions::assert_eq;
use serde_smb::{DeserializeSmbStruct, SerializeSmbStruct};

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
