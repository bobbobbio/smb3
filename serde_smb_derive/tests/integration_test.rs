// copyright 2023 Remi Bernotavicius

use serde_smb_derive::{DeserializeSmbStruct, SerializeSmbStruct};

#[derive(Debug, PartialEq, SerializeSmbStruct, DeserializeSmbStruct)]
#[smb(size = "14 + self.e.len()")]
struct Foo {
    a: u16,
    b: u16,
    #[smb(pad = 4)]
    c: u16,
    d: u16,
    #[smb(collection(
        count(int_type = "u16", after = "c"),
        offset(int_type = "u16", after = "e_count", value = 0xc)
    ))]
    e: Vec<u8>,
}

#[test]
fn serialize_deserialize() {
    let f = Foo {
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
        0xc, 0x0, // e_offset
        0xEE, 0xDD, // d
        0x1, 0x2, // e
    ];
    assert!(
        &expected[..] == &actual[..],
        "\nexpected = {expected:x?}\nactual   = {actual:x?}"
    );

    let deserialized: Foo = serde_smb::from_slice(&expected[..]).unwrap();
    assert_eq!(deserialized, f);
}
