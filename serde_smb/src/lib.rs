use byteorder::{ReadBytesExt as _, WriteBytesExt as _};
use count_write::CountWrite;
use derive_more::From;
use serde::de::Visitor;
use serde::{de, ser, Deserialize, Serialize};
use std::{collections::BTreeMap, fmt, io};

pub use serde_smb_derive::{DeserializeSmbStruct, SerializeSmbStruct};

type Endianness = byteorder::LittleEndian;

#[derive(Debug, From)]
pub enum Error {
    Io(io::Error),
    #[from(ignore)]
    Custom(String),
    #[from(ignore)]
    NonAscii(char),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => fmt::Display::fmt(e, f),
            Self::Custom(m) => fmt::Display::fmt(m, f),
            Self::NonAscii(c) => fmt::Display::fmt(&format!("{c:?} is not ASCII"), f),
        }
    }
}

impl std::error::Error for Error {}

impl ser::Error for Error {
    fn custom<T>(msg: T) -> Self
    where
        T: fmt::Display,
    {
        Self::Custom(msg.to_string())
    }
}

impl de::Error for Error {
    fn custom<T>(msg: T) -> Self
    where
        T: fmt::Display,
    {
        Self::Custom(msg.to_string())
    }
}

pub fn to_vec<T>(value: &T) -> Result<Vec<u8>>
where
    T: ?Sized + Serialize,
{
    let mut vec = vec![];
    let mut ser = Serializer::new(&mut vec);
    value.serialize(&mut ser)?;
    Ok(vec)
}

pub fn to_writer<T>(value: &T, writer: impl io::Write) -> Result<()>
where
    T: ?Sized + Serialize,
{
    let mut ser = Serializer::new(writer);
    value.serialize(&mut ser)?;
    Ok(())
}

pub fn from_slice<'de, T>(mut v: &[u8]) -> Result<T>
where
    T: Deserialize<'de>,
{
    let mut de = Deserializer::new(&mut v);
    de::Deserialize::deserialize(&mut de)
}

pub fn from_reader<'de, T>(v: impl io::Read) -> Result<T>
where
    T: Deserialize<'de>,
{
    let mut de = Deserializer::new(v);
    de::Deserialize::deserialize(&mut de)
}

pub type Result<T> = std::result::Result<T, Error>;

pub struct Serializer<Writer> {
    writer: CountWrite<Writer>,
    field_offsets: BTreeMap<&'static str, usize>,
    pending_offset: Option<&'static str>,
    pending_next_entry_offset: Option<&'static str>,
    next_entry_offset: BTreeMap<&'static str, usize>,
    struct_start_offset: usize,
    last_seq_element: bool,
}

impl<Writer: io::Write> Serializer<Writer> {
    fn new(writer: Writer) -> Self {
        Self {
            writer: CountWrite::from(writer),
            field_offsets: BTreeMap::new(),
            pending_offset: None,
            pending_next_entry_offset: None,
            next_entry_offset: BTreeMap::new(),
            struct_start_offset: 0,
            last_seq_element: false,
        }
    }

    fn pad(&mut self, align: usize) -> Result<()> {
        let padding = (self.writer.count() as usize) % align;
        for _ in 0..padding {
            self.writer.write_u8(0)?;
        }
        Ok(())
    }

    fn handle_next_entry_offset(
        &mut self,
        struct_name: &'static str,
        field_name: &'static str,
    ) -> Result<()> {
        if field_name == "$next_entry_offset" {
            self.pending_next_entry_offset = Some(struct_name);
        }
        Ok(())
    }

    fn handle_offset(&mut self, name: &'static str) -> Result<()> {
        if let Some(stripped) = name.strip_suffix("$offset") {
            self.pending_offset = Some(stripped);
            return Ok(());
        } else if name.ends_with("$count") || name.ends_with("$count_as_bytes") {
            return Ok(());
        }

        let first_name = name.split('$').next().unwrap();
        if let Some(offset) = self.field_offsets.get(&first_name) {
            while *offset > self.writer.count() as usize {
                self.writer.write_u8(0)?;
            }
        }
        Ok(())
    }

    fn handle_padding(&mut self, name: &str) -> Result<()> {
        let lower_name = name.to_lowercase();
        if lower_name.ends_with("$pad4") {
            self.pad(4)?;
        } else if lower_name.ends_with("$pad8") {
            self.pad(8)?;
        } else if lower_name.ends_with("$pad") {
            return Err(Error::Custom(format!("unsupported pad {name:?}")));
        }
        Ok(())
    }
}

impl<'a, Writer: io::Write> ser::Serializer for &'a mut Serializer<Writer> {
    type Ok = ();
    type Error = Error;

    type SerializeSeq = SequenceSerializer<'a, Writer>;
    type SerializeTuple = Self;
    type SerializeTupleStruct = Self;
    type SerializeTupleVariant = Self;
    type SerializeMap = Self;
    type SerializeStruct = StructSerializer<'a, Writer>;
    type SerializeStructVariant = Self;

    fn serialize_bool(self, v: bool) -> Result<()> {
        self.serialize_u8(v as u8)
    }

    fn serialize_i8(self, v: i8) -> Result<()> {
        Ok(self.writer.write_i8(v)?)
    }

    fn serialize_i16(self, v: i16) -> Result<()> {
        self.pad(2)?;
        Ok(self.writer.write_i16::<Endianness>(v)?)
    }

    fn serialize_i32(self, v: i32) -> Result<()> {
        self.pad(4)?;
        Ok(self.writer.write_i32::<Endianness>(v)?)
    }

    fn serialize_i64(self, v: i64) -> Result<()> {
        self.pad(8)?;
        Ok(self.writer.write_i64::<Endianness>(v)?)
    }

    fn serialize_u8(self, v: u8) -> Result<()> {
        Ok(self.writer.write_u8(v)?)
    }

    fn serialize_u16(self, v: u16) -> Result<()> {
        if let Some(n) = self.pending_offset.take() {
            self.field_offsets.insert(n, v as usize);
        }

        self.pad(2)?;
        Ok(self.writer.write_u16::<Endianness>(v)?)
    }

    fn serialize_u32(self, mut v: u32) -> Result<()> {
        if let Some(n) = self.pending_offset.take() {
            self.field_offsets.insert(n, v as usize);
        }
        if let Some(n) = self.pending_next_entry_offset {
            if self.last_seq_element {
                v = 0;
            } else {
                self.next_entry_offset
                    .insert(n, self.struct_start_offset + v as usize);
            }
            self.pending_next_entry_offset = None;
        }

        self.pad(4)?;
        Ok(self.writer.write_u32::<Endianness>(v)?)
    }

    fn serialize_u64(self, v: u64) -> Result<()> {
        self.pad(8)?;
        Ok(self.writer.write_u64::<Endianness>(v)?)
    }

    fn serialize_f32(self, v: f32) -> Result<()> {
        self.pad(4)?;
        Ok(self.writer.write_f32::<Endianness>(v)?)
    }

    fn serialize_f64(self, v: f64) -> Result<()> {
        self.pad(8)?;
        Ok(self.writer.write_f64::<Endianness>(v)?)
    }

    fn serialize_char(self, _v: char) -> Result<()> {
        unimplemented!()
    }

    fn serialize_str(self, s: &str) -> Result<()> {
        for v in s.encode_utf16() {
            self.writer.write_u16::<Endianness>(v)?
        }
        Ok(())
    }

    fn serialize_bytes(self, _v: &[u8]) -> Result<()> {
        unimplemented!()
    }

    fn serialize_none(self) -> Result<()> {
        unimplemented!()
    }

    fn serialize_some<T>(self, _value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        unimplemented!()
    }

    fn serialize_unit(self) -> Result<()> {
        unimplemented!()
    }

    fn serialize_unit_struct(self, _name: &'static str) -> Result<()> {
        unimplemented!()
    }

    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
    ) -> Result<()> {
        unimplemented!()
    }

    fn serialize_newtype_struct<T>(self, _name: &'static str, value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        value.serialize(&mut *self)
    }

    fn serialize_newtype_variant<T>(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _value: &T,
    ) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        unimplemented!()
    }

    fn serialize_seq(self, len: Option<usize>) -> Result<Self::SerializeSeq> {
        Ok(SequenceSerializer {
            serializer: self,
            len,
            field: 0,
        })
    }

    fn serialize_tuple(self, _len: usize) -> Result<Self::SerializeTuple> {
        Ok(self)
    }

    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleStruct> {
        unimplemented!()
    }

    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleVariant> {
        unimplemented!()
    }

    fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap> {
        unimplemented!()
    }

    fn serialize_struct(self, name: &'static str, _len: usize) -> Result<Self::SerializeStruct> {
        self.struct_start_offset = self.writer.count() as usize;
        self.handle_padding(name)?;
        Ok(StructSerializer {
            serializer: self,
            name,
        })
    }

    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStructVariant> {
        unimplemented!()
    }
}

pub struct SequenceSerializer<'a, Writer> {
    serializer: &'a mut Serializer<Writer>,
    len: Option<usize>,
    field: usize,
}

impl<'a, Writer: io::Write> ser::SerializeSeq for SequenceSerializer<'a, Writer> {
    type Ok = ();
    type Error = Error;

    fn serialize_element<T>(&mut self, value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        if let Some(len) = &self.len {
            self.serializer.last_seq_element = self.field >= len.saturating_sub(1);
        }
        value.serialize(&mut *self.serializer)?;
        self.field += 1;
        Ok(())
    }

    fn end(self) -> Result<()> {
        Ok(())
    }
}

impl<'a, Writer: io::Write> ser::SerializeTuple for &'a mut Serializer<Writer> {
    type Ok = ();
    type Error = Error;

    fn serialize_element<T>(&mut self, value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<()> {
        Ok(())
    }
}

impl<'a, Writer: io::Write> ser::SerializeTupleStruct for &'a mut Serializer<Writer> {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T>(&mut self, _value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        unimplemented!()
    }

    fn end(self) -> Result<()> {
        unimplemented!()
    }
}

impl<'a, Writer: io::Write> ser::SerializeTupleVariant for &'a mut Serializer<Writer> {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T>(&mut self, _value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        unimplemented!()
    }

    fn end(self) -> Result<()> {
        unimplemented!()
    }
}

impl<'a, Writer: io::Write> ser::SerializeMap for &'a mut Serializer<Writer> {
    type Ok = ();
    type Error = Error;

    fn serialize_key<T>(&mut self, _key: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        unimplemented!()
    }

    fn serialize_value<T>(&mut self, _value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        unimplemented!()
    }

    fn end(self) -> Result<()> {
        unimplemented!()
    }
}

pub struct StructSerializer<'a, Writer> {
    serializer: &'a mut Serializer<Writer>,
    name: &'static str,
}

impl<'a, Writer: io::Write> ser::SerializeStruct for StructSerializer<'a, Writer> {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T>(&mut self, key: &'static str, value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        self.serializer.handle_next_entry_offset(self.name, key)?;
        self.serializer.handle_padding(key)?;
        self.serializer.handle_offset(key)?;
        value.serialize(&mut *self.serializer)?;
        self.serializer.pending_offset = None;
        Ok(())
    }

    fn end(self) -> Result<()> {
        if let Some(end) = self.serializer.next_entry_offset.remove(self.name) {
            while end > self.serializer.writer.count() as usize {
                self.serializer.writer.write_u8(0)?;
            }
        }
        Ok(())
    }
}

impl<'a, Writer: io::Write> ser::SerializeStructVariant for &'a mut Serializer<Writer> {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T>(&mut self, _key: &'static str, _value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        unimplemented!()
    }

    fn end(self) -> Result<()> {
        unimplemented!()
    }
}

struct CountRead<Reader> {
    reader: Reader,
    num_read: usize,
}

impl<Reader> CountRead<Reader> {
    fn new(reader: Reader) -> Self {
        Self {
            reader,
            num_read: 0,
        }
    }

    fn num_read(&self) -> usize {
        self.num_read
    }
}

impl<Reader: io::Read> io::Read for CountRead<Reader> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let num = self.reader.read(buf)?;
        self.num_read += num;
        Ok(num)
    }

    fn read_vectored(&mut self, bufs: &mut [io::IoSliceMut<'_>]) -> io::Result<usize> {
        let num = self.reader.read_vectored(bufs)?;
        self.num_read += num;
        Ok(num)
    }
}

#[derive(Copy, Clone, PartialEq, Eq)]
enum Count {
    Elements(usize),
    Bytes(usize),
}

impl Count {
    fn to_usize(self) -> usize {
        match self {
            Self::Elements(v) => v,
            Self::Bytes(v) => v,
        }
    }
}

pub struct Deserializer<Reader> {
    reader: CountRead<Reader>,
    sequence_limit: Option<Count>,
    pending_count: Option<&'static str>,
    pending_count_as_bytes: Option<&'static str>,
    counts: BTreeMap<&'static str, Count>,
    field_offsets: BTreeMap<&'static str, usize>,
    pending_offset: Option<&'static str>,
    pending_next_entry_offset: Option<&'static str>,
    next_entry_offset: BTreeMap<&'static str, usize>,
}

impl<Reader: io::Read> Deserializer<Reader> {
    pub fn new(reader: Reader) -> Self {
        Self {
            reader: CountRead::new(reader),
            sequence_limit: None,
            pending_count: None,
            pending_count_as_bytes: None,
            counts: BTreeMap::new(),
            field_offsets: BTreeMap::new(),
            pending_offset: None,
            pending_next_entry_offset: None,
            next_entry_offset: BTreeMap::new(),
        }
    }

    fn consume_pad(&mut self, pad: usize) -> Result<()> {
        while self.reader.num_read() % pad > 0 {
            self.reader.read_u8()?;
        }
        Ok(())
    }

    fn handle_padding(&mut self, name: &str) -> Result<()> {
        let lower_name = name.to_lowercase();
        if lower_name.ends_with("$pad4") {
            self.consume_pad(4)?;
        } else if lower_name.ends_with("$pad8") {
            self.consume_pad(8)?;
        } else if lower_name.ends_with("$pad") {
            return Err(Error::Custom(format!("unsupported pad {name:?}")));
        }
        Ok(())
    }

    fn handle_field(
        &mut self,
        struct_name: &'static str,
        field_name: &'static str,
    ) -> Result<String> {
        self.handle_padding(field_name)?;

        if field_name == "$next_entry_offset" {
            self.pending_next_entry_offset = Some(struct_name);
            return Ok(field_name.into());
        }

        let first_name = field_name.split('$').next().unwrap();

        if let Some(stripped) = field_name.strip_suffix("$count") {
            self.pending_count = Some(stripped);
            return Ok(first_name.into());
        } else if let Some(stripped) = field_name.strip_suffix("$count_as_bytes") {
            self.pending_count_as_bytes = Some(stripped);
            return Ok(first_name.into());
        } else if let Some(stripped) = field_name.strip_suffix("$offset") {
            self.pending_offset = Some(stripped);
            return Ok(first_name.into());
        }

        if let Some(limit) = self.counts.get(&first_name) {
            self.sequence_limit = Some(*limit);
        }

        if let Some(offset) = self.field_offsets.get(&first_name) {
            while self.reader.num_read() < *offset {
                self.reader.read_u8()?;
            }
        }
        Ok(first_name.into())
    }
}

impl<'de, 'a, Reader: io::Read> de::Deserializer<'de> for &'a mut Deserializer<Reader> {
    type Error = Error;

    fn deserialize_any<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unimplemented!()
    }

    fn deserialize_bool<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_bool(self.reader.read_u8()? != 0)
    }

    fn deserialize_i8<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_i8(self.reader.read_i8()?)
    }

    fn deserialize_i16<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        self.consume_pad(2)?;
        visitor.visit_i16(self.reader.read_i16::<Endianness>()?)
    }

    fn deserialize_i32<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        self.consume_pad(4)?;
        visitor.visit_i32(self.reader.read_i32::<Endianness>()?)
    }

    fn deserialize_i64<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        self.consume_pad(8)?;
        visitor.visit_i64(self.reader.read_i64::<Endianness>()?)
    }

    fn deserialize_u8<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_u8(self.reader.read_u8()?)
    }

    fn deserialize_u16<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        self.consume_pad(2)?;
        let value = self.reader.read_u16::<Endianness>()?;

        if let Some(key) = self.pending_offset.take() {
            self.field_offsets.insert(key, value as usize);
        }
        if let Some(key) = self.pending_count.take() {
            self.counts.insert(key, Count::Elements(value as usize));
        }
        if let Some(key) = self.pending_count_as_bytes.take() {
            self.counts.insert(key, Count::Bytes(value as usize));
        }
        visitor.visit_u16(value)
    }

    fn deserialize_u32<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        self.consume_pad(4)?;
        let value = self.reader.read_u32::<Endianness>()?;

        if let Some(key) = self.pending_offset.take() {
            self.field_offsets.insert(key, value as usize);
        }
        if let Some(key) = self.pending_count.take() {
            self.counts.insert(key, Count::Elements(value as usize));
        }
        if let Some(key) = self.pending_count_as_bytes.take() {
            self.counts.insert(key, Count::Bytes(value as usize));
        }
        if let Some(key) = self.pending_next_entry_offset.take() {
            self.next_entry_offset.insert(key, value as usize);
        }

        visitor.visit_u32(value)
    }

    fn deserialize_u64<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        self.consume_pad(8)?;
        visitor.visit_u64(self.reader.read_u64::<Endianness>()?)
    }

    fn deserialize_f32<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        self.consume_pad(4)?;
        visitor.visit_f32(self.reader.read_f32::<Endianness>()?)
    }

    fn deserialize_f64<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        self.consume_pad(8)?;
        visitor.visit_f64(self.reader.read_f64::<Endianness>()?)
    }

    fn deserialize_char<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unimplemented!()
    }

    fn deserialize_str<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unimplemented!()
    }

    fn deserialize_string<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        let len = self
            .sequence_limit
            .take()
            .ok_or(Error::Custom("missing string length".into()))?;
        let mut bytes = vec![];
        for _ in 0..(len.to_usize() / 2) {
            bytes.push(self.reader.read_u16::<Endianness>()?);
        }

        let s: String = char::decode_utf16(bytes)
            .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER))
            .collect();

        visitor.visit_string(s)
    }

    fn deserialize_bytes<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unimplemented!()
    }

    fn deserialize_byte_buf<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unimplemented!()
    }

    fn deserialize_option<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unimplemented!()
    }

    fn deserialize_unit<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unimplemented!()
    }

    fn deserialize_unit_struct<V>(self, _name: &'static str, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unimplemented!()
    }

    fn deserialize_newtype_struct<V>(self, name: &'static str, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        self.handle_padding(name)?;
        visitor.visit_seq(SequenceDeserializer {
            name: "",
            fields: None,
            field: 0,
            max_fields: None,
            starting_offset: self.reader.num_read(),
            deserializer: self,
        })
    }

    fn deserialize_seq<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_seq(SequenceDeserializer {
            name: "",
            max_fields: self.sequence_limit.take(),
            fields: None,
            field: 0,
            starting_offset: self.reader.num_read(),
            deserializer: self,
        })
    }

    fn deserialize_tuple<V>(self, _len: usize, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_seq(SequenceDeserializer {
            name: "",
            fields: None,
            field: 0,
            max_fields: None,
            starting_offset: self.reader.num_read(),
            deserializer: self,
        })
    }

    fn deserialize_tuple_struct<V>(
        self,
        name: &'static str,
        _len: usize,
        visitor: V,
    ) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        self.handle_padding(name)?;
        visitor.visit_seq(SequenceDeserializer {
            name,
            fields: None,
            field: 0,
            max_fields: None,
            starting_offset: self.reader.num_read(),
            deserializer: self,
        })
    }

    fn deserialize_map<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unimplemented!()
    }

    fn deserialize_struct<V>(
        self,
        name: &'static str,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        self.handle_padding(name)?;
        visitor.visit_seq(SequenceDeserializer {
            name,
            fields: Some(fields),
            field: 0,
            max_fields: None,
            starting_offset: self.reader.num_read(),
            deserializer: self,
        })
    }

    fn deserialize_enum<V>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        _visitor: V,
    ) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unimplemented!()
    }

    fn deserialize_identifier<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unimplemented!()
    }

    fn deserialize_ignored_any<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        unimplemented!()
    }
}

struct SequenceDeserializer<'a, Reader> {
    deserializer: &'a mut Deserializer<Reader>,
    name: &'static str,
    fields: Option<&'static [&'static str]>,
    field: usize,
    max_fields: Option<Count>,
    starting_offset: usize,
}

impl<'de, 'a, Reader: io::Read> de::SeqAccess<'de> for SequenceDeserializer<'a, Reader> {
    type Error = Error;

    fn next_element_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>>
    where
        T: de::DeserializeSeed<'de>,
    {
        if let Some(max_fields) = self.max_fields {
            match max_fields {
                Count::Elements(v) => {
                    if self.field >= v {
                        return Ok(None);
                    }
                }
                Count::Bytes(v) => {
                    let offset = self.deserializer.reader.num_read();
                    let bytes = offset - self.starting_offset;
                    if bytes >= v {
                        return Ok(None);
                    }
                }
            }
        }

        if let Some(fields) = &self.fields {
            let f = fields[self.field];
            self.deserializer.handle_field(self.name, f)?;
        }

        self.field += 1;
        let value = seed.deserialize(&mut *self.deserializer)?;
        self.deserializer.pending_count = None;
        self.deserializer.pending_next_entry_offset = None;

        if let Some(fields) = &self.fields {
            if self.field >= fields.len() {
                if let Some(next_entry_offset) =
                    self.deserializer.next_entry_offset.remove(self.name)
                {
                    while self.starting_offset + next_entry_offset
                        > self.deserializer.reader.num_read()
                    {
                        self.deserializer.reader.read_u8()?;
                    }
                }
            }
        }

        Ok(Some(value))
    }
}
