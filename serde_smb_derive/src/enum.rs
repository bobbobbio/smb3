// copyright 2023 Remi Bernotavicius

use super::{generate_where_clause, generics_to_args, type_with_generics};
use darling::{FromDeriveInput, FromVariant};
use syn::{
    parse_quote, Arm, ConstParam, DeriveInput, Expr, GenericParam, Ident, ItemImpl, LifetimeParam,
    Pat, Result, Type, TypeParam,
};

#[allow(dead_code)]
#[derive(Clone, Debug, FromVariant)]
#[darling(attributes(smb))]
struct EnumVariant {
    ident: Ident,
    tag: String,
    size: usize,
    reserved_value: Option<Type>,
    offset: Option<Expr>,
}

#[allow(dead_code)]
#[derive(Clone, Debug, FromDeriveInput)]
#[darling(supports(enum_newtype, enum_unit))]
#[darling(attributes(smb))]
struct SerInput {
    ident: Ident,
    data: darling::ast::Data<EnumVariant, ()>,
    #[darling(default)]
    offset: u16,
}

pub fn serialize_smb_enum_inner(input: DeriveInput) -> Result<ItemImpl> {
    let self_: Type = type_with_generics(&input.ident, &input.generics);
    let self_name = input.ident.to_string();
    let impl_generics = &input.generics;
    let impl_where_clause =
        generate_where_clause(&input.generics, parse_quote!(::serde::Serialize));

    let input = SerInput::from_derive_input(&input)?;
    let variants = input.data.take_enum().unwrap();
    let base_offset = input.offset;
    let match_arms = variants.iter().map(|v| -> Arm {
        let ident = &v.ident;
        let name_count = u16::try_from(v.tag.len()).unwrap();
        let data_offset = v.offset.clone().unwrap_or(parse_quote!(0));
        let name = &v.tag;
        let data_count = u32::try_from(v.size).unwrap();
        let name_offset: Expr = parse_quote!(&(12u16 + #base_offset));
        let pat: Pat = if v.reserved_value.is_some() || v.size == 0 {
            parse_quote!(Self::#ident)
        } else {
            parse_quote!(Self::#ident(f))
        };
        let expr: Expr = if let Some(reserved) = &v.reserved_value {
            parse_quote!(&<#reserved as ::std::default::Default>::default())
        } else {
            parse_quote!(&f)
        };
        let data_offset_expr: Expr = if v.size == 0 {
            parse_quote!(&0u16)
        } else {
            parse_quote!(&u16::try_from(12 + #name_count + #base_offset + #data_offset).unwrap())
        };
        let data_expr: Option<Expr> = (v.size != 0 || v.reserved_value.is_some()).then_some(
            parse_quote! {
                ::serde::ser::SerializeStruct::serialize_field(&mut s, "data", #expr)?
            }
        );
        parse_quote! {
            #pat => {
                ::serde::ser::SerializeStruct::serialize_field(&mut s, "name$offset", &#name_offset)?;
                ::serde::ser::SerializeStruct::serialize_field(&mut s, "name$count", &#name_count)?;
                ::serde::ser::SerializeStruct::serialize_field(&mut s, "reserved", &0u16)?;
                ::serde::ser::SerializeStruct::serialize_field(
                    &mut s, "data_offset", #data_offset_expr
                )?;
                ::serde::ser::SerializeStruct::serialize_field(&mut s, "data_count", &#data_count)?;
                ::serde::ser::SerializeStruct::serialize_field(&mut s, "name", &(#name.as_bytes()))?;
                #data_expr
            }
        }
    });

    Ok(parse_quote! {
        impl #impl_generics ::serde::Serialize for #self_ #impl_where_clause {
            fn serialize<S>(&self, serializer: S) -> ::std::result::Result<S::Ok, S::Error>
                where
                    S: ::serde::Serializer
            {
                let mut s = serializer.serialize_struct(#self_name, 7)?;
                match self {
                    #(#match_arms,)*
                }
                ::serde::ser::SerializeStruct::end(s)
            }
        }
    })
}

pub fn deserialize_smb_enum_inner(input: DeriveInput) -> Result<ItemImpl> {
    let self_ident = &input.ident;
    let self_: Type = type_with_generics(&input.ident, &input.generics);
    let self_generics = input.generics.clone();
    let self_name = input.ident.to_string();

    let mut impl_generics = input.generics.clone();
    impl_generics.params.push(parse_quote!('de));

    let impl_where_clause =
        generate_where_clause(&input.generics, parse_quote!(::serde::Deserialize<'de>));

    let visitor_params = self_generics.params.iter().map(|p| -> Type {
        match p {
            GenericParam::Lifetime(LifetimeParam { lifetime, .. }) => parse_quote!(&#lifetime ()),
            GenericParam::Type(TypeParam { ident, .. }) => parse_quote!(#ident),
            GenericParam::Const(ConstParam { ident, .. }) => parse_quote!([(); #ident]),
        }
    });

    let self_generic_args = generics_to_args(&self_generics);

    let input = SerInput::from_derive_input(&input)?;
    let variants = input.data.take_enum().unwrap();
    let match_arms = variants.iter().map(|v| -> Arm {
        let ident = &v.ident;
        let tag = &v.tag;
        if let Some(reserved) = &v.reserved_value {
            parse_quote! {
                #tag => {
                    let _: #reserved = seq.next_element()?
                        .ok_or(::serde::de::Error::missing_field("reserved"))?;
                    Ok(#self_ident::#ident)
                }
            }
        } else if v.size == 0 {
            parse_quote!(#tag => Ok(#self_ident::#ident))
        } else {
            parse_quote! {
                #tag => Ok(#self_ident::#ident(
                    seq.next_element()?.ok_or(::serde::de::Error::missing_field("data"))?
                ))
            }
        }
    });

    Ok(parse_quote! {
        impl #impl_generics ::serde::Deserialize<'de> for #self_ #impl_where_clause {
            fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
                where
                    D: ::serde::de::Deserializer<'de>
            {
                struct Visitor #self_generics (::std::marker::PhantomData<(#(#visitor_params),*)>);

                impl #impl_generics ::serde::de::Visitor<'de> for Visitor <#(#self_generic_args),*>
                    #impl_where_clause
                {
                    type Value = #self_;

                    fn expecting(
                        &self, formatter: &mut ::std::fmt::Formatter<'_>
                    ) -> ::std::fmt::Result {
                        formatter.write_str(#self_name)
                    }

                    fn visit_seq<V>(self, mut seq: V) -> ::std::result::Result<#self_, V::Error>
                        where
                            V: ::serde::de::SeqAccess<'de>,
                    {
                        let _ = seq.next_element::<u16>()?
                            .ok_or(::serde::de::Error::missing_field("name$offset"))?;
                        let _ = seq.next_element::<u16>()?
                            .ok_or(::serde::de::Error::missing_field("name$count"))?;
                        let _ = seq.next_element::<u16>()?
                            .ok_or(::serde::de::Error::missing_field("reserved"))?;
                        let _ = seq.next_element::<u16>()?
                            .ok_or(::serde::de::Error::missing_field("data_offset"))?;
                        let _ = seq.next_element::<u32>()?
                            .ok_or(::serde::de::Error::missing_field("data_count"))?;
                        let name: Vec<u8> = seq.next_element()?
                            .ok_or(::serde::de::Error::missing_field("name"))?;
                        let name_str = ::std::str::from_utf8(&name[..])
                            .map_err(|_| ::serde::de::Error::custom("invalid utf8 for name"))?;
                        match name_str {
                            #(#match_arms,)*
                            v => Err(::serde::de::Error::custom(format!("unknown tag {v:?}"))),
                        }
                    }
                }

                const FIELDS: &'static [&'static str] = &[
                    "name$offset",
                    "name$count",
                    "reserved",
                    "data_offset",
                    "data_count",
                    "name",
                    "data",
                ];
                deserializer.deserialize_struct(
                    #self_name, FIELDS, Visitor(::std::marker::PhantomData)
                )
            }
        }
    })
}
