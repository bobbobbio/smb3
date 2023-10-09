// copyright 2023 Remi Bernotavicius

use darling::{FromDeriveInput, FromField, FromMeta};
use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::quote;
use syn::{
    parse_macro_input, parse_quote, DeriveInput, Error, Expr, Ident, ItemImpl, Pat, PatIdent,
    Result,
};

#[derive(Clone, Debug, FromMeta)]
struct CollectionCount {
    int_type: syn::Type,
    after: Ident,
    element_size: Option<syn::LitInt>,
}

#[derive(Clone, Debug, FromMeta)]
struct CollectionOffset {
    int_type: syn::Type,
    value: Expr,
    after: Ident,
}

#[derive(Clone, Debug, FromMeta)]
struct Collection {
    count: CollectionCount,
    offset: Option<CollectionOffset>,
}

impl Collection {
    fn insert_after(
        &self,
        new_fields: &mut Vec<NewField>,
        new_field: NewField,
        after: &Ident,
    ) -> Result<()> {
        let index = new_fields
            .iter()
            .position(|f| &f.ident == after)
            .ok_or(Error::new(
                after.span(),
                format!("couldn't find field {after}"),
            ))?;
        new_fields.insert(index + 1, new_field);
        Ok(())
    }

    fn handle_count(&self, collection: &Ident, new_fields: &mut Vec<NewField>) -> Result<()> {
        let count_type = &self.count.int_type;
        let element_size = self.count.element_size.clone().unwrap_or(parse_quote!(1));
        let new_field = NewField {
            ident: Ident::new(&format!("{collection}_count"), Span::call_site()),
            name: format!("{collection}$count"),
            ser_expr: parse_quote!(
                &<#count_type as ::std::convert::TryFrom<_>>::try_from(
                    self.#collection.len() * #element_size
                ).unwrap()
            ),
            deser_expr: parse_quote!(
                seq.next_element::<#count_type>()
            ),
            deser_binding: None,
        };
        self.insert_after(new_fields, new_field, &self.count.after)?;
        Ok(())
    }

    fn handle_offset(&self, collection: &Ident, new_fields: &mut Vec<NewField>) -> Result<()> {
        if let Some(offset) = &self.offset {
            let offset_type = &offset.int_type;
            let value = &offset.value;
            let new_field = NewField {
                ident: Ident::new(&format!("{collection}_offset"), Span::call_site()),
                name: format!("{collection}$offset"),
                ser_expr: parse_quote!(&((#value) as #offset_type)),
                deser_expr: parse_quote!(
                    seq.next_element::<#offset_type>()
                ),
                deser_binding: None,
            };
            self.insert_after(new_fields, new_field, &offset.after)?;
        }
        Ok(())
    }

    fn evaluate(&self, collection: &Ident, new_fields: &mut Vec<NewField>) -> Result<()> {
        self.handle_count(collection, new_fields)?;
        self.handle_offset(collection, new_fields)?;
        Ok(())
    }
}

#[derive(Clone, Debug, FromField)]
#[darling(attributes(smb))]
struct StructField {
    ident: Option<Ident>,
    pad: Option<usize>,
    collection: Option<Collection>,
}

impl StructField {
    fn name(&self) -> String {
        let mut name = self.ident.as_ref().unwrap().to_string();
        if let Some(p) = self.pad {
            name += &format!("$pad{p}");
        }
        name
    }
}

#[derive(Clone, Debug, FromDeriveInput)]
#[darling(supports(struct_named))]
#[darling(attributes(smb))]
struct SerInput {
    data: darling::ast::Data<(), StructField>,
    size: Option<Expr>,
}

fn evaluate_size(size: Option<Expr>, new_fields: &mut Vec<NewField>) -> Result<()> {
    if let Some(size) = size {
        let new_field = NewField {
            ident: Ident::new("size", Span::call_site()),
            name: "size".into(),
            ser_expr: parse_quote!(&((#size) as u16)),
            deser_expr: parse_quote!(seq.next_element::<u16>()),
            deser_binding: None,
        };
        new_fields.insert(0, new_field);
    }
    Ok(())
}

#[derive(Clone, Debug)]
struct NewField {
    ident: Ident,
    name: String,
    ser_expr: Expr,
    deser_expr: Expr,
    deser_binding: Option<Ident>,
}

impl From<StructField> for NewField {
    fn from(s: StructField) -> Self {
        let name = s.name();
        let ident = s.ident.unwrap();
        Self {
            name,
            ser_expr: parse_quote!(&self.#ident),
            deser_expr: parse_quote!(seq.next_element()?.unwrap()),
            deser_binding: Some(ident.clone()),
            ident,
        }
    }
}

impl NewField {
    fn deser_binding_pat(&self) -> Pat {
        if let Some(b) = &self.deser_binding {
            Pat::Ident(PatIdent {
                attrs: vec![],
                by_ref: None,
                mutability: None,
                ident: b.clone(),
                subpat: None,
            })
        } else {
            parse_quote!(_)
        }
    }
}

fn handle_input(input: DeriveInput) -> Result<Vec<NewField>> {
    let input = SerInput::from_derive_input(&input)?;

    let fields = input.data.take_struct().unwrap();

    let mut collections = vec![];
    for f in fields.iter() {
        if let Some(c) = &f.collection {
            collections.push((f.ident.clone().unwrap(), c.clone()));
        }
    }

    let mut new_fields: Vec<NewField> = fields.into_iter().map(|f| f.into()).collect();

    evaluate_size(input.size, &mut new_fields)?;

    for (collection, info) in collections {
        info.evaluate(&collection, &mut new_fields)?;
    }

    Ok(new_fields)
}

fn serialize_smb_struct_inner(input: DeriveInput) -> Result<ItemImpl> {
    let self_ = input.ident.clone();
    let self_name = self_.to_string();

    let new_fields = handle_input(input)?;

    let num_fields = new_fields.len();
    let field_names = new_fields.iter().map(|f| &f.name);
    let field_exprs = new_fields.iter().map(|f| &f.ser_expr);

    Ok(parse_quote! {
        impl ::serde::Serialize for #self_ {
            fn serialize<S>(&self, serializer: S) -> ::std::result::Result<S::Ok, S::Error>
                where
                    S: ::serde::Serializer
            {
                let mut s = serializer.serialize_struct(#self_name, #num_fields)?;
                #(::serde::ser::SerializeStruct::serialize_field(
                    &mut s, #field_names, #field_exprs
                )?;)*
                ::serde::ser::SerializeStruct::end(s)
            }
        }
    })
}

#[proc_macro_derive(SerializeSmbStruct, attributes(smb))]
pub fn serialize_smb_struct(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match serialize_smb_struct_inner(input) {
        Err(e) => e.into_compile_error().into(),
        Ok(v) => quote!(#v).into(),
    }
}

fn deserialize_smb_struct_inner(input: DeriveInput) -> Result<ItemImpl> {
    let self_ = input.ident.clone();
    let self_name = self_.to_string();

    let new_fields = handle_input(input)?;

    let field_names = new_fields.iter().map(|f| &f.name);
    let field_exprs = new_fields.iter().map(|f| &f.deser_expr);
    let field_bindings = new_fields.iter().flat_map(|f| &f.deser_binding);
    let field_patterns = new_fields.iter().map(|f| f.deser_binding_pat());

    Ok(parse_quote! {
        impl<'de> ::serde::Deserialize<'de> for #self_ {
            fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
                where
                    D: ::serde::de::Deserializer<'de>
            {
                struct Visitor;

                impl<'de2> ::serde::de::Visitor<'de2> for Visitor {
                    type Value = #self_;

                    fn expecting(
                        &self, formatter: &mut ::std::fmt::Formatter<'_>
                    ) -> ::std::fmt::Result {
                        formatter.write_str(#self_name)
                    }

                    fn visit_seq<V>(self, mut seq: V) -> ::std::result::Result<#self_, V::Error>
                        where
                            V: ::serde::de::SeqAccess<'de2>,
                    {
                        #(let #field_patterns = #field_exprs;)*
                        Ok(#self_ {
                            #(#field_bindings,)*
                        })
                    }
                }

                const FIELDS: &'static [&'static str] = &[#(#field_names),*];
                deserializer.deserialize_struct(#self_name, FIELDS, Visitor)
            }
        }
    })
}

#[proc_macro_derive(DeserializeSmbStruct, attributes(smb))]
pub fn deserialize_smb_struct(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match deserialize_smb_struct_inner(input) {
        Err(e) => e.into_compile_error().into(),
        Ok(v) => quote!(#v).into(),
    }
}
