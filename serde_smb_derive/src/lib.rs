// copyright 2023 Remi Bernotavicius

use proc_macro::TokenStream;
use quote::quote;
use syn::{
    parse_macro_input, parse_quote, ConstParam, DeriveInput, GenericArgument, GenericParam,
    Generics, Ident, LifetimeParam, Type, TypeParam, TypeParamBound, WhereClause,
};

mod r#enum;
mod r#struct;

fn type_with_generics(ident: &Ident, generics: &Generics) -> Type {
    let filtered_generics = generics_to_args(generics);
    parse_quote!(#ident <#(#filtered_generics),*>)
}

fn generics_to_args(generics: &Generics) -> Vec<GenericArgument> {
    generics
        .params
        .iter()
        .map(|p| -> GenericArgument {
            match p {
                GenericParam::Lifetime(LifetimeParam { lifetime, .. }) => parse_quote!(#lifetime),
                GenericParam::Type(TypeParam { ident, .. }) => parse_quote!(#ident),
                GenericParam::Const(ConstParam { ident, .. }) => parse_quote!(#ident),
            }
        })
        .collect()
}

fn generate_where_clause(self_generics: &Generics, bound: TypeParamBound) -> WhereClause {
    let predicates = self_generics
        .params
        .iter()
        .filter_map(|p| -> Option<TypeParam> {
            match p {
                GenericParam::Type(TypeParam { ident, .. }) => Some(parse_quote!(#ident: #bound)),
                _ => None,
            }
        });
    let impl_where_clause: WhereClause = parse_quote! {
        where
            #(#predicates),*
    };
    impl_where_clause
}

#[proc_macro_derive(SerializeSmbStruct, attributes(smb))]
pub fn serialize_smb_struct(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match r#struct::serialize_smb_struct_inner(input) {
        Err(e) => e.into_compile_error().into(),
        Ok(v) => quote!(#v).into(),
    }
}

#[proc_macro_derive(DeserializeSmbStruct, attributes(smb))]
pub fn deserialize_smb_struct(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match r#struct::deserialize_smb_struct_inner(input) {
        Err(e) => e.into_compile_error().into(),
        Ok(v) => quote!(#v).into(),
    }
}

#[proc_macro_derive(SerializeSmbEnum, attributes(smb))]
pub fn serialize_smb_enum(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match r#enum::serialize_smb_enum_inner(input) {
        Err(e) => e.into_compile_error().into(),
        Ok(v) => quote!(#v).into(),
    }
}

#[proc_macro_derive(DeserializeSmbEnum, attributes(smb))]
pub fn deserialize_smb_enum(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match r#enum::deserialize_smb_enum_inner(input) {
        Err(e) => e.into_compile_error().into(),
        Ok(v) => quote!(#v).into(),
    }
}
