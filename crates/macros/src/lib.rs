//! Namada macros for generating WASM binding code for transactions and validity
//! predicates.

#![doc(html_favicon_url = "https://dev.namada.net/master/favicon.png")]
#![doc(html_logo_url = "https://dev.namada.net/master/rustdoc-logo.png")]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(rustdoc::private_intra_doc_links)]

use proc_macro::TokenStream;
use proc_macro2::{Span as Span2, Span, TokenStream as TokenStream2};
use quote::{ToTokens, quote};
use sha2::Digest;
use syn::punctuated::Punctuated;
use syn::{ItemEnum, ItemFn, ItemStruct, LitByte, parse_macro_input};

/// Generate WASM binding for a transaction main entrypoint function.
///
/// This macro expects a function with signature:
///
/// ```compiler_fail
/// fn apply_tx(
///     ctx: &mut Ctx,
///     tx_data: BatchedTx,
/// ) -> TxResult
/// ```
#[proc_macro_attribute]
pub fn transaction(_attr: TokenStream, input: TokenStream) -> TokenStream {
    let ast = parse_macro_input!(input as ItemFn);
    let ident = &ast.sig.ident;
    let r#gen = quote! {
        // Use `rlsf` as the global allocator.
        #[global_allocator]
        static ALLOC: rlsf::SmallGlobalTlsf = rlsf::SmallGlobalTlsf::new();

        #ast

        // The module entrypoint callable by wasm runtime
        #[unsafe(no_mangle)]
        extern "C" fn _apply_tx(tx_data_ptr: u64, tx_data_len: u64) -> u64 {
            let slice = unsafe {
                core::slice::from_raw_parts(
                    tx_data_ptr as *const u8,
                    tx_data_len as _,
                )
            };
            let tx_data = BatchedTx::try_from_slice(slice).unwrap();

            // The context on WASM side is only provided by the VM once its
            // being executed (in here it's implicit). But because we want to
            // have interface consistent with the VP interface, in which the
            // context is explicit, in here we're just using an empty `Ctx`
            // to "fake" it.
            let mut ctx = unsafe { namada_tx_prelude::Ctx::new() };

            // Add a custom panic hook, in order to receive detailed
            // information on the host of panicking transactions, to
            // improve debugging
            #[cfg(all(
                target_family = "wasm",
                feature = "debug-panic-hook"
            ))]
            std::panic::set_hook(Box::new(|panic_info| {
                let mut ctx = unsafe { namada_tx_prelude::Ctx::new() };
                ctx.yield_value({
                    use std::fmt::Write;

                    let mut buf = "Panic occurred".to_owned();

                    // Append panic location
                    if let Some(loc) = panic_info.location() {
                        _ = write!(
                            &mut buf,
                            " in file {:?} at line {}",
                            loc.file(),
                            loc.line()
                        );
                    }

                    // Append panic message
                    if let Some(reason) = panic_info
                        .payload()
                        .downcast_ref::<&str>()
                        .map(|&s| s)
                        .or_else(|| {
                            panic_info
                                .payload()
                                .downcast_ref::<String>()
                                .map(String::as_str)
                        })
                    {
                        _ = write!(&mut buf, ": {reason}");
                    }

                    // TODO(namada#2980): pass some proper error from txs, instead of a string
                    buf.serialize_to_vec()
                });
                core::arch::wasm32::unreachable()
            }));

            match #ident(&mut ctx, tx_data) {
                Ok(()) => 1,
                Err(err) => {
                    namada_tx_prelude::debug_log!("Transaction error: {err}");
                    // TODO(namada#2980): pass some proper error from txs, instead of a string
                    let err = err.to_string().serialize_to_vec();
                    ctx.yield_value(err);
                    0
                },
            }
        }
    };
    TokenStream::from(r#gen)
}

/// Generate WASM binding for validity predicate main entrypoint function.
///
/// This macro expects a function with signature:
///
/// ```compiler_fail
/// fn validate_tx(
///     ctx: &Ctx,
///     tx_data: BatchedTx,
///     addr: Address,
///     keys_changed: BTreeSet<storage::Key>,
///     verifiers: BTreeSet<Address>
/// ) -> VpResult
/// ```
#[proc_macro_attribute]
pub fn validity_predicate(
    _attr: TokenStream,
    input: TokenStream,
) -> TokenStream {
    let ast = parse_macro_input!(input as ItemFn);
    let ident = &ast.sig.ident;
    let r#gen = quote! {
        // Use `rlsf` as the global allocator.
        #[global_allocator]
        static ALLOC: rlsf::SmallGlobalTlsf = rlsf::SmallGlobalTlsf::new();

        #ast

        // The module entrypoint callable by wasm runtime
        #[unsafe(no_mangle)]
        extern "C" fn _validate_tx(
            // VP's account's address
            addr_ptr: u64,
            addr_len: u64,
            tx_data_ptr: u64,
            tx_data_len: u64,
            keys_changed_ptr: u64,
            keys_changed_len: u64,
            verifiers_ptr: u64,
            verifiers_len: u64,
        ) -> u64 {
            let slice = unsafe {
                core::slice::from_raw_parts(addr_ptr as *const u8, addr_len as _)
            };
            let addr = Address::try_from_slice(slice).unwrap();

            let slice = unsafe {
                core::slice::from_raw_parts(
                    tx_data_ptr as *const u8,
                    tx_data_len as _,
                )
            };
            let tx_data = BatchedTx::try_from_slice(slice).unwrap();

            let slice = unsafe {
                core::slice::from_raw_parts(
                    keys_changed_ptr as *const u8,
                    keys_changed_len as _,
                )
            };
            let keys_changed: BTreeSet<storage::Key> = BTreeSet::try_from_slice(slice).unwrap();

            let slice = unsafe {
                core::slice::from_raw_parts(
                    verifiers_ptr as *const u8,
                    verifiers_len as _,
                )
            };
            let verifiers: BTreeSet<Address> = BTreeSet::try_from_slice(slice).unwrap();

            // The context on WASM side is only provided by the VM once its
            // being executed (in here it's implicit). But because we want to
            // have interface identical with the native VPs, in which the
            // context is explicit, in here we're just using an empty `Ctx`
            // to "fake" it.
            let ctx = unsafe { namada_vp_prelude::Ctx::new() };

            // run validation with the concrete type(s)
            match #ident(&ctx, tx_data, addr, keys_changed, verifiers)
            {
                Ok(()) => 1,
                Err(err) => {
                    namada_vp_prelude::debug_log!("Validity predicate error: {err}");
                    let err = err.serialize_to_vec();
                    ctx.yield_value(err);
                    0
                },
            }
        }
    };
    TokenStream::from(r#gen)
}

#[proc_macro_derive(StorageKeys)]
pub fn derive_storage_keys(struct_def: TokenStream) -> TokenStream {
    derive_storage_keys_inner(struct_def.into()).into()
}

#[inline]
fn derive_storage_keys_inner(struct_def: TokenStream2) -> TokenStream2 {
    let struct_def: ItemStruct = syn::parse2(struct_def)
        .expect("Expected a struct in the StorageKeys derive");

    // type check the struct - all fields must be of type `&'static str`
    let fields = match &struct_def.fields {
        syn::Fields::Named(fields) => &fields.named,
        _ => panic!(
            "Only named struct fields are accepted in StorageKeys derives"
        ),
    };

    let mut idents = vec![];

    for field in fields {
        let field_type = field.ty.to_token_stream().to_string();
        if field_type != "& 'static str" {
            panic!(
                "Expected `&'static str` field type in StorageKeys derive, \
                 but got `{field_type}` instead"
            );
        }
        idents.push(field.ident.clone().expect("Expected a named field"));
    }

    idents.sort();

    let ident_list = create_punctuated(&idents, |ident| ident.clone());
    let values_list = create_punctuated(&idents, |ident| {
        let storage_key = ident.to_token_stream().to_string();
        syn::FieldValue {
            attrs: vec![],
            member: syn::Member::Named(ident.clone()),
            colon_token: Some(syn::token::Colon {
                spans: [Span2::call_site()],
            }),
            expr: syn::Expr::Lit(syn::ExprLit {
                attrs: vec![],
                lit: syn::Lit::Str(syn::LitStr::new(
                    storage_key.as_str(),
                    Span2::call_site(),
                )),
            }),
        }
    });

    let struct_def_ident = &struct_def.ident;

    let helper_fns = idents
        .iter()
        .fold(vec![], |mut accum, ident| {
            let is_fn = {
                let id = format!("is_{ident}_key_at_addr");
                let id = syn::Ident::new(&id, ident.span());
                quote! {
                    #[allow(missing_docs)]
                    pub fn #id(key: &namada_core::storage::Key, address: &Address) -> bool {
                        matches!(&key.segments[..], [
                            namada_core::storage::DbKeySeg::AddressSeg(a),
                            namada_core::storage::DbKeySeg::StringSeg(#ident),
                        ] if a == address && #ident == #struct_def_ident::VALUES.#ident)
                    }
                }
            };
            let get_fn = {
                let id = format!("get_{ident}_key_at_addr");
                let id = syn::Ident::new(&id, ident.span());
                quote! {
                    #[allow(missing_docs)]
                    pub fn #id(address: Address) -> namada_core::storage::Key {
                        namada_core::storage::Key {
                            segments: vec![
                                namada_core::storage::DbKeySeg::AddressSeg(address),
                                namada_core::storage::DbKeySeg::StringSeg(#struct_def_ident::VALUES.#ident.to_string()),
                            ],
                        }
                    }
                }
            };
            accum.push(is_fn);
            accum.push(get_fn);
            accum
        });

    quote! {
        impl #struct_def_ident {
            /// A list of all storage keys
            pub const ALL: &'static [&'static str] = {
                let #struct_def_ident {
                    #ident_list
                } = Self::VALUES;

                &[ #ident_list ]
            };

            /// Storage keys values
            pub const VALUES: #struct_def_ident = Self {
                #values_list
            };
        }

        #(#helper_fns)*
    }
}

#[inline]
fn create_punctuated<F, M>(
    idents: &[syn::Ident],
    mut map: F,
) -> Punctuated<M, syn::token::Comma>
where
    F: FnMut(&syn::Ident) -> M,
{
    idents.iter().fold(Punctuated::new(), |mut accum, ident| {
        accum.push(map(ident));
        accum
    })
}

#[proc_macro_derive(BorshDeserializer)]
pub fn derive_borsh_deserializer(type_def: TokenStream) -> TokenStream {
    derive_borsh_deserializer_inner(type_def.into()).into()
}

#[proc_macro]
pub fn derive_borshdeserializer(type_def: TokenStream) -> TokenStream {
    derive_borsh_deserialize_inner(type_def.into()).into()
}

#[proc_macro]
pub fn derive_typehash(type_def: TokenStream) -> TokenStream {
    let type_def = syn::parse2::<syn::Type>(type_def.into()).expect(
        "Could not parse input to `derive_borshdesrializer` as a type.",
    );
    match type_def {
        syn::Type::Array(_) | syn::Type::Tuple(_) | syn::Type::Path(_) => {}
        _ => panic!(
            "The `borsh_derserializer!` macro may only be called on arrays, \
             tuples, structs, and enums."
        ),
    }
    let (_, hash) = derive_typehash_inner(&type_def);
    quote!(
        impl TypeHash for #type_def {
            const HASH: [u8; 32] = #hash;
        }
    )
    .into()
}

#[proc_macro]
pub fn typehash(type_def: TokenStream) -> TokenStream {
    let type_def = syn::parse2::<syn::Type>(type_def.into()).expect(
        "Could not parse input to `derive_borshdesrializer` as a type.",
    );
    match type_def {
        syn::Type::Array(_) | syn::Type::Tuple(_) | syn::Type::Path(_) => {}
        _ => panic!(
            "The `borsh_derserializer!` macro may only be called on arrays, \
             tuples, structs, and enums."
        ),
    }
    let (_, hash) = derive_typehash_inner(&type_def);
    quote!(#hash).into()
}

#[inline]
fn derive_borsh_deserializer_inner(item_def: TokenStream2) -> TokenStream2 {
    let mut hasher = sha2::Sha256::new();
    let (type_def, generics) = syn::parse2::<ItemStruct>(item_def.clone())
        .map(|def| {
            hasher.update(def.to_token_stream().to_string().as_bytes());
            (def.ident, def.generics)
        })
        .unwrap_or_else(|_| {
            let def = syn::parse2::<ItemEnum>(item_def).expect(
                "BorshDeserializer expected to be derived on a struct or enum",
            );
            hasher.update(def.to_token_stream().to_string().as_bytes());
            (def.ident, def.generics)
        });
    let type_hash: [u8; 32] = hasher.finalize().into();

    if !generics.params.is_empty() {
        panic!(
            "Cannot derive BorshDeserializer on a parameterized type. This \
             can be done manually for concrete instantiations via the \
             derive_borshdeserializer! macro."
        );
    }
    let hash = syn::ExprArray {
        attrs: vec![],
        bracket_token: Default::default(),
        elems: Punctuated::<_, _>::from_iter(type_hash.into_iter().map(|b| {
            syn::Expr::Lit(syn::ExprLit {
                attrs: vec![],
                lit: syn::Lit::Byte(LitByte::new(b, Span::call_site())),
            })
        })),
    };
    let hex = data_encoding::HEXUPPER.encode(&type_hash);
    let deserializer_ident =
        syn::Ident::new(&format!("DESERIALIZER_{}", hex), Span::call_site());

    quote!(
        #[cfg(feature = "migrations")]
        #[::namada_migrations::distributed_slice(REGISTER_DESERIALIZERS)]
        static #deserializer_ident: fn() = || {
            ::namada_migrations::register_deserializer(#hash, |bytes| {
                #type_def::try_from_slice(&bytes).map(|val| format!("{:?}", val)).ok()
            });
        };
        #[cfg(feature = "migrations")]
        impl ::namada_migrations::TypeHash for #type_def {
            const HASH: [u8; 32] = #hash;
        }
    )
}

#[inline]
fn derive_borsh_deserialize_inner(item: TokenStream2) -> TokenStream2 {
    let type_def = syn::parse2::<syn::Type>(item).expect(
        "Could not parse input to `derive_borshdesrializer` as a type.",
    );
    match type_def {
        syn::Type::Array(_) | syn::Type::Tuple(_) | syn::Type::Path(_) => {}
        _ => panic!(
            "The `borsh_derserializer!` macro may only be called on arrays, \
             tuples, structs, and enums."
        ),
    }
    let (type_hash, hash) = derive_typehash_inner(&type_def);
    let hex = data_encoding::HEXUPPER.encode(&type_hash);
    let deserializer_ident =
        syn::Ident::new(&format!("DESERIALIZER_{}", hex), Span::call_site());

    quote!(
        #[cfg(feature = "migrations")]
        #[::namada_migrations::distributed_slice(REGISTER_DESERIALIZERS)]
        static #deserializer_ident: fn() = || {
            ::namada_migrations::register_deserializer(#hash, |bytes| {
                #type_def::try_from_slice(&bytes).map(|val| format!("{:?}", val)).ok()
            });
        };
    )
}

#[inline]
fn derive_typehash_inner(type_def: &syn::Type) -> ([u8; 32], syn::ExprArray) {
    let mut hasher = sha2::Sha256::new();
    hasher.update(type_def.to_token_stream().to_string().as_bytes());
    let type_hash: [u8; 32] = hasher.finalize().into();
    (
        type_hash,
        syn::ExprArray {
            attrs: vec![],
            bracket_token: Default::default(),
            elems: Punctuated::<_, _>::from_iter(type_hash.into_iter().map(
                |b| {
                    syn::Expr::Lit(syn::ExprLit {
                        attrs: vec![],
                        lit: syn::Lit::Byte(LitByte::new(b, Span::call_site())),
                    })
                },
            )),
        },
    )
}

#[cfg(test)]
mod test_proc_macros {
    use syn::File;

    use super::*;

    /// Test if we reject enums in `StorageKeys` derives.
    #[test]
    #[should_panic(expected = "Expected a struct in the StorageKeys derive")]
    fn test_storage_keys_panics_on_enum() {
        derive_storage_keys_inner(quote! {
            enum What {
                The,
                Funk,
            }
        });
    }

    /// Test if we reject unit structs in `StorageKeys` derives.
    #[test]
    #[should_panic(expected = "Only named struct fields are accepted in \
                               StorageKeys derives")]
    fn test_storage_keys_panics_on_unit_structs() {
        derive_storage_keys_inner(quote! {
            struct WhatTheFunk;
        });
    }

    /// Test if we reject tuple structs in `StorageKeys` derives.
    #[test]
    #[should_panic(expected = "Only named struct fields are accepted in \
                               StorageKeys derives")]
    fn test_storage_keys_panics_on_tuple_structs() {
        derive_storage_keys_inner(quote! {
            struct WhatTheFunk(&'static str);
        });
    }

    /// Test if the `ALL` slice generated in `StorageKeys` macro
    /// derives is sorted in ascending order.
    #[test]
    fn test_storage_keys_derive_sorted_slice() {
        let test_struct = quote! {
            struct Keys {
                word: &'static str,
                is: &'static str,
                bird: &'static str,
                the: &'static str,
            }
        };
        let test_impl: File =
            syn::parse2(derive_storage_keys_inner(test_struct))
                .expect("Test failed");

        let expected_impl = quote! {
            impl Keys {
                /// A list of all storage keys
                pub const ALL: &'static [&'static str] = {
                    let Keys { bird, is, the, word } = Self::VALUES;
                    &[bird, is, the, word]
                };

                /// Storage keys values
                pub const VALUES: Keys = Self {
                    bird: "bird",
                    is: "is",
                    the: "the",
                    word: "word"
                };
            }
            #[allow(missing_docs)]
            pub fn is_bird_key_at_addr(key: &namada_core::storage::Key, address: &Address) -> bool {
                matches!(&key.segments[..], [
                    namada_core::storage::DbKeySeg::AddressSeg(a),
                    namada_core::storage::DbKeySeg::StringSeg(bird),
                ] if a == address && bird == Keys::VALUES.bird)
            }
            #[allow(missing_docs)]
            pub fn get_bird_key_at_addr(address: Address) -> namada_core::storage::Key {
                namada_core::storage::Key {
                    segments: vec![
                        namada_core::storage::DbKeySeg::AddressSeg(address),
                        namada_core::storage::DbKeySeg::StringSeg(Keys::VALUES.bird.to_string()),
                    ],
                }
            }
            #[allow(missing_docs)]
            pub fn is_is_key_at_addr(key: &namada_core::storage::Key, address: &Address) -> bool {
                matches!(&key.segments[..], [
                    namada_core::storage::DbKeySeg::AddressSeg(a),
                    namada_core::storage::DbKeySeg::StringSeg(is),
                ] if a == address && is == Keys::VALUES.is)
            }
            #[allow(missing_docs)]
            pub fn get_is_key_at_addr(address: Address) -> namada_core::storage::Key {
                namada_core::storage::Key {
                    segments: vec![
                        namada_core::storage::DbKeySeg::AddressSeg(address),
                        namada_core::storage::DbKeySeg::StringSeg(Keys::VALUES.is.to_string()),
                    ],
                }
            }
            #[allow(missing_docs)]
            pub fn is_the_key_at_addr(key: &namada_core::storage::Key, address: &Address) -> bool {
                matches!(&key.segments[..], [
                    namada_core::storage::DbKeySeg::AddressSeg(a),
                    namada_core::storage::DbKeySeg::StringSeg(the),
                ] if a == address && the == Keys::VALUES.the)
            }
            #[allow(missing_docs)]
            pub fn get_the_key_at_addr(address: Address) -> namada_core::storage::Key {
                namada_core::storage::Key {
                    segments: vec![
                        namada_core::storage::DbKeySeg::AddressSeg(address),
                        namada_core::storage::DbKeySeg::StringSeg(Keys::VALUES.the.to_string()),
                    ],
                }
            }
            #[allow(missing_docs)]
            pub fn is_word_key_at_addr(key: &namada_core::storage::Key, address: &Address) -> bool {
                matches!(&key.segments[..], [
                    namada_core::storage::DbKeySeg::AddressSeg(a),
                    namada_core::storage::DbKeySeg::StringSeg(word),
                ] if a == address && word == Keys::VALUES.word)
            }
            #[allow(missing_docs)]
            pub fn get_word_key_at_addr(address: Address) -> namada_core::storage::Key {
                namada_core::storage::Key {
                    segments: vec![
                        namada_core::storage::DbKeySeg::AddressSeg(address),
                        namada_core::storage::DbKeySeg::StringSeg(Keys::VALUES.word.to_string()),
                    ],
                }
            }
        };
        let expected_impl: File =
            syn::parse2(expected_impl).expect("Test failed");

        pretty_assertions::assert_eq!(test_impl, expected_impl);
    }

    /// Test if we reject structs with non static string fields in
    /// `StorageKeys` macro derives.
    #[test]
    #[should_panic(
        expected = "Expected `&'static str` field type in StorageKeys derive"
    )]
    fn test_typecheck_storage_keys_derive() {
        derive_storage_keys_inner(quote! {
            struct Keys {
                x: &'static str,
                y: i32,
                z: u64,
            }
        });
    }

    /// Test if we reject structs with non static lifetimes.
    #[test]
    #[should_panic(
        expected = "Expected `&'static str` field type in StorageKeys derive"
    )]
    fn test_storage_keys_derive_with_non_static_str() {
        derive_storage_keys_inner(quote! {
            struct Keys<'a> {
                x: &'static str,
                y: &'a str,
            }
        });
    }

    /// Test that the create storage keys produces
    /// the expected code.
    #[test]
    fn test_derive_storage_keys() {
        let test_struct = quote! {
            struct Keys {
                param1: &'static str,
                param2: &'static str,
            }
        };
        let test_impl: File =
            syn::parse2(derive_storage_keys_inner(test_struct))
                .expect("Test failed");

        let expected_impl = quote! {
            impl Keys {
                /// A list of all storage keys
                pub const ALL: &'static [&'static str] = {
                    let Keys { param1, param2 } = Self::VALUES;
                    &[param1, param2]
                };
                /// Storage keys values
                pub const VALUES: Keys = Self {
                    param1: "param1",
                    param2: "param2"
                };
            }
            #[allow(missing_docs)]
            pub fn is_param1_key_at_addr(key: &namada_core::storage::Key, address: &Address) -> bool {
                matches!(&key.segments[..], [
                    namada_core::storage::DbKeySeg::AddressSeg(a),
                    namada_core::storage::DbKeySeg::StringSeg(param1),
                ] if a == address && param1 == Keys::VALUES.param1)
            }
            #[allow(missing_docs)]
            pub fn get_param1_key_at_addr(address: Address) -> namada_core::storage::Key {
                namada_core::storage::Key {
                    segments: vec![
                        namada_core::storage::DbKeySeg::AddressSeg(address),
                        namada_core::storage::DbKeySeg::StringSeg(Keys::VALUES.param1.to_string()),
                    ],
                }
            }
            #[allow(missing_docs)]
            pub fn is_param2_key_at_addr(key: &namada_core::storage::Key, address: &Address) -> bool {
                matches!(&key.segments[..], [
                    namada_core::storage::DbKeySeg::AddressSeg(a),
                    namada_core::storage::DbKeySeg::StringSeg(param2),
                ] if a == address && param2 == Keys::VALUES.param2)
            }
            #[allow(missing_docs)]
            pub fn get_param2_key_at_addr(address: Address) -> namada_core::storage::Key {
                namada_core::storage::Key {
                    segments: vec![
                        namada_core::storage::DbKeySeg::AddressSeg(address),
                        namada_core::storage::DbKeySeg::StringSeg(Keys::VALUES.param2.to_string()),
                    ],
                }
            }
        };
        let expected_impl: File =
            syn::parse2(expected_impl).expect("Test failed");

        pretty_assertions::assert_eq!(test_impl, expected_impl);
    }
}
