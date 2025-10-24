//! CLI input types can be used for command arguments

use std::env;
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use color_eyre::eyre::Result;
use masp_primitives::zip32::sapling::PseudoExtendedKey;
use masp_primitives::zip32::{
    ExtendedFullViewingKey as MaspExtendedViewingKey,
    ExtendedSpendingKey as MaspExtendedSpendingKey,
};
use namada_core::masp::{
    BalanceOwner, ExtendedSpendingKey, ExtendedViewingKey, PaymentAddress,
    TransferSource, TransferTarget,
};
use namada_sdk::address::Address;
use namada_sdk::chain::ChainId;
use namada_sdk::ibc::trace::{ibc_token, is_ibc_denom, is_nft_trace};
use namada_sdk::io::Io;
use namada_sdk::key::*;
use namada_sdk::masp::ShieldedWallet;
use namada_sdk::masp::fs::FsShieldedUtils;
use namada_sdk::wallet::{DatedSpendingKey, DatedViewingKey, Wallet};
use namada_sdk::{Namada, NamadaImpl};

use super::args;
use crate::cli::utils;
use crate::config::global::GlobalConfig;
use crate::config::{Config, genesis};
use crate::wallet::CliWalletUtils;
use crate::{wallet, wasm_loader};

/// Skip errors encountered while parsing raw string values.
struct SkipErr;

/// Env. var to set wasm directory
pub const ENV_VAR_WASM_DIR: &str = "NAMADA_WASM_DIR";

/// Env. var to read the Namada chain id from
pub const ENV_VAR_CHAIN_ID: &str = "NAMADA_CHAIN_ID";

/// A raw address (bech32m encoding) or an alias of an address that may be found
/// in the wallet
pub type WalletAddress = FromContext<Address>;

/// A raw address (bech32m encoding) or an alias of an address that may be found
/// in the wallet. Defaults to the native token address.
pub type WalletAddrOrNativeToken = FromContext<AddrOrNativeToken>;

/// A raw extended spending key (bech32m encoding) or an alias of an extended
/// spending key in the wallet
pub type WalletSpendingKey = FromContext<PseudoExtendedKey>;

/// A raw dated extended spending key (bech32m encoding) or an alias of an
/// extended spending key in the wallet
pub type WalletDatedSpendingKey = FromContext<DatedSpendingKey>;

/// A raw payment address (bech32m encoding) or an alias of a payment address
/// in the wallet
pub type WalletPaymentAddr = FromContext<PaymentAddress>;

/// A raw full viewing key (bech32m encoding) or an alias of a full viewing key
/// in the wallet
pub type WalletViewingKey = FromContext<ExtendedViewingKey>;

/// A raw full dated viewing key (bech32m encoding) or an alias of a full
/// viewing key in the wallet
pub type WalletDatedViewingKey = FromContext<DatedViewingKey>;

/// A raw address or a raw extended spending key (bech32m encoding) or an alias
/// of either in the wallet
pub type WalletTransferSource = FromContext<TransferSource>;

/// A raw address or a raw payment address (bech32m encoding) or an alias of
/// either in the wallet
pub type WalletTransferTarget = FromContext<TransferTarget>;

/// A raw keypair (hex encoding), an alias, a public key or a public key hash of
/// a keypair that may be found in the wallet
pub type WalletKeypair = FromContext<common::SecretKey>;

/// A raw public key (hex encoding), a public key hash (also hex encoding) or an
/// alias of an public key that may be found in the wallet
pub type WalletPublicKey = FromContext<common::PublicKey>;

/// A raw address or a raw full viewing key (bech32m encoding) or an alias of
/// either in the wallet
pub type WalletBalanceOwner = FromContext<BalanceOwner>;

/// RPC address of a locally configured node
pub type ConfigRpcAddress = FromContext<tendermint_rpc::Url>;

/// Address that defaults to the native token address.
#[derive(Clone, Debug)]
pub struct AddrOrNativeToken(Address);

impl From<AddrOrNativeToken> for Address {
    fn from(AddrOrNativeToken(addr): AddrOrNativeToken) -> Self {
        addr
    }
}

impl FromStr for AddrOrNativeToken {
    type Err = <Address as FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let addr = Address::from_str(s)?;
        Ok(Self(addr))
    }
}

impl From<tendermint_rpc::Url> for ConfigRpcAddress {
    fn from(value: tendermint_rpc::Url) -> Self {
        FromContext::new(value.to_string())
    }
}

/// Command execution context
#[derive(Debug)]
pub struct Context {
    /// Global arguments
    pub global_args: args::Global,
    /// The global configuration
    pub global_config: GlobalConfig,
    /// Chain-specific context, if any chain is configured in `global_config`
    pub chain: Option<ChainContext>,
}

/// Command execution context with chain-specific data
#[derive(Debug)]
pub struct ChainContext {
    /// The wallet
    pub wallet: Wallet<CliWalletUtils>,
    /// The ledger configuration for a specific chain ID
    pub config: Config,
    /// The context fr shielded operations
    pub shielded: ShieldedWallet<FsShieldedUtils>,
    /// Native token's address
    pub native_token: Address,
}

/// Convenience function wrapping over [`wasm_dir_from_env_or`].
pub fn wasm_dir_from_env_or_args(
    global_args: &args::Global,
) -> Option<PathBuf> {
    wasm_dir_from_env_or(global_args.wasm_dir.as_ref())
}

/// Return the wasm artifacts path in use.
pub fn wasm_dir_from_env_or<P: AsRef<Path>>(
    wasm_dir: Option<&P>,
) -> Option<PathBuf> {
    wasm_dir
        .map(|wasm_dir| wasm_dir.as_ref().to_owned())
        .or_else(|| {
            env::var(ENV_VAR_WASM_DIR)
                .ok()
                .map(|wasm_dir| wasm_dir.into())
        })
}

impl Context {
    pub fn new<IO: Io>(global_args: args::Global) -> Result<Self> {
        let global_config = read_or_try_new_global_config(&global_args);

        let env_var_chain_id = std::env::var(ENV_VAR_CHAIN_ID)
            .ok()
            .and_then(|chain_id| ChainId::from_str(&chain_id).ok());
        let chain_id = env_var_chain_id
            .as_ref()
            .or(global_args.chain_id.as_ref())
            .or(global_config.default_chain_id.as_ref());

        let chain = match chain_id {
            Some(chain_id) if !global_args.is_pre_genesis => {
                let mut config =
                    Config::load(&global_args.base_dir, chain_id, None);
                let chain_dir = global_args.base_dir.join(chain_id.as_str());
                let native_token =
                    genesis::chain::Finalized::read_native_token(&chain_dir)
                        .expect("Missing genesis files");
                let wallet = if wallet::exists(&chain_dir) {
                    wallet::load(&chain_dir).unwrap()
                } else {
                    panic!(
                        "Could not find wallet at {}.",
                        chain_dir.to_string_lossy()
                    );
                };

                // Put WASM dir path in the config
                if let Some(wasm_dir) = wasm_dir_from_env_or_args(&global_args)
                {
                    config.wasm_dir = wasm_dir;
                }

                Some(ChainContext {
                    wallet,
                    config,
                    shielded: FsShieldedUtils::new(chain_dir),
                    native_token,
                })
            }
            _ => None,
        };

        Ok(Self {
            global_args,
            global_config,
            chain,
        })
    }

    /// Try to take the chain context, or exit the process with an error if no
    /// chain is configured.
    pub fn take_chain_or_exit(self) -> ChainContext {
        self.chain
            .unwrap_or_else(|| safe_exit_on_missing_chain_context())
    }

    /// Try to borrow chain context, or exit the process with an error if no
    /// chain is configured.
    pub fn borrow_chain_or_exit(&self) -> &ChainContext {
        self.chain
            .as_ref()
            .unwrap_or_else(|| safe_exit_on_missing_chain_context())
    }

    /// Try to borrow mutably chain context, or exit the process with an error
    /// if no chain is configured.
    pub fn borrow_mut_chain_or_exit(&mut self) -> &mut ChainContext {
        self.chain
            .as_mut()
            .unwrap_or_else(|| safe_exit_on_missing_chain_context())
    }

    /// Make an implementation of Namada from this object and parameters.
    pub fn to_sdk<C, IO>(self, client: C, io: IO) -> impl Namada
    where
        C: namada_sdk::io::Client + Sync,
        IO: Io,
    {
        let chain_ctx = self.take_chain_or_exit();
        NamadaImpl::native_new(
            client,
            chain_ctx.wallet,
            chain_ctx.shielded,
            io,
            chain_ctx.native_token,
        )
    }
}

fn safe_exit_on_missing_chain_context() -> ! {
    eprintln!(
        "Failed to construct Namada chain context. If no chain is configured, \
         you may need to run `namada client utils join-network`. If the chain \
         is configured, you may need to set the chain id with `--chain-id \
         <chainid>`, via the env var `{ENV_VAR_CHAIN_ID}`, or configure the \
         default chain id in the `global-config.toml` file. If you do intend \
         to run pre-genesis operations, pass the `--pre-genesis` flag as the \
         first argument to the command."
    );
    utils::safe_exit(1)
}

impl ChainContext {
    /// Parse and/or look-up the value from the context.
    pub fn get<T>(&self, from_context: &FromContext<T>) -> T
    where
        T: ArgFromContext,
    {
        from_context.arg_from_ctx(self).unwrap()
    }

    /// Try to parse and/or look-up an optional value from the context.
    pub fn get_opt<T>(&self, from_context: &Option<FromContext<T>>) -> Option<T>
    where
        T: ArgFromContext,
    {
        from_context
            .as_ref()
            .map(|from_context| from_context.arg_from_ctx(self).unwrap())
    }

    /// Parse and/or look-up the value from the context with cache.
    pub fn get_cached<T>(&mut self, from_context: &FromContext<T>) -> T
    where
        T: ArgFromMutContext,
    {
        from_context.arg_from_mut_ctx(self).unwrap()
    }

    /// Try to parse and/or look-up an optional value from the context with
    /// cache.
    pub fn get_opt_cached<T>(
        &mut self,
        from_context: &Option<FromContext<T>>,
    ) -> Option<T>
    where
        T: ArgFromMutContext,
    {
        from_context
            .as_ref()
            .map(|from_context| from_context.arg_from_mut_ctx(self).unwrap())
    }

    /// Get the wasm directory configured for the chain.
    ///
    /// Note that in "dev" build, this may be the root `wasm` dir.
    pub fn wasm_dir(&self) -> PathBuf {
        self.config.ledger.chain_dir().join(&self.config.wasm_dir)
    }

    /// Read the given WASM file from the WASM directory or an absolute path.
    pub fn read_wasm(&self, file_name: impl AsRef<Path>) -> Vec<u8> {
        wasm_loader::read_wasm_or_exit(self.wasm_dir(), file_name)
    }
}

/// Load global config from expected path in the `base_dir` or try to generate a
/// new one without a chain if it doesn't exist.
pub fn read_or_try_new_global_config(
    global_args: &args::Global,
) -> GlobalConfig {
    GlobalConfig::read(&global_args.base_dir).unwrap_or_else(|err| {
        eprintln!("Error reading global config: {}", err);
        super::safe_exit(1)
    })
}

/// Argument that can be given raw or found in the [`Context`].
#[derive(Debug, Clone)]
pub struct FromContext<T> {
    pub(crate) raw: String,
    phantom: PhantomData<T>,
}

impl<T> FromContext<T> {
    pub fn new(raw: String) -> FromContext<T> {
        Self {
            raw,
            phantom: PhantomData,
        }
    }
}

impl From<FromContext<Address>> for FromContext<AddrOrNativeToken> {
    fn from(value: FromContext<Address>) -> Self {
        Self {
            raw: value.raw,
            phantom: PhantomData,
        }
    }
}

impl FromContext<TransferSource> {
    /// Converts this TransferSource argument to an Address. Call this function
    /// only when certain that raw represents an Address.
    pub fn to_address(&self) -> FromContext<Address> {
        FromContext::<Address> {
            raw: self.raw.clone(),
            phantom: PhantomData,
        }
    }

    /// Converts this TransferSource argument to an ExtendedSpendingKey. Call
    /// this function only when certain that raw represents an
    /// ExtendedSpendingKey.
    pub fn to_spending_key(&self) -> FromContext<ExtendedSpendingKey> {
        FromContext::<ExtendedSpendingKey> {
            raw: self.raw.clone(),
            phantom: PhantomData,
        }
    }
}

impl FromContext<TransferTarget> {
    /// Converts this TransferTarget argument to an Address. Call this function
    /// only when certain that raw represents an Address.
    pub fn to_address(&self) -> FromContext<Address> {
        FromContext::<Address> {
            raw: self.raw.clone(),
            phantom: PhantomData,
        }
    }

    /// Converts this TransferTarget argument to a PaymentAddress. Call this
    /// function only when certain that raw represents a PaymentAddress.
    pub fn to_payment_address(&self) -> FromContext<PaymentAddress> {
        FromContext::<PaymentAddress> {
            raw: self.raw.clone(),
            phantom: PhantomData,
        }
    }
}

impl<T> FromContext<T>
where
    T: ArgFromContext,
{
    /// Parse and/or look-up the value from the chain context.
    fn arg_from_ctx(&self, ctx: &ChainContext) -> Result<T, String> {
        T::arg_from_ctx(ctx, &self.raw)
    }
}

impl<T> FromContext<T>
where
    T: ArgFromMutContext,
{
    /// Parse and/or look-up the value from the mutable chain context.
    fn arg_from_mut_ctx(&self, ctx: &mut ChainContext) -> Result<T, String> {
        T::arg_from_mut_ctx(ctx, &self.raw)
    }
}

/// CLI argument that found via the [`ChainContext`].
pub trait ArgFromContext: Sized {
    fn arg_from_ctx(
        ctx: &ChainContext,
        raw: impl AsRef<str>,
    ) -> Result<Self, String>;
}

/// CLI argument that found via the [`ChainContext`] and cached (as in case of
/// an encrypted keypair that has been decrypted), hence using mutable context.
pub trait ArgFromMutContext: Sized {
    fn arg_from_mut_ctx(
        ctx: &mut ChainContext,
        raw: impl AsRef<str>,
    ) -> Result<Self, String>;
}

impl ArgFromContext for Address {
    fn arg_from_ctx(
        ctx: &ChainContext,
        raw: impl AsRef<str>,
    ) -> Result<Self, String> {
        let raw = raw.as_ref();
        // An address can be either raw (bech32m encoding)
        FromStr::from_str(raw)
            // Or an IBC token
            .or_else(|_| {
                is_ibc_denom(raw)
                    .map(|(trace_path, base_denom)| {
                        let base_token = ctx
                            .wallet
                            .find_address(&base_denom)
                            .filter(|addr| **addr == ctx.native_token)
                            .map(|addr| addr.to_string())
                            .unwrap_or(base_denom);
                        let ibc_denom = format!("{trace_path}/{base_token}");
                        ibc_token(ibc_denom)
                    })
                    .ok_or(SkipErr)
            })
            .or_else(|_| {
                is_nft_trace(raw)
                    .map(|(_, _, _)| ibc_token(raw))
                    .ok_or(SkipErr)
            })
            // Or it can be an alias that may be found in the wallet
            .or_else(|_| {
                ctx.wallet
                    .find_address(raw)
                    .map(|x| x.into_owned())
                    .ok_or(SkipErr)
            })
            .map_err(|_| format!("Unknown address {raw}"))
    }
}

impl ArgFromContext for AddrOrNativeToken {
    fn arg_from_ctx(
        ctx: &ChainContext,
        raw: impl AsRef<str>,
    ) -> Result<Self, String> {
        if let Ok(addr) = Address::arg_from_ctx(ctx, raw) {
            Ok(Self(addr))
        } else {
            Ok(Self(ctx.native_token.clone()))
        }
    }
}

impl ArgFromContext for tendermint_rpc::Url {
    fn arg_from_ctx(
        ctx: &ChainContext,
        raw: impl AsRef<str>,
    ) -> Result<Self, String> {
        if raw.as_ref().is_empty() {
            return Self::from_str(
                &ctx.config
                    .ledger
                    .cometbft
                    .rpc
                    .laddr
                    .to_string()
                    .replace("tcp", "http"),
            )
            .map_err(|err| format!("Invalid Tendermint address: {err}"));
        }
        Self::from_str(raw.as_ref())
            .map_err(|err| format!("Invalid Tendermint address: {err}"))
    }
}

impl ArgFromMutContext for common::SecretKey {
    fn arg_from_mut_ctx(
        ctx: &mut ChainContext,
        raw: impl AsRef<str>,
    ) -> Result<Self, String> {
        let raw = raw.as_ref();
        // A keypair can be either a raw keypair in hex string
        FromStr::from_str(raw).or_else(|_parse_err| {
            // Or it can be an alias
            ctx.wallet
                .find_secret_key(raw, None)
                .map_err(|_find_err| format!("Unknown key {}", raw))
        })
    }
}

impl ArgFromContext for common::PublicKey {
    fn arg_from_ctx(
        ctx: &ChainContext,
        raw: impl AsRef<str>,
    ) -> Result<Self, String> {
        let raw = raw.as_ref();
        // A public key can either be a bech32 encoded (tpknam1...) string
        FromStr::from_str(raw)
            .map_err(|_| SkipErr)
            // Or it can be a hex encoded public key hash
            .or_else(|SkipErr| {
                FromStr::from_str(raw).map_err(|_| SkipErr).and_then(
                    |pkh: PublicKeyHash| {
                        ctx.wallet
                            .find_public_key_by_pkh(&pkh)
                            .map_err(|_| SkipErr)
                    },
                )
            })
            // Or it can be an alias that may be found in the wallet
            .or_else(|SkipErr| {
                ctx.wallet.find_public_key(raw).map_err(|_| SkipErr)
            })
            // Or it can be an implicit address
            .or_else(|SkipErr| {
                let Address::Implicit(implicit_addr) =
                    Address::decode(raw).map_err(|_| SkipErr)?
                else {
                    return Err(SkipErr);
                };
                ctx.wallet
                    .find_public_key_from_implicit_addr(&implicit_addr)
                    .map_err(|_| SkipErr)
            })
            .map_err(|SkipErr| {
                format!("Couldn't look-up public key associated with {raw:?}")
            })
    }
}

impl ArgFromMutContext for ExtendedSpendingKey {
    fn arg_from_mut_ctx(
        ctx: &mut ChainContext,
        raw: impl AsRef<str>,
    ) -> Result<Self, String> {
        let raw = raw.as_ref();
        // Either the string is a raw extended spending key
        FromStr::from_str(raw).or_else(|_parse_err| {
            // Or it is a stored alias of one
            ctx.wallet
                .find_spending_key(raw, None)
                .map_err(|_find_err| format!("Unknown spending key {}", raw))
        })
    }
}

impl ArgFromMutContext for PseudoExtendedKey {
    fn arg_from_mut_ctx(
        ctx: &mut ChainContext,
        raw: impl AsRef<str>,
    ) -> Result<Self, String> {
        let raw = raw.as_ref();
        // Either the string is a raw extended spending key
        ExtendedSpendingKey::from_str(raw)
            .map(|x| PseudoExtendedKey::from(MaspExtendedSpendingKey::from(x)))
            .or_else(|_parse_err| {
                ExtendedViewingKey::from_str(raw).map(|x| {
                    PseudoExtendedKey::from(MaspExtendedViewingKey::from(x))
                })
            })
            .or_else(|_parse_err| {
                // Or it is a stored alias of one
                ctx.wallet
                    .find_spending_key(raw, None)
                    .map(|k| {
                        PseudoExtendedKey::from(MaspExtendedSpendingKey::from(
                            k,
                        ))
                    })
                    .map_err(|_find_err| {
                        format!("Unknown spending key {}", raw)
                    })
            })
            .or_else(|_parse_err| {
                // Or it is a stored alias of one
                ctx.wallet
                    .find_viewing_key(raw)
                    .copied()
                    .map(|k| {
                        PseudoExtendedKey::from(MaspExtendedViewingKey::from(k))
                    })
                    .map_err(|_find_err| format!("Unknown viewing key {}", raw))
            })
    }
}

impl ArgFromMutContext for DatedSpendingKey {
    fn arg_from_mut_ctx(
        ctx: &mut ChainContext,
        raw: impl AsRef<str>,
    ) -> Result<Self, String> {
        let raw = raw.as_ref();
        // Either the string is a raw extended spending key
        FromStr::from_str(raw).or_else(|_parse_err| {
            // Or it is a stored alias of one
            let sk = ctx
                .wallet
                .find_spending_key(raw, None)
                .map_err(|_find_err| format!("Unknown spending key {}", raw))?;
            let birthday = ctx.wallet.find_birthday(raw);
            Ok(DatedSpendingKey::new(sk, birthday.copied()))
        })
    }
}

impl ArgFromMutContext for ExtendedViewingKey {
    fn arg_from_mut_ctx(
        ctx: &mut ChainContext,
        raw: impl AsRef<str>,
    ) -> Result<Self, String> {
        let raw = raw.as_ref();
        // Either the string is a raw full viewing key
        FromStr::from_str(raw).or_else(|_parse_err| {
            // Or it is a stored alias of one
            ctx.wallet
                .find_viewing_key(raw)
                .copied()
                .map_err(|_find_err| format!("Unknown viewing key {}", raw))
        })
    }
}

impl ArgFromMutContext for DatedViewingKey {
    fn arg_from_mut_ctx(
        ctx: &mut ChainContext,
        raw: impl AsRef<str>,
    ) -> Result<Self, String> {
        let raw = raw.as_ref();
        // Either the string is a raw full viewing key
        FromStr::from_str(raw).or_else(|_parse_err| {
            // Or it is a stored alias of one
            let vk = ctx
                .wallet
                .find_viewing_key(raw)
                .map_err(|_find_err| format!("Unknown viewing key {}", raw))?;
            let birthday = ctx.wallet.find_birthday(raw);
            Ok(DatedViewingKey::new(*vk, birthday.copied()))
        })
    }
}

impl ArgFromContext for PaymentAddress {
    fn arg_from_ctx(
        ctx: &ChainContext,
        raw: impl AsRef<str>,
    ) -> Result<Self, String> {
        let raw = raw.as_ref();
        // Either the string is a payment address
        FromStr::from_str(raw).or_else(|_parse_err| {
            // Or it is a stored alias of one
            ctx.wallet
                .find_payment_addr(raw)
                .cloned()
                .ok_or_else(|| format!("Unknown payment address {}", raw))
        })
    }
}

impl ArgFromMutContext for TransferSource {
    fn arg_from_mut_ctx(
        ctx: &mut ChainContext,
        raw: impl AsRef<str>,
    ) -> Result<Self, String> {
        let raw = raw.as_ref();
        // Either the string is a transparent address or a spending key
        Address::arg_from_ctx(ctx, raw)
            .map(Self::Address)
            .or_else(|_| {
                ExtendedSpendingKey::arg_from_mut_ctx(ctx, raw).map(|x| {
                    Self::ExtendedKey(PseudoExtendedKey::from(
                        MaspExtendedSpendingKey::from(x),
                    ))
                })
            })
            .or_else(|_| {
                ExtendedViewingKey::arg_from_mut_ctx(ctx, raw).map(|x| {
                    Self::ExtendedKey(PseudoExtendedKey::from(
                        MaspExtendedViewingKey::from(x),
                    ))
                })
            })
    }
}

impl ArgFromContext for TransferTarget {
    fn arg_from_ctx(
        ctx: &ChainContext,
        raw: impl AsRef<str>,
    ) -> Result<Self, String> {
        let raw = raw.as_ref();
        // Either the string is a transparent address or a payment address
        Address::arg_from_ctx(ctx, raw)
            .map(Self::Address)
            .or_else(|_| {
                PaymentAddress::arg_from_ctx(ctx, raw).map(Self::PaymentAddress)
            })
    }
}

impl ArgFromMutContext for BalanceOwner {
    fn arg_from_mut_ctx(
        ctx: &mut ChainContext,
        raw: impl AsRef<str>,
    ) -> Result<Self, String> {
        let raw = raw.as_ref();
        // Either the string is a transparent address or a viewing key
        Address::arg_from_ctx(ctx, raw)
            .map(Self::Address)
            .or_else(|_| {
                ExtendedViewingKey::arg_from_mut_ctx(ctx, raw)
                    .map(Self::FullViewingKey)
            })
            .map_err(|_| {
                format!(
                    "Could not find {raw} in the wallet, nor parse it as a \
                     transparent address or as a MASP viewing key"
                )
            })
    }
}
