//! Validity predictates dependency injection soup. In here, we're assigning
//! concrete types for generic type params of native VPs.

use namada_vm::wasm::VpCache;
use namada_vm::wasm::run::VpEvalWasm;
use namada_vp::VpEnv;
use namada_vp::native_vp::{self, CtxPostStorageRead, CtxPreStorageRead};

use crate::state::StateRead;
use crate::{eth_bridge, governance, ibc, parameters, proof_of_stake, token};

/// Native VP context
pub type NativeVpCtx<'a, S, CA> =
    native_vp::Ctx<'a, S, VpCache<CA>, Eval<S, CA>>;

/// VP WASM evaluator
type Eval<S, CA> = VpEvalWasm<<S as StateRead>::D, <S as StateRead>::H, CA>;

/// Native PoS VP
pub type PosVp<'ctx, CTX> = proof_of_stake::vp::PosVp<
    'ctx,
    CTX,
    governance::Store<<CTX as VpEnv<'ctx>>::Pre>,
>;

/// Native IBC VP
pub type IbcVp<'a, S, CA> = ibc::vp::Ibc<
    'a,
    S,
    VpCache<CA>,
    Eval<S, CA>,
    ParamsIbcVpStore<'a, S, CA>,
    ParamsPreStore<'a, S, CA>,
    ParamsIbcPseudoStore<'a, S, CA>,
    GovPreStore<'a, S, CA>,
    TokenStoreForIbcExec<'a, S, CA>,
    ShieldedTokenIbcVpStore<'a, S, CA>,
    ShieldedTokenStoreForIbcExec<'a, S, CA>,
    PosPreStore<'a, S, CA>,
    token::Transfer,
>;

/// IBC VP pseudo-execution context
pub type IbcVpContext<'view, 'a, S, CA, EVAL> =
    ibc::vp::context::PseudoExecutionContext<
        'view,
        'a,
        S,
        VpCache<CA>,
        EVAL,
        TokenStoreForIbcExec<'a, S, CA>,
    >;

/// Native parameters VP
pub type ParametersVp<'ctx, CTX> = parameters::vp::ParametersVp<
    'ctx,
    CTX,
    governance::Store<<CTX as VpEnv<'ctx>>::Pre>,
>;

/// Native governance VP
pub type GovernanceVp<'ctx, CTX> = governance::vp::GovernanceVp<
    'ctx,
    CTX,
    proof_of_stake::Store<<CTX as VpEnv<'ctx>>::Pre>,
    TokenKeys,
>;

/// Native PGF VP
pub type PgfVp<'ctx, CTX> = governance::vp::pgf::PgfVp<'ctx, CTX, TokenKeys>;

/// Native multitoken VP
pub type MultitokenVp<'ctx, CTX> = token::vp::MultitokenVp<
    'ctx,
    CTX,
    parameters::Store<<CTX as VpEnv<'ctx>>::Pre>,
    governance::Store<<CTX as VpEnv<'ctx>>::Pre>,
>;

/// Native MASP VP
pub type MaspVp<'ctx, CTX> = token::vp::MaspVp<
    'ctx,
    CTX,
    parameters::Store<<CTX as VpEnv<'ctx>>::Pre>,
    governance::Store<<CTX as VpEnv<'ctx>>::Pre>,
    ibc::Store<<CTX as VpEnv<'ctx>>::Post>,
    token::Store<<CTX as VpEnv<'ctx>>::Pre>,
    token::Transfer,
>;

/// Native ETH bridge VP
pub type EthBridgeVp<'ctx, CTX> =
    eth_bridge::vp::EthBridge<'ctx, CTX, TokenKeys>;

/// Native ETH bridge pool VP
pub type EthBridgePoolVp<'ctx, CTX> =
    eth_bridge::vp::BridgePool<'ctx, CTX, TokenKeys>;

/// Native ETH bridge NUT VP
pub type EthBridgeNutVp<'ctx, CTX> =
    eth_bridge::vp::NonUsableTokens<'ctx, CTX, TokenKeys>;

/// Governance store implementation over the native prior context
pub type GovPreStore<'a, S, CA> =
    governance::Store<CtxPreStorageRead<'a, 'a, S, VpCache<CA>, Eval<S, CA>>>;

/// Parameters store implementation over the native prior context
pub type ParamsPreStore<'a, S, CA> =
    parameters::Store<CtxPreStorageRead<'a, 'a, S, VpCache<CA>, Eval<S, CA>>>;

/// PoS store implementation over the native prior context
pub type PosPreStore<'a, S, CA> = proof_of_stake::Store<
    CtxPreStorageRead<'a, 'a, S, VpCache<CA>, Eval<S, CA>>,
>;

/// Token store implementation over the native prior context
pub type TokenPreStore<'a, S, CA> =
    token::Store<CtxPreStorageRead<'a, 'a, S, VpCache<CA>, Eval<S, CA>>>;

/// Ibc store implementation over the native posterior context
pub type IbcPostStore<'a, S, CA> =
    ibc::Store<CtxPostStorageRead<'a, 'a, S, VpCache<CA>, Eval<S, CA>>>;

/// Token store impl over IBC pseudo-execution storage
pub type TokenStoreForIbcExec<'a, S, CA> = token::Store<
    ibc::vp::context::PseudoExecutionStorage<
        'a,
        'a,
        S,
        VpCache<CA>,
        Eval<S, CA>,
    >,
>;

/// Shielded token store impl over the native prior context
pub type ShieldedTokenIbcVpStore<'a, S, CA> = token::ShieldedStore<
    ibc::vp::context::VpValidationContext<'a, 'a, S, VpCache<CA>, Eval<S, CA>>,
>;

/// Shielded token store impl over IBC pseudo-execution storage
pub type ShieldedTokenStoreForIbcExec<'a, S, CA> = token::ShieldedStore<
    ibc::vp::context::PseudoExecutionStorage<
        'a,
        'a,
        S,
        VpCache<CA>,
        Eval<S, CA>,
    >,
>;

/// Parameters store implementation over the native prior context
pub type ParamsIbcVpStore<'a, S, CA> = parameters::Store<
    ibc::vp::context::VpValidationContext<'a, 'a, S, VpCache<CA>, Eval<S, CA>>,
>;

/// Parameters store implementation over the native prior context
pub type ParamsIbcPseudoStore<'a, S, CA> = parameters::Store<
    ibc::vp::context::PseudoExecutionStorage<
        'a,
        'a,
        S,
        VpCache<CA>,
        Eval<S, CA>,
    >,
>;

/// Token storage keys implementation
pub type TokenKeys = token::Store<()>;

/// Parameters storage keys implementation
pub type ParamKeys = parameters::Store<()>;
