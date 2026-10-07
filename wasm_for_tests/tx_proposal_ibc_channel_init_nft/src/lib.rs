//! A governance proposal tx that initiates an IBC channel handshake over
//! the `nft-transfer` port.
//!
//! IBC channel creation on Namada is permissioned: `ChanOpenInit` must be
//! submitted by an accepted governance proposal (the IBC VP's governance
//! bypass validates it), while everything else (the handshake steps that
//! follow) remains permissionless. This wasm executes `ChanOpenInit` for
//! the connection created beforehand by the relayer.
use ibc::core::channel::types::channel::Order;
use ibc::core::channel::types::msgs::MsgChannelOpenInit;
use ibc::core::channel::types::Version;
use ibc::core::host::types::identifiers::{ConnectionId, PortId};
use ibc::primitives::{Signer, ToProto, ToVec};
use namada_tx_prelude::*;

/// The ICS-721 version string
const ICS721_VERSION: &str = "ics721-1";
/// The connection established by the relayer before the proposal
const CONNECTION_ID: u64 = 0;
/// The ICS-721 port, as `PortId::new` is fallible
const NFT_PORT: &str = "nft-transfer";
/// The port of the ICS-721 contract on the CosmWasm chain used in the e2e
/// tests. A contract's port is derived from its address, which in turn is
/// derived from its code ID and instance ID: the tests always instantiate
/// the ICS-721 contract second, after the CW-721 one.
const COUNTERPARTY_NFT_PORT: &str =
    "wasm.wasm1nc5tatafv6eyq7llkr2gv50ff9e22mnf70qgjlv737ktmt4eswrqr5j2ht";

#[transaction]
fn apply_tx(ctx: &mut Ctx, _tx_data: BatchedTx) -> TxResult {
    let msg = MsgChannelOpenInit {
        port_id_on_a: PortId::new(NFT_PORT.to_string()).unwrap(),
        connection_hops_on_a: vec![ConnectionId::new(CONNECTION_ID)],
        port_id_on_b: PortId::new(COUNTERPARTY_NFT_PORT.to_string()).unwrap(),
        ordering: Order::Unordered,
        signer: Signer::from("governance-proposal".to_string()),
        version_proposal: Version::new(ICS721_VERSION.to_string()),
    };

    ibc::ibc_actions(ctx)
        .execute::<token::Transfer>(&msg.to_any().to_vec())
        .into_storage_result()?;

    Ok(())
}
