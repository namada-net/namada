//! IBC storage context

pub use ics23::ProofSpec;
use namada_core::address::Address;
use namada_core::masp_primitives::asset_type::AssetType;
use namada_core::token::Amount;
use namada_events::Event;
use namada_state::{Result, StorageRead, StorageWrite};

/// IBC context trait to be implemented in integration that can read and write
pub trait IbcStorageContext {
    /// Storage read/write type
    type Storage: StorageRead + StorageWrite;

    /// Read-only storage access
    fn storage(&self) -> &Self::Storage;

    /// Read/write storage access
    fn storage_mut(&mut self) -> &mut Self::Storage;

    /// Check if a conversion exists
    fn has_conversion(&self, asset_type: &AssetType) -> Result<bool>;

    /// Emit an event
    fn emit_event(&mut self, event: Event) -> Result<()>;

    /// Transfer token
    fn transfer_token(
        &mut self,
        src: &Address,
        dest: &Address,
        token: &Address,
        amount: Amount,
    ) -> Result<()>;

    /// Mint token
    fn mint_token(
        &mut self,
        target: &Address,
        token: &Address,
        amount: Amount,
    ) -> Result<()>;

    /// Burn token
    fn burn_token(
        &mut self,
        target: &Address,
        token: &Address,
        amount: Amount,
    ) -> Result<()>;

    /// Insert the verifier
    fn insert_verifier(&mut self, verifier: &Address) -> Result<()>;

    /// Logging
    fn log_string(&self, message: String);
}
