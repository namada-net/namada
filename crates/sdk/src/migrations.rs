#![allow(missing_docs)]

use core::fmt::{Display, Formatter};
use core::str::FromStr;
use std::path::{Path, PathBuf};

use borsh::{BorshDeserialize, BorshSerialize};
use data_encoding::HEXUPPER;
use eyre::eyre;
use namada_core::chain::BlockHeight;
use namada_core::hash::Hash;
use namada_core::storage;
use namada_macros::{derive_borshdeserializer, typehash};
use namada_migrations::{TypeHash, *};
use namada_state::merkle_tree::NO_DIFF_KEY_PREFIX;
use namada_state::{DBIter, FullAccessState, KeySeg, StorageHasher};
use namada_storage::{DB, DBUpdateVisitor, DbColFam};
use regex::Regex;
use serde::de::{Error, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::borsh::BorshSerializeExt;

/// The maximum number of character printed per value.
const PRINTLN_CUTOFF: usize = 300;

/// For migrations involving the conversion state
pub const CONVERSION_STATE_KEY: &str = "conversion_state";
/// Key holding minimum start height for next epoch
pub const NEXT_EPOCH_MIN_START_HEIGHT_KEY: &str = "next_epoch_min_start_height";
/// Key holding minimum start time for next epoch
pub const NEXT_EPOCH_MIN_START_TIME_KEY: &str = "next_epoch_min_start_time";
/// Key holding number of blocks till next epoch
pub const UPDATE_EPOCH_BLOCKS_DELAY_KEY: &str = "update_epoch_blocks_delay";

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
enum UpdateBytes {
    Raw {
        to_write: Vec<u8>,
        serialized: Vec<u8>,
    },
    Serialized {
        bytes: Vec<u8>,
    },
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
/// A value to be added to the database that can be
/// validated.
pub struct UpdateValue {
    type_hash: [u8; 32],
    bytes: UpdateBytes,
}

impl UpdateValue {
    /// Using a type that is a thin wrapper around bytes but with a custom
    /// serialization when we don't want to use Borsh necessarily
    pub fn raw<T>(value: T) -> Self
    where
        T: TypeHash + AsRef<[u8]> + BorshSerialize + BorshDeserialize,
    {
        Self {
            type_hash: T::HASH,
            bytes: UpdateBytes::Raw {
                to_write: value.as_ref().to_vec(),
                serialized: value.serialize_to_vec(),
            },
        }
    }

    /// Using a type that is Borsh-serializable but we don't have an
    /// implementation for conversion yet. Must provide `force: true`
    pub fn wrapped<T>(value: T) -> Self
    where
        T: BorshSerialize + BorshDeserialize,
        SerializeWrapper<T>: TypeHash,
    {
        SerializeWrapper(value).into()
    }

    /// Using a type that is Borsh-serializable but we don't have an
    /// implementation for conversion yet. Must provide `force: true`
    pub fn force_borsh<T>(value: T) -> Self
    where
        T: BorshSerialize + BorshDeserialize,
    {
        Self {
            type_hash: Default::default(),
            bytes: UpdateBytes::Serialized {
                bytes: value.serialize_to_vec(),
            },
        }
    }

    pub fn is_raw(&self) -> bool {
        matches!(self.bytes, UpdateBytes::Raw { .. })
    }

    fn bytes(&self) -> &[u8] {
        match &self.bytes {
            UpdateBytes::Raw { serialized, .. } => serialized,
            UpdateBytes::Serialized { bytes } => bytes,
        }
    }

    /// The value to write to storage
    fn to_write(&self) -> Vec<u8> {
        match &self.bytes {
            UpdateBytes::Raw { to_write, .. } => to_write.clone(),
            UpdateBytes::Serialized { bytes } => bytes.clone(),
        }
    }
}

impl<T: TypeHash + BorshSerialize + BorshDeserialize> From<T> for UpdateValue {
    fn from(value: T) -> Self {
        Self {
            type_hash: T::HASH,
            bytes: UpdateBytes::Serialized {
                bytes: value.serialize_to_vec(),
            },
        }
    }
}

#[derive(Default)]
struct UpdateValueVisitor;

impl Visitor<'_> for UpdateValueVisitor {
    type Value = UpdateValue;

    fn expecting(&self, formatter: &mut Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(
            "a hex encoded series of bytes that borsh decode to an \
             UpdateValue.",
        )
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: Error,
    {
        UpdateValue::try_from_slice(
            &HEXUPPER
                .decode(v.as_bytes())
                .map_err(|e| E::custom(e.to_string()))?,
        )
        .map_err(|e| E::custom(e.to_string()))
    }
}

impl Serialize for UpdateValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let hex_bytes = HEXUPPER.encode(&self.serialize_to_vec());
        Serialize::serialize(&hex_bytes, serializer)
    }
}

impl<'de> Deserialize<'de> for UpdateValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(UpdateValueVisitor)
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
/// An update to the database
pub enum DbUpdateType {
    Add {
        key: storage::Key,
        cf: DbColFam,
        value: UpdateValue,
        force: bool,
    },
    Delete(storage::Key, DbColFam),
    RepeatAdd {
        pattern: String,
        cf: DbColFam,
        value: UpdateValue,
        force: bool,
    },
    RepeatDelete(String, DbColFam),
}

impl DbUpdateType {
    /// Get the key or pattern being modified as string
    pub fn pattern(&self) -> String {
        match self {
            DbUpdateType::Add { key, .. } => key.to_string(),
            DbUpdateType::Delete(key, ..) => key.to_string(),
            DbUpdateType::RepeatAdd { pattern, .. } => pattern.to_string(),
            DbUpdateType::RepeatDelete(pattern, ..) => pattern.to_string(),
        }
    }

    fn is_force(&self) -> bool {
        match self {
            DbUpdateType::Add { force, .. } => *force,
            DbUpdateType::RepeatAdd { force, .. } => *force,
            _ => false,
        }
    }

    fn formatted_bytes(&self) -> String {
        match self {
            DbUpdateType::Add { value, .. }
            | DbUpdateType::RepeatAdd { value, .. } => {
                if value.to_write().len() > PRINTLN_CUTOFF {
                    format!("{:?} ...", &value.bytes()[..PRINTLN_CUTOFF])
                } else {
                    format!("{:?}", value.bytes())
                }
            }
            _ => String::default(),
        }
    }

    /// Validate that the contained value deserializes correctly given its data
    /// hash and the value is not "raw". Return the string formatted value and,
    /// if the value is not "raw", the deserializer function.
    pub fn validate(
        &self,
    ) -> eyre::Result<(String, Option<CbFromByteArrayToTypeName>)> {
        // skip all checks if force == true
        if self.is_force() {
            return Ok((self.formatted_bytes(), None));
        }
        let key_or_pattern = self.pattern();
        match self {
            DbUpdateType::RepeatAdd { value, .. }
            | DbUpdateType::Add { value, .. } => {
                let deserializer =
                    namada_migrations::get_deserializer(&value.type_hash)
                        .ok_or_else(|| {
                            eyre::eyre!(
                                "Type hash {:?} did not correspond to a \
                                 deserializer in TYPE_DESERIALIZERS.",
                                value.type_hash
                            )
                        })?;
                let deserialized = deserializer(value.bytes().to_vec())
                    .ok_or_else(|| {
                        eyre::eyre!(
                            "The value {:?} for key/pattern {} could not be \
                             successfully deserialized",
                            value.bytes(),
                            key_or_pattern,
                        )
                    })?;
                let deserializer = (!value.is_raw()).then_some(deserializer);
                if deserialized.len() > PRINTLN_CUTOFF {
                    Ok((
                        format!(
                            "{} ...",
                            deserialized
                                .chars()
                                .take(PRINTLN_CUTOFF)
                                .collect::<String>()
                        ),
                        deserializer,
                    ))
                } else {
                    Ok((deserialized, deserializer))
                }
            }
            DbUpdateType::Delete(_, _) | DbUpdateType::RepeatDelete(_, _) => {
                Ok((String::default(), None))
            }
        }
    }

    /// Validate a DB change and persist it if so. The debug representation of
    /// the new value is returned for logging purposes.
    pub fn update<D, H>(
        &self,
        state: &mut FullAccessState<D, H>,
    ) -> eyre::Result<UpdateStatus>
    where
        D: 'static + DB + for<'iter> DBIter<'iter>,
        H: 'static + StorageHasher,
    {
        let mut migrator = D::migrator();
        let status = match self {
            Self::Add { key, cf, value, .. } => {
                let (deserialized, deserializer) = self.validate()?;
                if let (Some(prev), Some(des)) =
                    (migrator.read(state.db(), key, cf), deserializer)
                {
                    des(prev).ok_or_else(|| {
                        eyre::eyre!(
                            "The previous value under the key {} did not have \
                             the same type as that provided: Input was {}",
                            key,
                            deserialized
                        )
                    })?;
                }
                let value = value.bytes();
                let persist_diffs = (state.diff_key_filter)(key);
                if let DbColFam::SUBSPACE = cf {
                    // Update the merkle tree
                    let merk_key = if !persist_diffs {
                        let prefix = storage::Key::from(
                            NO_DIFF_KEY_PREFIX.to_string().to_db_key(),
                        );
                        &prefix.join(key)
                    } else {
                        key
                    };
                    state.in_mem_mut().block.tree.update(merk_key, value)?;
                } else if DbColFam::STATE == *cf
                    && CONVERSION_STATE_KEY == key.to_string()
                {
                    let conversion_state =
                        crate::decode(value).map_err(|_| {
                            eyre::eyre!(
                                "The value provided for the key {} is not a \
                                 valid ConversionState",
                                key,
                            )
                        })?;
                    // Make sure to put the conversion state into memory too
                    state.in_mem_mut().conversion_state = conversion_state;
                } else if DbColFam::STATE == *cf
                    && NEXT_EPOCH_MIN_START_HEIGHT_KEY == key.to_string()
                {
                    let next_epoch_min_start_height = crate::decode(value)
                        .map_err(|_| {
                            eyre::eyre!(
                                "The value provided for the key {} is not a \
                                 valid BlockHeight",
                                key,
                            )
                        })?;
                    // Make sure to put the next epoch minimum start height into
                    // memory too
                    state.in_mem_mut().next_epoch_min_start_height =
                        next_epoch_min_start_height;
                } else if DbColFam::STATE == *cf
                    && NEXT_EPOCH_MIN_START_TIME_KEY == key.to_string()
                {
                    let next_epoch_min_start_time = crate::decode(value)
                        .map_err(|_| {
                            eyre::eyre!(
                                "The value provided for the key {} is not a \
                                 valid DateTimeUtc",
                                key,
                            )
                        })?;
                    // Make sure to put the next epoch minimum start time into
                    // memory too
                    state.in_mem_mut().next_epoch_min_start_time =
                        next_epoch_min_start_time;
                } else if DbColFam::STATE == *cf
                    && UPDATE_EPOCH_BLOCKS_DELAY_KEY == key.to_string()
                {
                    let update_epoch_blocks_delay = crate::decode(value)
                        .map_err(|_| {
                            eyre::eyre!(
                                "The value provided for the key {} is not a \
                                 valid Option<u32>",
                                key,
                            )
                        })?;
                    // Make sure to put the update epoch blocks delay into
                    // memory too
                    state.in_mem_mut().update_epoch_blocks_delay =
                        update_epoch_blocks_delay;
                }

                migrator.write(state.db(), key, cf, value, persist_diffs);
                Ok(UpdateStatus::Add(vec![(key.to_string(), deserialized)]))
            }
            Self::Delete(key, cf) => {
                let persist_diffs = (state.diff_key_filter)(key);
                migrator.delete(state.db(), key, cf, persist_diffs);
                if let DbColFam::SUBSPACE = cf {
                    // Update the merkle tree
                    let merk_key = if !persist_diffs {
                        let prefix = storage::Key::from(
                            NO_DIFF_KEY_PREFIX.to_string().to_db_key(),
                        );
                        &prefix.join(key)
                    } else {
                        key
                    };
                    state.in_mem_mut().block.tree.delete(merk_key)?;
                }
                Ok(UpdateStatus::Deleted(vec![key.to_string()]))
            }
            DbUpdateType::RepeatAdd {
                pattern, cf, value, ..
            } => {
                let pattern = Regex::new(pattern).unwrap();
                let mut pairs = vec![];
                let (deserialized, deserializer) = self.validate()?;
                for (key, prev) in
                    migrator.get_pattern(state.db(), pattern.clone())
                {
                    if let Some(des) = deserializer {
                        des(prev).ok_or_else(|| {
                            eyre::eyre!(
                                "The previous value under the key {} did not \
                                 have the same type as that provided: Input \
                                 was {}",
                                key,
                                deserialized,
                            )
                        })?;
                        pairs.push((key.clone(), deserialized.clone()));
                    } else {
                        pairs.push((key.clone(), deserialized.clone()));
                    }
                    let key = storage::Key::from_str(&key).unwrap();
                    let value = value.bytes();
                    let persist_diffs = (state.diff_key_filter)(&key);
                    if let DbColFam::SUBSPACE = cf {
                        // Update the merkle tree
                        let merk_key = if !persist_diffs {
                            let prefix = storage::Key::from(
                                NO_DIFF_KEY_PREFIX.to_string().to_db_key(),
                            );
                            &prefix.join(&key)
                        } else {
                            &key
                        };
                        state
                            .in_mem_mut()
                            .block
                            .tree
                            .update(merk_key, value)?;
                    }
                    migrator.write(state.db(), &key, cf, value, persist_diffs);
                }
                Ok::<_, eyre::Error>(UpdateStatus::Add(pairs))
            }
            DbUpdateType::RepeatDelete(pattern, cf) => {
                let pattern = Regex::new(pattern).unwrap();
                Ok(UpdateStatus::Deleted(
                    migrator
                        .get_pattern(state.db(), pattern.clone())
                        .into_iter()
                        .map(|(raw_key, _)| {
                            let key = storage::Key::from_str(&raw_key).unwrap();
                            let persist_diffs = (state.diff_key_filter)(&key);
                            if let DbColFam::SUBSPACE = cf {
                                // Update the merkle tree
                                let merk_key = if !persist_diffs {
                                    let prefix = storage::Key::from(
                                        NO_DIFF_KEY_PREFIX
                                            .to_string()
                                            .to_db_key(),
                                    );
                                    &prefix.join(&key)
                                } else {
                                    &key
                                };
                                state
                                    .in_mem_mut()
                                    .block
                                    .tree
                                    .delete(merk_key)?;
                            }

                            migrator.delete(
                                state.db(),
                                &key,
                                cf,
                                persist_diffs,
                            );
                            Ok(raw_key)
                        })
                        .collect::<eyre::Result<Vec<_>>>()?,
                ))
            }
        }?;
        migrator.commit(state.db())?;
        Ok(status)
    }
}

/// A set of key-value changes to be applied to
/// the db at a specified height.
#[derive(Debug, Clone)]
pub struct ScheduledMigration {
    /// The height at which to perform the changes
    pub height: BlockHeight,
    /// The actual set of changes
    pub path: PathBuf,
    /// A hash of the expected contents in the file
    pub hash: Hash,
}

impl ScheduledMigration {
    /// Read in a migrations json and a hash to verify the contents
    /// against. Also needs a height for which the changes are scheduled.
    pub fn from_path(
        path: impl AsRef<Path>,
        hash: Hash,
        height: BlockHeight,
    ) -> eyre::Result<Self> {
        let scheduled_migration = Self {
            height,
            path: path.as_ref().to_path_buf(),
            hash,
        };
        scheduled_migration.load_and_validate()?;
        Ok(scheduled_migration)
    }

    pub fn load_and_validate(&self) -> eyre::Result<DbChanges> {
        let update_json = self.load_bytes_and_validate()?;
        serde_json::from_slice(&update_json)
            .map_err(|_| eyre!("Could not parse the updates file as json"))
    }

    fn load_bytes_and_validate(&self) -> eyre::Result<Vec<u8>> {
        let update_json = std::fs::read(&self.path).map_err(|_| {
            eyre!("Could not find or read updates file at the specified path.")
        })?;
        // validate contents against provided hash
        if Hash::sha256(&update_json) != self.hash {
            Err(eyre!(
                "Provided hash did not match the contents at the specified \
                 path."
            ))
        } else {
            Ok(update_json)
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DbChanges {
    pub changes: Vec<DbUpdateType>,
}

impl IntoIterator for DbChanges {
    type IntoIter = std::vec::IntoIter<DbUpdateType>;
    type Item = DbUpdateType;

    fn into_iter(self) -> Self::IntoIter {
        self.changes.into_iter()
    }
}
impl Display for DbUpdateType {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            DbUpdateType::Add { key, cf, value, .. } => {
                let (formatted, _) = match self.validate() {
                    Ok(f) => f,
                    Err(e) => return f.write_str(&e.to_string()),
                };

                f.write_str(&format!(
                    "Write to key in {} CF: <{}> with {}value: {}",
                    cf.to_str(),
                    key,
                    value.is_raw().then_some("raw ").unwrap_or_default(),
                    formatted
                ))
            }
            DbUpdateType::Delete(key, cf) => f.write_str(&format!(
                "Delete key in {} CF: <{}>",
                cf.to_str(),
                key
            )),
            DbUpdateType::RepeatAdd {
                pattern, cf, value, ..
            } => {
                let (formatted, _) = match self.validate() {
                    Ok(f) => f,
                    Err(e) => return f.write_str(&e.to_string()),
                };
                f.write_str(&format!(
                    "Write to pattern in {} CF: <{}> with {}value: {}",
                    cf.to_str(),
                    pattern,
                    value.is_raw().then_some("raw ").unwrap_or_default(),
                    formatted,
                ))
            }
            DbUpdateType::RepeatDelete(pattern, cf) => f.write_str(&format!(
                "Delete pattern in {} CF: <{}>",
                cf.to_str(),
                pattern
            )),
        }
    }
}

pub enum UpdateStatus {
    Deleted(Vec<String>),
    Add(Vec<(String, String)>),
}

impl Display for UpdateStatus {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Deleted(keys) => {
                for key in keys {
                    f.write_str(&format!("Deleting key <{}>\n", key))?;
                }
            }
            Self::Add(pairs) => {
                for (k, v) in pairs {
                    f.write_str(&format!(
                        "Writing key <{}> with value: {}\n",
                        k, v
                    ))?;
                }
            }
        }
        Ok(())
    }
}

/// Check if a scheduled migration should take place at this block height.
/// If so, apply it to the DB.
pub fn commit<D, H>(
    state: &mut FullAccessState<D, H>,
    migration: impl IntoIterator<Item = DbUpdateType>,
) where
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
{
    tracing::info!(
        "A migration is scheduled to take place at this block height. \
         Starting..."
    );

    for change in migration.into_iter() {
        match change.update(state) {
            Ok(status) => {
                tracing::info!("{status}");
            }
            Err(e) => {
                let error = format!(
                    "Attempt to write to key/pattern <{}> failed:\n{}.",
                    change.pattern(),
                    e
                );
                tracing::error!(error);
                panic!(
                    "Failed to execute migration, no changes persisted. \
                     Encountered error: {}",
                    e
                );
            }
        }
    }
}

derive_borshdeserializer!(Vec::<u8>);
derive_borshdeserializer!(Vec::<String>);
derive_borshdeserializer!(u64);
derive_borshdeserializer!(u128);
derive_borshdeserializer!(namada_core::hash::Hash);
derive_borshdeserializer!(Option::<u32>);
derive_borshdeserializer!(masp_primitives::convert::AllowedConversion);

#[derive(BorshSerialize, BorshDeserialize)]
#[repr(transparent)]
pub struct SerializeWrapper<T: BorshSerialize + BorshDeserialize>(T);

impl TypeHash
    for SerializeWrapper<
        std::collections::BTreeMap<String, namada_core::address::Address>,
    >
{
    const HASH: [u8; 32] =
        typehash!(SerializeWrapper<BTreeMap<String, Address>>);
}

#[distributed_slice(REGISTER_DESERIALIZERS)]
static BTREEMAP_STRING_ADDRESS: fn() = || {
    use std::collections::BTreeMap;

    use namada_core::address::Address;
    register_deserializer(
        SerializeWrapper::<BTreeMap<String, Address>>::HASH,
        |bytes| {
            BTreeMap::<String, Address>::try_from_slice(&bytes)
                .map(|val| format!("{:?}", val))
                .ok()
        },
    );
};

#[cfg(test)]
mod test_migrations {
    use namada_core::token::Amount;

    use super::*;

    /// Check that if the hash of the file is wrong, the scheduled
    /// migration will not load.
    #[test]
    fn test_scheduled_migration_validate() {
        let file = tempfile::Builder::new().tempfile().expect("Test failed");
        let updates = [DbUpdateType::Add {
            key: storage::Key::parse("bing/fucking/bong").expect("Test failed"),
            cf: DbColFam::SUBSPACE,
            value: Amount::native_whole(1337).into(),
            force: false,
        }];
        let changes = DbChanges {
            changes: updates.into_iter().collect(),
        };
        let json = serde_json::to_string(&changes).expect("Test failed");
        let hash = Hash::sha256("derpy derp".as_bytes());
        std::fs::write(file.path(), json).expect("Test failed");
        let migration = ScheduledMigration::from_path(
            file.path(),
            hash,
            Default::default(),
        );
        assert!(migration.is_err());
    }
}
