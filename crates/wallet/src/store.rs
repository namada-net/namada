//! Wallet Store information

#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::collections::BTreeMap;
use std::fmt::Display;
use std::str::FromStr;

use bimap::BiBTreeMap;
use itertools::Itertools;
use masp_primitives::zip32;
use namada_core::address::{Address, ImplicitAddress};
use namada_core::chain::BlockHeight;
use namada_core::collections::HashSet;
use namada_core::key::*;
use namada_core::masp::{
    DiversifierIndex, ExtendedSpendingKey, ExtendedViewingKey, PaymentAddress,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::alias::{self, Alias};
use super::derivation_path::DerivationPath;
use super::pre_genesis;
use crate::{StoreSpendingKey, StoredKeypair, WalletIo};

/// Actions that can be taken when there is an alias conflict
pub enum ConfirmationResponse {
    /// Replace the existing alias
    Replace,
    /// Reselect the alias that is ascribed to a given entity
    Reselect(Alias),
    /// Skip assigning the given entity an alias
    Skip,
}

/// Special keys for a validator
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ValidatorKeys {
    /// Special keypair for signing protocol txs
    pub protocol_keypair: common::SecretKey,
    /// Special hot keypair for signing Ethereum bridge txs
    pub eth_bridge_keypair: common::SecretKey,
}

impl ValidatorKeys {
    /// Get the protocol keypair
    pub fn get_protocol_keypair(&self) -> &common::SecretKey {
        &self.protocol_keypair
    }
}

/// Special data associated with a validator
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ValidatorData {
    /// The address associated to a validator
    pub address: Address,
    /// special keys for a validator
    pub keys: ValidatorKeys,
}

/// A Storage area for keys and addresses
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Store {
    /// Known birthdays
    birthdays: BTreeMap<Alias, BlockHeight>,
    /// Known viewing keys
    view_keys: BTreeMap<Alias, ExtendedViewingKey>,
    /// Known spending keys
    spend_keys: BTreeMap<Alias, StoredKeypair<StoreSpendingKey>>,
    /// Payment address book
    payment_addrs: BiBTreeMap<Alias, PaymentAddress>,
    /// Diverisifier index of the next payment address to be generated for a
    /// given key.
    diversifier_indices: BTreeMap<Alias, DiversifierIndex>,
    /// Cryptographic keypairs
    secret_keys: BTreeMap<Alias, StoredKeypair<common::SecretKey>>,
    /// Known public keys
    public_keys: BTreeMap<Alias, common::PublicKey>,
    /// Known derivation paths
    derivation_paths: BTreeMap<Alias, DerivationPath>,
    /// Namada address book
    addresses: BiBTreeMap<Alias, Address>,
    /// Known mappings of public key hashes to their aliases in the `keys`
    /// field. Used for look-up by a public key.
    pkhs: BTreeMap<PublicKeyHash, Alias>,
    /// Special keys if the wallet belongs to a validator
    pub(crate) validator_data: Option<ValidatorData>,
    /// Namada address vp type
    address_vp_types: BTreeMap<AddressVpType, HashSet<Address>>,
}

/// Grouping of addresses by validity predicate.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, PartialOrd, Ord)]
pub enum AddressVpType {
    /// The Token
    Token,
}

impl Store {
    /// Find the stored key by an alias, a public key hash or a public key.
    pub fn find_secret_key(
        &self,
        alias_pkh_or_pk: impl AsRef<str>,
    ) -> Option<&StoredKeypair<common::SecretKey>> {
        let alias_pkh_or_pk = alias_pkh_or_pk.as_ref();
        // Try to find by alias
        self.secret_keys
            .get(&alias_pkh_or_pk.into())
            // Try to find by PKH
            .or_else(|| {
                let pkh = PublicKeyHash::from_str(alias_pkh_or_pk).ok()?;
                self.find_key_by_pkh(&pkh)
            })
            // Try to find by PK
            .or_else(|| {
                let pk = common::PublicKey::from_str(alias_pkh_or_pk).ok()?;
                self.find_key_by_pk(&pk)
            })
    }

    /// Find the stored key by an alias, a public key hash or a public key.
    pub fn find_public_key(
        &self,
        alias_or_pkh: impl AsRef<str>,
    ) -> Option<&common::PublicKey> {
        let alias_or_pkh = alias_or_pkh.as_ref();
        // Try to find by alias
        self.public_keys
            .get(&alias_or_pkh.into())
            // Try to find by PKH
            .or_else(|| {
                let pkh = PublicKeyHash::from_str(alias_or_pkh).ok()?;
                self.find_public_key_by_pkh(&pkh)
            })
    }

    /// Find the spending key with the given alias and return it
    pub fn find_spending_key(
        &self,
        alias: impl AsRef<str>,
    ) -> Option<&StoredKeypair<StoreSpendingKey>> {
        self.spend_keys.get(&alias.into())
    }

    /// Find the viewing key with the given alias and return it
    pub fn find_viewing_key(
        &self,
        alias: impl AsRef<str>,
    ) -> Option<&ExtendedViewingKey> {
        self.view_keys.get(&alias.into())
    }

    /// Find the birthday of the given alias
    pub fn find_birthday(
        &self,
        alias: impl AsRef<str>,
    ) -> Option<&BlockHeight> {
        self.birthdays.get(&alias.into())
    }

    /// Find the diversifier of the given alias
    pub fn find_diversifier_index(
        &self,
        alias: impl AsRef<str>,
    ) -> Option<&DiversifierIndex> {
        self.diversifier_indices.get(&alias.into())
    }

    /// Find the payment address with the given alias and return it
    pub fn find_payment_addr(
        &self,
        alias: impl AsRef<str>,
    ) -> Option<&PaymentAddress> {
        self.payment_addrs.get_by_left(&alias.into())
    }

    /// Find an alias by the address if it's in the wallet.
    pub fn find_alias_by_payment_addr(
        &self,
        payment_address: &PaymentAddress,
    ) -> Option<&Alias> {
        self.payment_addrs.get_by_right(payment_address)
    }

    /// Find the stored key by a public key.
    pub fn find_key_by_pk(
        &self,
        pk: &common::PublicKey,
    ) -> Option<&StoredKeypair<common::SecretKey>> {
        let pkh = PublicKeyHash::from(pk);
        self.find_key_by_pkh(&pkh)
    }

    /// Find the stored key by a public key hash.
    pub fn find_key_by_pkh(
        &self,
        pkh: &PublicKeyHash,
    ) -> Option<&StoredKeypair<common::SecretKey>> {
        let alias = self.pkhs.get(pkh)?;
        self.secret_keys.get(alias)
    }

    /// Find the stored alias for a public key hash.
    pub fn find_alias_by_pkh(&self, pkh: &PublicKeyHash) -> Option<Alias> {
        self.pkhs.get(pkh).cloned()
    }

    /// Find a derivation path by public key hash
    pub fn find_path_by_pkh(
        &self,
        pkh: &PublicKeyHash,
    ) -> Option<DerivationPath> {
        self.derivation_paths.get(self.pkhs.get(pkh)?).cloned()
    }

    /// Find a derivation path by viewing key
    pub fn find_path_by_viewing_key(
        &self,
        viewing_key: &ExtendedViewingKey,
    ) -> Option<DerivationPath> {
        for (alias, vk) in &self.view_keys {
            if *viewing_key == *vk {
                return self.derivation_paths.get(alias).cloned();
            }
        }
        None
    }

    /// Find the public key by a public key hash.
    pub fn find_public_key_by_pkh(
        &self,
        pkh: &PublicKeyHash,
    ) -> Option<&common::PublicKey> {
        self.public_keys.get(self.pkhs.get(pkh)?)
    }

    /// Find the stored address by an alias.
    pub fn find_address(&self, alias: impl AsRef<str>) -> Option<&Address> {
        self.addresses.get_by_left(&alias.into())
    }

    /// Find an alias by the address if it's in the wallet.
    pub fn find_alias(&self, address: &Address) -> Option<&Alias> {
        self.addresses.get_by_right(address)
    }

    /// Get all known keys by their alias, paired with PKH, if known.
    pub fn get_secret_keys(
        &self,
    ) -> BTreeMap<
        Alias,
        (&StoredKeypair<common::SecretKey>, Option<&PublicKeyHash>),
    > {
        let mut keys: BTreeMap<
            Alias,
            (&StoredKeypair<common::SecretKey>, Option<&PublicKeyHash>),
        > = self
            .pkhs
            .iter()
            .filter_map(|(pkh, alias)| {
                let key = &self.secret_keys.get(alias)?;
                Some((alias.clone(), (*key, Some(pkh))))
            })
            .collect();
        self.secret_keys.iter().for_each(|(alias, key)| {
            if !keys.contains_key(alias) {
                keys.insert(alias.clone(), (key, None));
            }
        });
        keys
    }

    /// Get all known public keys by their alias.
    pub fn get_public_keys(&self) -> &BTreeMap<Alias, common::PublicKey> {
        &self.public_keys
    }

    /// Get all known addresses by their alias.
    pub fn get_addresses(&self) -> &BiBTreeMap<Alias, Address> {
        &self.addresses
    }

    /// Get all known payment addresses by their alias.
    pub fn get_payment_addrs(&self) -> &BiBTreeMap<Alias, PaymentAddress> {
        &self.payment_addrs
    }

    /// Get all known viewing keys by their alias.
    pub fn get_viewing_keys(&self) -> &BTreeMap<Alias, ExtendedViewingKey> {
        &self.view_keys
    }

    /// Get all known spending keys by their alias.
    pub fn get_spending_keys(
        &self,
    ) -> &BTreeMap<Alias, StoredKeypair<StoreSpendingKey>> {
        &self.spend_keys
    }

    /// Add validator data to the store
    pub fn add_validator_data(
        &mut self,
        address: Address,
        keys: ValidatorKeys,
    ) {
        self.validator_data = Some(ValidatorData { address, keys });
    }

    /// Returns a reference to the validator data, if it exists.
    pub fn get_validator_data(&self) -> Option<&ValidatorData> {
        self.validator_data.as_ref()
    }

    /// Returns a mut reference to the validator data, if it exists.
    pub fn get_validator_data_mut(&mut self) -> Option<&mut ValidatorData> {
        self.validator_data.as_mut()
    }

    /// Take the validator data, if it exists.
    pub fn take_validator_data(&mut self) -> Option<ValidatorData> {
        self.validator_data.take()
    }

    /// Returns the validator data, if it exists.
    pub fn into_validator_data(self) -> Option<ValidatorData> {
        self.validator_data
    }

    /// Insert a new secret key with the given alias. If the alias is already
    /// used, will prompt for overwrite/reselection confirmation. If declined,
    /// then keypair is not inserted and nothing is returned, otherwise selected
    /// alias is returned.
    pub fn insert_keypair<U: WalletIo>(
        &mut self,
        mut alias: Alias,
        keypair: common::SecretKey,
        password: Option<Zeroizing<String>>,
        address: Option<Address>,
        path: Option<DerivationPath>,
        force: bool,
    ) -> Option<Alias> {
        // abort if the key already exists
        let pubkey = keypair.ref_to();
        let pkh = PublicKeyHash::from(&pubkey);
        let address = address
            .unwrap_or_else(|| Address::Implicit(ImplicitAddress(pkh.clone())));
        if !force {
            if let Some(alias) = self.pkhs.get(&pkh) {
                println!("The key already exists with alias {}", alias);
                return None;
            } else if let Some(alias) = self.addresses.get_by_right(&address) {
                println!(
                    "Address {} already exists in the wallet with alias {}",
                    address.encode(),
                    alias,
                );
                return None;
            }
        }

        // abort if the alias is reserved
        if Alias::is_reserved(&alias).is_some() {
            println!("The alias {} is reserved.", alias);
            return None;
        }

        if alias.is_empty() {
            alias = pkh.to_string().into();
            println!("Empty alias given, defaulting to {}.", alias);
        }
        if self.contains_alias(&alias) && !force {
            match U::show_overwrite_confirmation(&alias, "a key") {
                ConfirmationResponse::Replace => {}
                ConfirmationResponse::Reselect(new_alias) => {
                    return self.insert_keypair::<U>(
                        new_alias,
                        keypair,
                        password,
                        Some(address),
                        path,
                        false,
                    );
                }
                ConfirmationResponse::Skip => {
                    return None;
                }
            }
        }
        self.remove_alias(&alias);
        self.secret_keys
            .insert(alias.clone(), StoredKeypair::new(keypair, password).0);
        self.public_keys.insert(alias.clone(), pubkey);
        self.pkhs.insert(pkh, alias.clone());
        self.addresses.insert(alias.clone(), address);
        path.map(|x| self.derivation_paths.insert(alias.clone(), x));
        Some(alias)
    }

    /// Insert spending keys similarly to how it's done for keypairs
    pub fn insert_spending_key<U: WalletIo>(
        &mut self,
        alias: Alias,
        spendkey: ExtendedSpendingKey,
        birthday: Option<BlockHeight>,
        password: Option<Zeroizing<String>>,
        path: Option<DerivationPath>,
        force: bool,
    ) -> Option<Alias> {
        // abort if the alias is reserved
        if Alias::is_reserved(&alias).is_some() {
            println!("The alias {} is reserved.", alias);
            return None;
        }
        // abort if the alias is empty
        if alias.is_empty() {
            eprintln!("Empty alias given.");
            return None;
        }

        if self.contains_alias(&alias) && !force {
            match U::show_overwrite_confirmation(&alias, "a spending key") {
                ConfirmationResponse::Replace => {}
                ConfirmationResponse::Reselect(new_alias) => {
                    return self.insert_spending_key::<U>(
                        new_alias, spendkey, birthday, password, path, false,
                    );
                }
                ConfirmationResponse::Skip => return None,
            }
        }
        self.remove_alias(&alias);

        let (spendkey_to_store, _raw_spendkey) =
            StoredKeypair::new(spendkey.into(), password);
        self.spend_keys.insert(alias.clone(), spendkey_to_store);
        // Simultaneously add the derived viewing key to ease balance viewing
        birthday.map(|x| self.birthdays.insert(alias.clone(), x));
        self.view_keys.insert(
            alias.clone(),
            zip32::ExtendedFullViewingKey::from(&spendkey.into()).into(),
        );
        path.map(|p| self.derivation_paths.insert(alias.clone(), p));
        Some(alias)
    }

    /// Insert viewing keys similarly to how it's done for keypairs
    pub fn insert_viewing_key<U: WalletIo>(
        &mut self,
        alias: Alias,
        viewkey: ExtendedViewingKey,
        birthday: Option<BlockHeight>,
        path: Option<DerivationPath>,
        force: bool,
    ) -> Option<Alias> {
        // abort if the alias is reserved
        if Alias::is_reserved(&alias).is_some() {
            println!("The alias {} is reserved.", alias);
            return None;
        }

        if alias.is_empty() {
            eprintln!("Empty alias given.");
            return None;
        }
        if self.contains_alias(&alias) && !force {
            match U::show_overwrite_confirmation(&alias, "a viewing key") {
                ConfirmationResponse::Replace => {}
                ConfirmationResponse::Reselect(new_alias) => {
                    return self.insert_viewing_key::<U>(
                        new_alias, viewkey, birthday, path, false,
                    );
                }
                ConfirmationResponse::Skip => return None,
            }
        }
        self.remove_alias(&alias);
        birthday.map(|x| self.birthdays.insert(alias.clone(), x));
        self.view_keys.insert(alias.clone(), viewkey);
        path.map(|p| self.derivation_paths.insert(alias.clone(), p));
        Some(alias)
    }

    /// Insert public keys
    pub fn insert_public_key<U: WalletIo>(
        &mut self,
        mut alias: Alias,
        pubkey: common::PublicKey,
        address: Option<Address>,
        path: Option<DerivationPath>,
        force: bool,
    ) -> Option<Alias> {
        let pkh = PublicKeyHash::from(&pubkey);
        let address = address
            .unwrap_or_else(|| Address::Implicit(ImplicitAddress(pkh.clone())));
        if !force {
            if let Some(alias) = self.pkhs.get(&pkh) {
                println!("The key already exists with alias {}", alias);
                return None;
            } else if let Some(alias) = self.addresses.get_by_right(&address) {
                println!(
                    "Address {} already exists in the wallet with alias {}",
                    address.encode(),
                    alias,
                );
                return None;
            }
        }
        if alias.is_empty() {
            alias = pkh.to_string().into();
            println!("Empty alias given, defaulting to {}.", alias);
        }
        if self.contains_alias(&alias) && !force {
            match U::show_overwrite_confirmation(&alias, "a public key") {
                ConfirmationResponse::Replace => {}
                ConfirmationResponse::Reselect(new_alias) => {
                    return self.insert_public_key::<U>(
                        new_alias,
                        pubkey,
                        Some(address),
                        path,
                        false,
                    );
                }
                ConfirmationResponse::Skip => return None,
            }
        }
        self.remove_alias(&alias);
        self.public_keys.insert(alias.clone(), pubkey);
        path.map(|x| self.derivation_paths.insert(alias.clone(), x));
        self.pkhs.insert(pkh, alias.clone());
        self.addresses.insert(alias.clone(), address);
        Some(alias)
    }

    /// Insert payment addresses similarly to how it's done for keypairs
    pub fn insert_payment_addr<U: WalletIo>(
        &mut self,
        alias: Alias,
        payment_addr: PaymentAddress,
        force: bool,
    ) -> Option<Alias> {
        // abort if the alias is reserved
        if Alias::is_reserved(&alias).is_some() {
            println!("The alias {} is reserved.", alias);
            return None;
        }

        if alias.is_empty() {
            eprintln!("Empty alias given.");
            return None;
        }
        if self.contains_alias(&alias) && !force {
            match U::show_overwrite_confirmation(&alias, "a payment address") {
                ConfirmationResponse::Replace => {}
                ConfirmationResponse::Reselect(new_alias) => {
                    return self.insert_payment_addr::<U>(
                        new_alias,
                        payment_addr,
                        false,
                    );
                }
                ConfirmationResponse::Skip => return None,
            }
        }
        self.remove_alias(&alias);
        self.payment_addrs.insert(alias.clone(), payment_addr);
        Some(alias)
    }

    /// Insert the given diversifier index under the given alias. Useful for
    /// sequential payment address generation.
    pub fn insert_diversifier_index(
        &mut self,
        alias: Alias,
        div_index: DiversifierIndex,
    ) -> Option<Alias> {
        // abort if the alias is reserved
        if Alias::is_reserved(&alias).is_some() {
            println!("The alias {} is reserved.", alias);
            return None;
        }

        if alias.is_empty() {
            eprintln!("Empty alias given.");
            return None;
        }
        self.diversifier_indices.insert(alias.clone(), div_index);
        Some(alias)
    }

    /// Insert a new address with the given alias. If the alias is already used,
    /// will prompt for overwrite/reselection confirmation, which when declined,
    /// the address won't be added. Return the selected alias if the address has
    /// been added.
    pub fn insert_address<U: WalletIo>(
        &mut self,
        mut alias: Alias,
        address: Address,
        force: bool,
    ) -> Option<Alias> {
        // abort if the address already exists in the wallet
        if self.addresses.contains_right(&address) && !force {
            println!(
                "Address {} already exists in the wallet with alias {}",
                address.encode(),
                self.addresses.get_by_right(&address).unwrap()
            );
            return None;
        }

        if alias.is_empty() {
            alias = address.encode().into();
            println!("Empty alias given, defaulting to {}.", alias);
        }
        if self.contains_alias(&alias) && !force {
            match U::show_overwrite_confirmation(&alias, "an address") {
                ConfirmationResponse::Replace => {}
                ConfirmationResponse::Reselect(new_alias) => {
                    return self.insert_address::<U>(new_alias, address, false);
                }
                ConfirmationResponse::Skip => {
                    return None;
                }
            }
        }
        self.remove_alias(&alias);
        self.addresses.insert(alias.clone(), address);
        Some(alias)
    }

    /// Check if any map of the wallet contains the given alias
    pub fn contains_alias(&self, alias: &Alias) -> bool {
        self.payment_addrs.contains_left(alias)
            || self.view_keys.contains_key(alias)
            || self.spend_keys.contains_key(alias)
            || self.secret_keys.contains_key(alias)
            || self.addresses.contains_left(alias)
            || self.pkhs.values().contains(alias)
            || self.public_keys.contains_key(alias)
            || self.derivation_paths.contains_key(alias)
            || self.birthdays.contains_key(alias)
    }

    /// Completely remove the given alias from all maps in the wallet
    pub fn remove_alias(&mut self, alias: &Alias) {
        self.payment_addrs.remove_by_left(alias);
        self.view_keys.remove(alias);
        self.spend_keys.remove(alias);
        self.secret_keys.remove(alias);
        self.addresses.remove_by_left(alias);
        self.pkhs.retain(|_key, val| val != alias);
        self.public_keys.remove(alias);
        self.derivation_paths.remove(alias);
        self.birthdays.remove(alias);
        self.diversifier_indices.remove(alias);
    }

    /// Extend this store from another store (typically pre-genesis).
    /// Note that this method ignores `validator_data` if any.
    pub fn extend(&mut self, store: Store) {
        let Self {
            birthdays,
            view_keys,
            spend_keys,
            payment_addrs,
            diversifier_indices,
            secret_keys,
            public_keys,
            derivation_paths,
            addresses,
            pkhs,
            validator_data: _,
            address_vp_types,
        } = self;
        birthdays.extend(store.birthdays);
        view_keys.extend(store.view_keys);
        spend_keys.extend(store.spend_keys);
        payment_addrs.extend(store.payment_addrs);
        diversifier_indices.extend(store.diversifier_indices);
        secret_keys.extend(store.secret_keys);
        public_keys.extend(store.public_keys);
        derivation_paths.extend(store.derivation_paths);
        addresses.extend(store.addresses);
        pkhs.extend(store.pkhs);
        address_vp_types.extend(store.address_vp_types);
    }

    /// Extend this store from pre-genesis validator wallet.
    pub fn extend_from_pre_genesis_validator(
        &mut self,
        validator_address: Address,
        validator_alias: Alias,
        other: pre_genesis::ValidatorWallet,
    ) {
        let consensus_key_alias =
            alias::validator_consensus_key(&validator_alias);
        let tendermint_node_key_alias =
            alias::validator_tendermint_node_key(&validator_alias);
        let address_alias = alias::validator_address(&validator_alias);

        let keys = [
            (consensus_key_alias.clone(), other.store.consensus_key),
            (
                tendermint_node_key_alias.clone(),
                other.store.tendermint_node_key,
            ),
        ];
        self.secret_keys.extend(keys);

        let consensus_pk = other.consensus_key.ref_to();
        let tendermint_node_pk = other.tendermint_node_key.ref_to();
        let public_keys = [
            (consensus_key_alias.clone(), consensus_pk.clone()),
            (
                tendermint_node_key_alias.clone(),
                tendermint_node_pk.clone(),
            ),
        ];
        self.public_keys.extend(public_keys.clone());
        self.addresses
            .extend(public_keys.map(|(k, v)| (k, (&v).into())));

        let pkhs = [
            ((&consensus_pk).into(), consensus_key_alias),
            ((&tendermint_node_pk).into(), tendermint_node_key_alias),
        ];
        self.pkhs.extend(pkhs);

        self.addresses
            .insert(address_alias.clone(), validator_address.clone());

        println!(
            "\nAdded the validator address {} to the wallet with alias \"{}\".",
            &validator_address, address_alias
        );

        self.validator_data = Some(ValidatorData {
            address: validator_address,
            keys: other.store.validator_keys,
        });
    }

    /// get an address with the vp type
    pub fn get_addresses_with_vp_type(
        &self,
        vp_type: AddressVpType,
    ) -> HashSet<Address> {
        // defaults to an empty set
        self.address_vp_types
            .get(&vp_type)
            .cloned()
            .unwrap_or_default()
    }

    /// Adds a VP type to the address
    pub fn add_vp_type_to_address(
        &mut self,
        vp_type: AddressVpType,
        address: Address,
    ) {
        // defaults to an empty set
        self.address_vp_types
            .entry(vp_type)
            .or_default()
            .insert(address);
    }

    /// Decode a Store from the given string
    pub fn decode(data: &str) -> Result<Self, toml::de::Error> {
        // First try to decode Store from current version (with separate
        // birthdays)
        toml::from_str(data)
            .or_else(
                // Otherwise try to decode Store from older version (without
                // diversifier indices)
                |_| toml::from_str::<StoreV1>(data).map(Into::into),
            )
            .or_else(
                // Otherwise try to decode Store from older version (with
                // integrated birthdays)
                |_| toml::from_str::<StoreV0>(data).map(Into::into),
            )
    }

    /// Encode a store into a string
    pub fn encode(&self) -> String {
        toml::to_string(self).expect("Serializing of store shouldn't fail")
    }
}

/// Generate a new secret key from the seed.
pub fn derive_hd_secret_key(
    scheme: SchemeType,
    seed: &[u8],
    derivation_path: DerivationPath,
) -> common::SecretKey {
    match scheme {
        SchemeType::Ed25519 => {
            let indexes = derivation_path
                .path()
                .iter()
                .map(|idx| idx.to_bits())
                .collect_vec();
            // SLIP10 Ed25519 key derivation function promotes all indexes to
            // hardened indexes.
            let sk = slip10_ed25519::derive_ed25519_private_key(seed, &indexes);
            ed25519::SigScheme::from_bytes(sk).try_to_sk().unwrap()
        }
        SchemeType::Secp256k1 => {
            let xpriv = bip32::XPrv::derive_from_path(
                seed,
                &derivation_path.try_into().expect("bip32 derivation path"),
            )
            .expect("Secret key derivation should not fail.");
            secp256k1::SigScheme::from_bytes(xpriv.to_bytes())
                .try_to_sk()
                .unwrap()
        }
        SchemeType::Common => {
            panic!(
                "Cannot generate common signing scheme. Must convert from \
                 alternative scheme."
            )
        }
    }
}

/// Generate a new spending key from the seed.
pub fn derive_hd_spending_key(
    seed: &[u8],
    derivation_path: DerivationPath,
) -> ExtendedSpendingKey {
    let master_spend_key = zip32::sapling::ExtendedSpendingKey::master(seed);
    let zip32_path: Vec<zip32::ChildIndex> = derivation_path.into();
    zip32::sapling::ExtendedSpendingKey::from_path(
        &master_spend_key,
        &zip32_path,
    )
    .into()
}

impl Display for AddressVpType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AddressVpType::Token => write!(f, "token"),
        }
    }
}

impl FromStr for AddressVpType {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "token" => Ok(Self::Token),
            _ => Err("unexpected address VP type"),
        }
    }
}

impl Serialize for AddressVpType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.to_string().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for AddressVpType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        let raw: String = Deserialize::deserialize(deserializer)?;
        Self::from_str(&raw).map_err(D::Error::custom)
    }
}

// A Storage area for keys and addresses. This is a deprecated format but it
// is required for compatability purposes.
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct StoreV0 {
    /// Known viewing keys
    view_keys: BTreeMap<Alias, crate::DatedViewingKey>,
    /// Known spending keys
    spend_keys: BTreeMap<Alias, StoredKeypair<crate::DatedSpendingKey>>,
    /// Payment address book
    payment_addrs: BiBTreeMap<Alias, PaymentAddress>,
    /// Cryptographic keypairs
    secret_keys: BTreeMap<Alias, StoredKeypair<common::SecretKey>>,
    /// Known public keys
    public_keys: BTreeMap<Alias, common::PublicKey>,
    /// Known derivation paths
    derivation_paths: BTreeMap<Alias, DerivationPath>,
    /// Namada address book
    addresses: BiBTreeMap<Alias, Address>,
    /// Known mappings of public key hashes to their aliases in the `keys`
    /// field. Used for look-up by a public key.
    pkhs: BTreeMap<PublicKeyHash, Alias>,
    /// Special keys if the wallet belongs to a validator
    pub(crate) validator_data: Option<ValidatorData>,
    /// Namada address vp type
    address_vp_types: BTreeMap<AddressVpType, HashSet<Address>>,
}

impl From<StoreV0> for Store {
    fn from(store: StoreV0) -> Self {
        let mut to = Store {
            payment_addrs: store.payment_addrs,
            secret_keys: store.secret_keys,
            public_keys: store.public_keys,
            derivation_paths: store.derivation_paths,
            addresses: store.addresses,
            pkhs: store.pkhs,
            validator_data: store.validator_data,
            address_vp_types: store.address_vp_types,
            ..Store::default()
        };
        for (alias, key) in store.view_keys {
            // Extract the birthday into the birthdays map
            to.birthdays.insert(alias.clone(), key.birthday);
            // Extrat the key into the viewing keys map
            to.view_keys.insert(alias, key.key);
        }
        for (alias, key) in store.spend_keys {
            match key {
                StoredKeypair::Raw(key) => {
                    // Extract the birthday into the birthdays map
                    to.birthdays.insert(alias.clone(), key.birthday);
                    // Extract the key into the spending keys map
                    to.spend_keys
                        .insert(alias, StoredKeypair::Raw(key.key.into()));
                }
                StoredKeypair::Encrypted(key) => {
                    // This map is fine because DatedSpendingKey has the same
                    // Borsh serialization as StoreSpendingKey
                    to.spend_keys.insert(
                        alias,
                        StoredKeypair::Encrypted(key.map::<StoreSpendingKey>()),
                    );
                    // Here we assume the birthday for the current alias is
                    // already given in a viewing key with the same alias.
                }
            }
        }
        to
    }
}

// A Storage area for keys and addresses. This is a deprecated format but it
// is required for compatability purposes.
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct StoreV1 {
    /// Known birthdays
    birthdays: BTreeMap<Alias, BlockHeight>,
    /// Known viewing keys
    view_keys: BTreeMap<Alias, ExtendedViewingKey>,
    /// Known spending keys
    spend_keys: BTreeMap<Alias, StoredKeypair<StoreSpendingKey>>,
    /// Payment address book
    payment_addrs: BiBTreeMap<Alias, PaymentAddress>,
    /// Cryptographic keypairs
    secret_keys: BTreeMap<Alias, StoredKeypair<common::SecretKey>>,
    /// Known public keys
    public_keys: BTreeMap<Alias, common::PublicKey>,
    /// Known derivation paths
    derivation_paths: BTreeMap<Alias, DerivationPath>,
    /// Namada address book
    addresses: BiBTreeMap<Alias, Address>,
    /// Known mappings of public key hashes to their aliases in the `keys`
    /// field. Used for look-up by a public key.
    pkhs: BTreeMap<PublicKeyHash, Alias>,
    /// Special keys if the wallet belongs to a validator
    pub(crate) validator_data: Option<ValidatorData>,
    /// Namada address vp type
    address_vp_types: BTreeMap<AddressVpType, HashSet<Address>>,
}

impl From<StoreV1> for Store {
    fn from(store: StoreV1) -> Self {
        Store {
            payment_addrs: store.payment_addrs,
            secret_keys: store.secret_keys,
            public_keys: store.public_keys,
            derivation_paths: store.derivation_paths,
            addresses: store.addresses,
            pkhs: store.pkhs,
            validator_data: store.validator_data,
            address_vp_types: store.address_vp_types,
            view_keys: store.view_keys,
            spend_keys: store.spend_keys,
            birthdays: store.birthdays,
            ..Store::default()
        }
    }
}

#[cfg(test)]
mod test_wallet {
    use base58::FromBase58;
    use bip39::{Language, Mnemonic, Seed};
    use data_encoding::HEXLOWER;

    use super::*;

    #[test]
    fn gen_sk_from_mnemonic_code_secp256k1() {
        const SCHEME: SchemeType = SchemeType::Secp256k1;
        const MNEMONIC_CODE: &str = "cruise ball fame lucky fabric govern \
                                     length fruit permit tonight fame pear \
                                     horse park key chimney furnace lobster \
                                     foot example shoot dry fuel lawn";
        const SEED_EXPECTED: &str = "8601e9f639f995f856c8ecfa3cd298d292253d071d6fa75d50dd31f6ba9df743ec279354a73fe78e6011738027fb994e5d904c476c4679c7c35e82586e14297f";
        const PASSPHRASE: &str = "test";
        const DERIVATION_PATH: &str = "m/44'/60'/0'/0/0";
        const SK_EXPECTED: &str =
            "9e426cc5f63cdbd5f362adb918a07c2b16c593b2bc1b244f33b9e2c3ac6b265a";

        let mnemonic = Mnemonic::from_phrase(MNEMONIC_CODE, Language::English)
            .expect("Mnemonic construction cannot fail.");
        let seed = Seed::new(&mnemonic, PASSPHRASE);
        assert_eq!(format!("{:x}", seed), SEED_EXPECTED);

        let derivation_path =
            DerivationPath::from_path_string_for_transparent_scheme(
                SCHEME,
                DERIVATION_PATH,
            )
            .expect("Derivation path construction cannot fail");

        let sk = derive_hd_secret_key(SCHEME, seed.as_bytes(), derivation_path);

        assert_eq!(&sk.to_string()[2..], SK_EXPECTED);
    }

    #[test]
    fn gen_sk_from_mnemonic_code_ed25519() {
        const SCHEME: SchemeType = SchemeType::Ed25519;
        const MNEMONIC_CODE: &str = "cruise ball fame lucky fabric govern \
                                     length fruit permit tonight fame pear \
                                     horse park key chimney furnace lobster \
                                     foot example shoot dry fuel lawn";
        const SEED_EXPECTED: &str = "8601e9f639f995f856c8ecfa3cd298d292253d071d6fa75d50dd31f6ba9df743ec279354a73fe78e6011738027fb994e5d904c476c4679c7c35e82586e14297f";
        const PASSPHRASE: &str = "test";
        const DERIVATION_PATH: &str = "m/44'/877'/0'/0/0";
        const DERIVATION_PATH_HARDENED: &str = "m/44'/877'/0'/0'/0'";

        let mnemonic = Mnemonic::from_phrase(MNEMONIC_CODE, Language::English)
            .expect("Mnemonic construction cannot fail.");
        let seed = Seed::new(&mnemonic, PASSPHRASE);
        assert_eq!(format!("{:x}", seed), SEED_EXPECTED);

        let derivation_path =
            DerivationPath::from_path_string_for_transparent_scheme(
                SCHEME,
                DERIVATION_PATH,
            )
            .expect("Derivation path construction cannot fail");

        let derivation_path_hardened =
            DerivationPath::from_path_string_for_transparent_scheme(
                SCHEME,
                DERIVATION_PATH_HARDENED,
            )
            .expect("Derivation path construction cannot fail");

        let sk = derive_hd_secret_key(SCHEME, seed.as_bytes(), derivation_path);

        let sk_hard = derive_hd_secret_key(
            SCHEME,
            seed.as_bytes(),
            derivation_path_hardened,
        );

        // check that indexes are promoted to hardened
        assert_eq!(&sk.to_string(), &sk_hard.to_string());
    }

    fn do_test_gen_sk_from_seed_and_derivation_path(
        scheme: SchemeType,
        seed: &str,
        derivation_path: &str,
        priv_key: &str,
    ) {
        let sk = derive_hd_secret_key(
            scheme,
            HEXLOWER
                .decode(seed.as_bytes())
                .expect("Seed parsing cannot fail.")
                .as_slice(),
            DerivationPath::from_path_string_for_transparent_scheme(
                scheme,
                derivation_path,
            )
            .expect("Derivation path construction cannot fail"),
        );
        let sk_expected = if priv_key.starts_with("xprv") {
            // this is an extended private key encoded in base58
            let xprv =
                priv_key.from_base58().expect("XPRV parsing cannot fail.");
            HEXLOWER.encode(&xprv[46..78])
        } else {
            priv_key.to_string()
        };
        assert_eq!(&sk.to_string()[2..], sk_expected);
    }

    #[test]
    fn gen_sk_from_seed_secp256k1() {
        const SCHEME: SchemeType = SchemeType::Secp256k1;
        // https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
        {
            // Test vector 1
            const SEED: &str = "000102030405060708090a0b0c0d0e0f";
            do_test_gen_sk_from_seed_and_derivation_path(
                SCHEME,
                SEED,
                "m",
                "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
            );
            do_test_gen_sk_from_seed_and_derivation_path(
                SCHEME,
                SEED,
                "m/0'",
                "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7",
            );
            do_test_gen_sk_from_seed_and_derivation_path(
                SCHEME,
                SEED,
                "m/0'/1",
                "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs",
            );
            do_test_gen_sk_from_seed_and_derivation_path(
                SCHEME,
                SEED,
                "m/0'/1/2'",
                "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM",
            );
            do_test_gen_sk_from_seed_and_derivation_path(
                SCHEME,
                SEED,
                "m/0'/1/2'/2",
                "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334",
            );
            do_test_gen_sk_from_seed_and_derivation_path(
                SCHEME,
                SEED,
                "m/0'/1/2'/2/1000000000",
                "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76",
            );
        }
        {
            // Test vector 2
            const SEED: &str = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542";
            do_test_gen_sk_from_seed_and_derivation_path(
                SCHEME,
                SEED,
                "m",
                "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U",
            );
            do_test_gen_sk_from_seed_and_derivation_path(
                SCHEME,
                SEED,
                "m/0",
                "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt",
            );
            do_test_gen_sk_from_seed_and_derivation_path(
                SCHEME,
                SEED,
                "m/0/2147483647'",
                "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9",
            );
            do_test_gen_sk_from_seed_and_derivation_path(
                SCHEME,
                SEED,
                "m/0/2147483647'/1",
                "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef",
            );
            do_test_gen_sk_from_seed_and_derivation_path(
                SCHEME,
                SEED,
                "m/0/2147483647'/1/2147483646'",
                "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc",
            );
            do_test_gen_sk_from_seed_and_derivation_path(
                SCHEME,
                SEED,
                "m/0/2147483647'/1/2147483646'/2",
                "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j",
            );
        }
    }

    #[test]
    fn gen_sk_from_seed_ed25519() {
        const SCHEME: SchemeType = SchemeType::Ed25519;
        // https://github.com/satoshilabs/slips/blob/master/slip-0010.md
        {
            // Test vector 1 for ed15519
            const SEED: &str = "000102030405060708090a0b0c0d0e0f";
            do_test_gen_sk_from_seed_and_derivation_path(
                SCHEME,
                SEED,
                "m",
                "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7",
            );
            do_test_gen_sk_from_seed_and_derivation_path(
                SCHEME,
                SEED,
                "m/0'",
                "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3",
            );
            do_test_gen_sk_from_seed_and_derivation_path(
                SCHEME,
                SEED,
                "m/0'/1'",
                "b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2",
            );
            do_test_gen_sk_from_seed_and_derivation_path(
                SCHEME,
                SEED,
                "m/0'/1'/2'",
                "92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc9",
            );
            do_test_gen_sk_from_seed_and_derivation_path(
                SCHEME,
                SEED,
                "m/0'/1'/2'/2'",
                "30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662",
            );
            do_test_gen_sk_from_seed_and_derivation_path(
                SCHEME,
                SEED,
                "m/0'/1'/2'/2'/1000000000'",
                "8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793",
            );
        }
        {
            // Test vector 2 for ed15519
            const SEED: &str = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542";
            do_test_gen_sk_from_seed_and_derivation_path(
                SCHEME,
                SEED,
                "m",
                "171cb88b1b3c1db25add599712e36245d75bc65a1a5c9e18d76f9f2b1eab4012",
            );
            do_test_gen_sk_from_seed_and_derivation_path(
                SCHEME,
                SEED,
                "m/0'",
                "1559eb2bbec5790b0c65d8693e4d0875b1747f4970ae8b650486ed7470845635",
            );
            do_test_gen_sk_from_seed_and_derivation_path(
                SCHEME,
                SEED,
                "m/0'/2147483647'",
                "ea4f5bfe8694d8bb74b7b59404632fd5968b774ed545e810de9c32a4fb4192f4",
            );
            do_test_gen_sk_from_seed_and_derivation_path(
                SCHEME,
                SEED,
                "m/0'/2147483647'/1'",
                "3757c7577170179c7868353ada796c839135b3d30554bbb74a4b1e4a5a58505c",
            );
            do_test_gen_sk_from_seed_and_derivation_path(
                SCHEME,
                SEED,
                "m/0'/2147483647'/1'/2147483646'",
                "5837736c89570de861ebc173b1086da4f505d4adb387c6a1b1342d5e4ac9ec72",
            );
            do_test_gen_sk_from_seed_and_derivation_path(
                SCHEME,
                SEED,
                "m/0'/2147483647'/1'/2147483646'/2'",
                "551d333177df541ad876a60ea71f00447931c0a9da16f227c11ea080d7391b8d",
            );
        }
    }
}
