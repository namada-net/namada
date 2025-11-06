use core::fmt;
use std::str::FromStr;

use derivation_path::{ChildIndex, DerivationPath as DerivationPathInner};
use masp_primitives::zip32;
use namada_core::key::SchemeType;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

const BIP44_PURPOSE: u32 = 44;
const ZIP32_PURPOSE: u32 = 32;
// Maximum allowed value in BIP44
const MODIFIED_ZIP32_ADDR: u32 = 0x7FFFFFFF;

const ETH_COIN_TYPE: u32 = 60;
const NAMADA_COIN_TYPE: u32 = 877;

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum DerivationPathError {
    #[error("invalid derivation path: {0}")]
    InvalidDerivationPath(String),
}

/// A key derivation path
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DerivationPath(DerivationPathInner);

impl DerivationPath {
    fn new<P>(path: P) -> Self
    where
        P: Into<Box<[ChildIndex]>>,
    {
        Self(DerivationPathInner::new(path))
    }

    /// Check if the path has a compatible transparent coin type
    pub fn has_transparent_compatible_coin_type(
        &self,
        scheme: SchemeType,
    ) -> bool {
        if let Some(coin_type) = self.0.as_ref().get(1) {
            let coin_type = coin_type.to_u32();
            match scheme {
                SchemeType::Ed25519 => coin_type == NAMADA_COIN_TYPE,
                SchemeType::Secp256k1 => coin_type == ETH_COIN_TYPE,
                _ => true,
            }
        } else {
            true
        }
    }

    /// Check if the path has a compatible shielded coin type
    pub fn has_shielded_compatible_coin_type(&self) -> bool {
        if let Some(coin_type) = self.0.as_ref().get(1) {
            coin_type.to_u32() == NAMADA_COIN_TYPE
        } else {
            true
        }
    }

    /// Check if the path is BIP-0044 conform
    /// <https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki#path-levels>
    pub fn is_bip44_conform(&self, strict: bool) -> bool {
        // check the path conforms the structure:
        // m / purpose' / coin_type' / account' / change / address_index
        let purpose = self.0.as_ref().first();
        let coin_type = self.0.as_ref().get(1);
        let account = self.0.as_ref().get(2);
        let change = self.0.as_ref().get(3);
        let address = self.0.as_ref().get(4);
        let junk = self.0.as_ref().get(5);
        if let (
            Some(purpose),
            Some(coin_type),
            Some(account),
            Some(change),
            Some(address),
            None,
        ) = (purpose, coin_type, account, change, address, junk)
        {
            purpose.to_u32() == BIP44_PURPOSE
                && purpose.is_hardened()
                && coin_type.is_hardened()
                && account.is_hardened()
                && (!strict || (change.is_normal() && address.is_normal()))
        } else {
            false
        }
    }

    /// Check if the path is SLIP-0010 conform
    /// <https://github.com/satoshilabs/slips/blob/master/slip-0010.md#child-key-derivation-ckd-functions>
    pub fn is_slip10_conform(&self, scheme: SchemeType) -> bool {
        match scheme {
            SchemeType::Ed25519 => {
                // all indices must be hardened
                self.0.as_ref().iter().all(|idx| idx.is_hardened())
            }
            // no restriction for secp256k1 scheme
            _ => true,
        }
    }

    /// Check if the path is ZIP-0032 conform
    /// <https://zips.z.cash/zip-0032#sapling-key-path>
    pub fn is_zip32_conform(&self) -> bool {
        // check the path conforms one of the structure:
        // m / purpose' / coin_type' / account'
        // m / purpose' / coin_type' / account' / address_index
        let purpose = self.0.as_ref().first();
        let coin_type = self.0.as_ref().get(1);
        let account = self.0.as_ref().get(2);
        let address = self.0.as_ref().get(3);
        let junk = self.0.as_ref().get(4);
        if let (Some(purpose), Some(coin_type), Some(account), None) =
            (purpose, coin_type, account, junk)
        {
            purpose.to_u32() == ZIP32_PURPOSE
                && purpose.is_hardened()
                && coin_type.is_hardened()
                && account.is_hardened()
                && (address.is_none() || address.unwrap().is_normal())
        } else {
            false
        }
    }

    /// Check if the path is compliant with Namada's transparent scheme
    pub fn is_namada_transparent_compliant(&self, scheme: SchemeType) -> bool {
        match scheme {
            SchemeType::Ed25519 => {
                self.is_bip44_conform(false)
                    && self.is_slip10_conform(scheme)
                    && self.has_transparent_compatible_coin_type(scheme)
            }
            SchemeType::Secp256k1 => {
                self.is_bip44_conform(true)
                    && self.has_transparent_compatible_coin_type(scheme)
            }
            SchemeType::Common => false,
        }
    }

    /// Check if the path is compliant with Namada's shielded scheme
    pub fn is_namada_shielded_compliant(&self) -> bool {
        self.is_zip32_conform() && self.has_shielded_compatible_coin_type()
    }

    /// Modified ZIP32 path is used to derive Ed25519 keys to derive shielded
    /// keys in way that's compatible with the Ledger device app, in which the
    /// pure ZIP32 cannot be used because its secret is inaccessible.
    pub fn modified_zip32() -> (Self, SchemeType) {
        let scheme = SchemeType::Ed25519;
        let path = Self::bip44(scheme, 0, 0, MODIFIED_ZIP32_ADDR);
        (path.hardened(scheme), scheme)
    }

    fn bip44_base_indexes_for_scheme(scheme: SchemeType) -> Vec<ChildIndex> {
        vec![
            ChildIndex::Hardened(BIP44_PURPOSE),
            match scheme {
                SchemeType::Secp256k1 => ChildIndex::Hardened(ETH_COIN_TYPE),
                SchemeType::Ed25519 => ChildIndex::Hardened(NAMADA_COIN_TYPE),
                SchemeType::Common => unimplemented!("not implemented"),
            },
        ]
    }

    fn bip44(
        scheme: SchemeType,
        account: u32,
        change: u32,
        address: u32,
    ) -> Self {
        let mut indexes = Self::bip44_base_indexes_for_scheme(scheme);
        indexes.push(ChildIndex::Hardened(account));
        indexes.push(ChildIndex::Normal(change));
        indexes.push(ChildIndex::Normal(address));
        Self::new(indexes)
    }

    /// Key path according to zip-0032
    /// https://zips.z.cash/zip-0032#sapling-key-path
    fn zip32(account: u32, address: Option<u32>) -> Self {
        let mut indexes = vec![
            ChildIndex::Hardened(ZIP32_PURPOSE),
            ChildIndex::Hardened(NAMADA_COIN_TYPE),
            ChildIndex::Hardened(account),
        ];
        if let Some(address) = address {
            indexes.push(ChildIndex::Normal(address));
        }
        Self::new(indexes)
    }

    fn hardened(&self, scheme: SchemeType) -> Self {
        Self::new(
            self.0
                .into_iter()
                .map(|idx| match scheme {
                    SchemeType::Ed25519 => ChildIndex::Hardened(idx.to_u32()),
                    _ => *idx,
                })
                .collect::<Vec<_>>(),
        )
    }

    /// A default derivation path for transparent scheme
    pub fn default_for_transparent_scheme(scheme: SchemeType) -> Self {
        let path = Self::bip44(scheme, 0, 0, 0);
        path.hardened(scheme)
    }

    /// A default derivation path for shielded scheme
    pub fn default_for_shielded() -> Self {
        Self::zip32(0, None)
    }

    /// Try to parse a derivation path from a string
    pub fn from_path_string(path: &str) -> Result<Self, DerivationPathError> {
        let inner = DerivationPathInner::from_str(path).map_err(|err| {
            DerivationPathError::InvalidDerivationPath(err.to_string())
        })?;
        Ok(Self(inner))
    }

    /// Try to parse a derivation path for transparent scheme from a string
    pub fn from_path_string_for_transparent_scheme(
        scheme: SchemeType,
        path: &str,
    ) -> Result<Self, DerivationPathError> {
        Self::from_path_string(path).map(|dp| dp.hardened(scheme))
    }

    /// Get a reference to the path's list of [`ChildIndex`] items
    pub fn path(&self) -> &[ChildIndex] {
        self.0.path()
    }
}

impl fmt::Display for DerivationPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl FromStr for DerivationPath {
    type Err = DerivationPathError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        DerivationPathInner::from_str(s).map(Self).map_err(|err| {
            DerivationPathError::InvalidDerivationPath(err.to_string())
        })
    }
}

impl Serialize for DerivationPath {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for DerivationPath {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let string = String::deserialize(d)?;
        string.parse().map_err(serde::de::Error::custom)
    }
}

impl TryFrom<DerivationPath> for bip32::DerivationPath {
    type Error = <bip32::DerivationPath as FromStr>::Err;

    fn try_from(
        DerivationPath(inner): DerivationPath,
    ) -> Result<Self, Self::Error> {
        bip32::DerivationPath::from_str(&inner.to_string())
    }
}

impl From<DerivationPath> for Vec<zip32::ChildIndex> {
    fn from(path: DerivationPath) -> Vec<zip32::ChildIndex> {
        path.0
            .into_iter()
            .map(|idx| match idx {
                ChildIndex::Normal(idx) => zip32::ChildIndex::NonHardened(*idx),
                ChildIndex::Hardened(idx) => zip32::ChildIndex::Hardened(*idx),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use namada_core::key::SchemeType;

    use super::DerivationPath;

    #[test]
    fn path_conformity() {
        let path_empty = DerivationPath::from_path_string("m")
            .expect("Path construction cannot fail.");
        assert!(
            path_empty
                .has_transparent_compatible_coin_type(SchemeType::Ed25519)
        );
        assert!(
            path_empty
                .has_transparent_compatible_coin_type(SchemeType::Secp256k1)
        );
        assert!(path_empty.has_shielded_compatible_coin_type());
        assert!(!path_empty.is_bip44_conform(true));
        assert!(!path_empty.is_bip44_conform(false));
        assert!(path_empty.is_slip10_conform(SchemeType::Ed25519));
        assert!(path_empty.is_slip10_conform(SchemeType::Secp256k1));
        assert!(!path_empty.is_zip32_conform());
        assert!(
            !path_empty.is_namada_transparent_compliant(SchemeType::Ed25519)
        );
        assert!(
            !path_empty.is_namada_transparent_compliant(SchemeType::Secp256k1)
        );
        assert!(!path_empty.is_namada_shielded_compliant());

        let path_eth = DerivationPath::from_path_string("m/44'/60'/0'/0/0")
            .expect("Path construction cannot fail.");
        assert!(
            !path_eth.has_transparent_compatible_coin_type(SchemeType::Ed25519)
        );
        assert!(
            path_eth
                .has_transparent_compatible_coin_type(SchemeType::Secp256k1)
        );
        assert!(!path_eth.has_shielded_compatible_coin_type());
        assert!(path_eth.is_bip44_conform(true));
        assert!(path_eth.is_bip44_conform(false));
        assert!(!path_eth.is_slip10_conform(SchemeType::Ed25519));
        assert!(path_eth.is_slip10_conform(SchemeType::Secp256k1));
        assert!(!path_eth.is_zip32_conform());
        assert!(!path_eth.is_namada_transparent_compliant(SchemeType::Ed25519));
        assert!(
            path_eth.is_namada_transparent_compliant(SchemeType::Secp256k1)
        );
        assert!(!path_eth.is_namada_shielded_compliant());

        let path_nam = DerivationPath::from_path_string("m/44'/877'/0'/0'/0'")
            .expect("Path construction cannot fail.");
        assert!(
            path_nam.has_transparent_compatible_coin_type(SchemeType::Ed25519)
        );
        assert!(
            !path_nam
                .has_transparent_compatible_coin_type(SchemeType::Secp256k1)
        );
        assert!(path_nam.has_shielded_compatible_coin_type());
        assert!(!path_nam.is_bip44_conform(true));
        assert!(path_nam.is_bip44_conform(false));
        assert!(path_nam.is_slip10_conform(SchemeType::Ed25519));
        assert!(path_nam.is_slip10_conform(SchemeType::Secp256k1));
        assert!(!path_nam.is_zip32_conform());
        assert!(path_nam.is_namada_transparent_compliant(SchemeType::Ed25519));
        assert!(
            !path_nam.is_namada_transparent_compliant(SchemeType::Secp256k1)
        );
        assert!(!path_nam.is_namada_shielded_compliant());

        let path_z_1 = DerivationPath::from_path_string("m/32'/877'/0'")
            .expect("Path construction cannot fail.");
        assert!(
            path_z_1.has_transparent_compatible_coin_type(SchemeType::Ed25519)
        );
        assert!(
            !path_z_1
                .has_transparent_compatible_coin_type(SchemeType::Secp256k1)
        );
        assert!(path_z_1.has_shielded_compatible_coin_type());
        assert!(!path_z_1.is_bip44_conform(true));
        assert!(!path_z_1.is_bip44_conform(false));
        assert!(path_z_1.is_slip10_conform(SchemeType::Ed25519));
        assert!(path_z_1.is_slip10_conform(SchemeType::Secp256k1));
        assert!(path_z_1.is_zip32_conform());
        assert!(!path_z_1.is_namada_transparent_compliant(SchemeType::Ed25519));
        assert!(
            !path_z_1.is_namada_transparent_compliant(SchemeType::Secp256k1)
        );
        assert!(path_z_1.is_namada_shielded_compliant());

        let path_z_2 = DerivationPath::from_path_string("m/32'/877'/0'/0")
            .expect("Path construction cannot fail.");
        assert!(
            path_z_2.has_transparent_compatible_coin_type(SchemeType::Ed25519)
        );
        assert!(
            !path_z_2
                .has_transparent_compatible_coin_type(SchemeType::Secp256k1)
        );
        assert!(path_z_2.has_shielded_compatible_coin_type());
        assert!(!path_z_2.is_bip44_conform(true));
        assert!(!path_z_2.is_bip44_conform(false));
        assert!(!path_z_2.is_slip10_conform(SchemeType::Ed25519));
        assert!(path_z_2.is_slip10_conform(SchemeType::Secp256k1));
        assert!(path_z_2.is_zip32_conform());
        assert!(!path_z_2.is_namada_transparent_compliant(SchemeType::Ed25519));
        assert!(
            !path_z_2.is_namada_transparent_compliant(SchemeType::Secp256k1)
        );
        assert!(path_z_2.is_namada_shielded_compliant());

        let (modified_zip32, zip32_scheme) = DerivationPath::modified_zip32();
        assert!(matches!(zip32_scheme, SchemeType::Ed25519));
        assert_eq!(
            modified_zip32,
            DerivationPath::from_path_string("m/44'/877'/0'/0'/2147483647'")
                .expect("Path construction cannot fail.")
        );
    }
}
