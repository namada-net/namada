use core::str::FromStr;
use std::collections::BTreeMap;
use std::sync::Arc;

use borsh::BorshDeserialize;
use eyre::eyre;
use masp_primitives::asset_type::AssetType;
use masp_primitives::merkle_tree::{
    CommitmentTree, IncrementalWitness, MerklePath,
};
use masp_primitives::sapling::{Node, Rseed, ViewingKey};
use masp_primitives::transaction::Transaction;
use masp_primitives::transaction::components::I128Sum;
use masp_primitives::zip32::ExtendedFullViewingKey;
use namada_core::address::Address;
use namada_core::borsh::BorshSerializeExt;
use namada_core::chain::BlockHeight;
use namada_core::collections::HashMap;
use namada_core::masp::{
    AssetData, ExtendedViewingKey, MaspEpoch, PaymentAddress,
};
use namada_core::time::DurationSecs;
use namada_core::token::{Denomination, MaspDigitPos};
use namada_io::client::EncodedResponseQuery;
use namada_io::{Client, MaybeSend, MaybeSync, NamadaIo, NullIo};
use namada_wallet::DatedKeypair;
use thiserror::Error;
use tokio::sync::Mutex;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

use super::utils::MaspIndexedTx;
use crate::ShieldedWallet;
use crate::masp::shielded_wallet::{CompactNote, ShieldedQueries};
use crate::masp::utils::{
    IndexedNoteEntry, MaspClient, MaspClientCapabilities,
};
use crate::masp::{NotePosition, ShieldedUtils};

/// A viewing key derived from A_SPENDING_KEY
pub const AA_VIEWING_KEY: &str = "zvknam1qqqqqqqqqqqqqq9v0sls5r5de7njx8ehu49pqgmqr9ygelg87l5x8y4s9r0pjlvu6x74w9gjpw856zcu826qesdre628y6tjc26uhgj6d9zqur9l5u3p99d9ggc74ald6s8y3sdtka74qmheyqvdrasqpwyv2fsmxlz57lj4grm2pthzj3sflxc0jx0edrakx3vdcngrfjmru8ywkguru8mxss2uuqxdlglaz6undx5h8w7g70t2es850g48xzdkqay5qs0yw06rtxcpjdve6";

// A payment address derived from A_SPENDING_KEY
pub const AA_PAYMENT_ADDRESS: &str = "znam1ky620tz7z658cralqt693qpvk42wvth468zp38nqvq2apmex5rfut3dfqm2asrsqv0tc7saqje7";

pub fn dated_arbitrary_vk() -> DatedKeypair<ViewingKey> {
    arbitrary_vk().into()
}

pub fn arbitrary_vk() -> ViewingKey {
    ExtendedFullViewingKey::from(
        ExtendedViewingKey::from_str(AA_VIEWING_KEY).expect("Test failed"),
    )
    .fvk
    .vk
}

pub fn arbitrary_pa() -> PaymentAddress {
    FromStr::from_str(AA_PAYMENT_ADDRESS).expect("Test failed")
}

/// A serialized transaction that will work for testing.
/// Would love to do this in a less opaque fashion, but
/// making these things is a misery not worth my time.
///
/// This a tx sending 1 BTC from Albert to Albert's PA,
/// that was extracted from a masp integration test.
///
/// ```ignore
/// vec![
///     "shield",
///     "--source",
///     ALBERT,
///     "--target",
///     AA_PAYMENT_ADDRESS,
///     "--token",
///     BTC,
///     "--amount",
///     "1",
///     "--node",
///     validator_one_rpc,
/// ]
/// ```
pub(super) fn arbitrary_masp_tx() -> Transaction {
    Transaction::try_from_slice(&[
        2, 0, 0, 0, 10, 39, 167, 38, 166, 117, 255, 233, 0, 0, 0, 0, 255, 255,
        255, 255, 1, 162, 120, 217, 193, 173, 117, 92, 126, 107, 199, 182, 72,
        95, 60, 122, 52, 9, 134, 72, 4, 167, 41, 187, 171, 17, 124, 114, 84,
        191, 75, 37, 2, 0, 225, 245, 5, 0, 0, 0, 0, 93, 213, 181, 21, 38, 32,
        230, 52, 155, 4, 203, 26, 70, 63, 59, 179, 142, 7, 72, 76, 0, 0, 0, 1,
        132, 100, 41, 23, 128, 97, 116, 40, 195, 40, 46, 55, 79, 106, 234, 32,
        4, 216, 106, 88, 173, 65, 140, 99, 239, 71, 103, 201, 111, 149, 166,
        13, 73, 224, 253, 98, 27, 199, 11, 142, 56, 214, 4, 96, 35, 72, 83, 86,
        194, 107, 163, 194, 238, 37, 19, 171, 8, 129, 53, 246, 64, 220, 155,
        47, 177, 165, 109, 232, 84, 247, 128, 184, 40, 26, 113, 196, 190, 181,
        57, 213, 45, 144, 46, 12, 145, 128, 169, 116, 65, 51, 208, 239, 50,
        217, 224, 98, 179, 53, 18, 130, 183, 114, 225, 21, 34, 175, 144, 125,
        239, 240, 82, 100, 174, 1, 192, 32, 187, 208, 205, 31, 108, 59, 87,
        201, 148, 214, 244, 255, 8, 150, 100, 225, 11, 245, 221, 170, 85, 241,
        110, 50, 90, 151, 210, 169, 41, 3, 23, 160, 196, 117, 211, 217, 121, 9,
        42, 236, 19, 149, 94, 62, 163, 222, 172, 128, 197, 56, 100, 233, 227,
        239, 60, 182, 191, 55, 148, 17, 0, 168, 198, 84, 87, 191, 89, 229, 9,
        129, 165, 98, 200, 127, 225, 192, 58, 0, 92, 104, 97, 26, 125, 169,
        209, 40, 170, 29, 93, 16, 114, 174, 23, 233, 218, 112, 26, 175, 196,
        198, 197, 159, 167, 157, 16, 232, 247, 193, 44, 82, 143, 238, 179, 77,
        87, 153, 3, 33, 207, 215, 142, 104, 179, 17, 252, 148, 215, 150, 76,
        56, 169, 13, 240, 4, 195, 221, 45, 250, 24, 51, 243, 174, 176, 47, 117,
        38, 1, 124, 193, 191, 55, 11, 164, 97, 83, 188, 92, 202, 229, 106, 236,
        165, 85, 236, 95, 255, 28, 71, 18, 173, 202, 47, 63, 226, 129, 203,
        154, 54, 155, 177, 161, 106, 210, 220, 193, 142, 44, 105, 46, 164, 83,
        136, 63, 24, 172, 157, 117, 9, 202, 99, 223, 144, 36, 26, 154, 84, 175,
        119, 12, 102, 71, 33, 14, 131, 250, 86, 215, 153, 18, 94, 213, 61, 196,
        67, 132, 204, 89, 235, 241, 188, 147, 236, 92, 46, 83, 169, 236, 12,
        34, 33, 65, 243, 18, 23, 29, 41, 252, 207, 17, 196, 55, 56, 141, 158,
        116, 227, 195, 159, 233, 72, 26, 69, 72, 213, 50, 101, 161, 127, 213,
        35, 210, 223, 201, 219, 198, 192, 125, 129, 222, 178, 241, 116, 59,
        255, 72, 163, 46, 21, 222, 74, 202, 117, 217, 22, 188, 203, 2, 150, 38,
        78, 78, 250, 45, 36, 225, 240, 227, 115, 33, 114, 189, 25, 9, 219, 239,
        57, 103, 19, 109, 11, 5, 156, 43, 35, 53, 219, 250, 215, 185, 173, 11,
        101, 221, 29, 130, 74, 110, 225, 183, 77, 13, 52, 90, 183, 93, 212,
        175, 132, 21, 229, 109, 188, 124, 103, 3, 39, 174, 140, 115, 67, 49,
        100, 231, 129, 32, 24, 201, 196, 247, 33, 155, 20, 139, 34, 3, 183, 12,
        164, 6, 10, 219, 207, 151, 160, 4, 201, 160, 12, 156, 82, 142, 226, 19,
        134, 144, 53, 220, 140, 61, 74, 151, 129, 102, 214, 73, 107, 147, 4,
        98, 68, 79, 225, 103, 242, 187, 170, 102, 225, 114, 4, 87, 96, 7, 212,
        150, 127, 211, 158, 54, 86, 15, 191, 21, 116, 202, 195, 60, 65, 134,
        22, 2, 44, 133, 64, 181, 121, 66, 218, 227, 72, 148, 63, 108, 227, 33,
        66, 239, 77, 127, 139, 31, 16, 150, 119, 198, 119, 229, 88, 188, 113,
        80, 222, 86, 122, 181, 142, 186, 130, 125, 236, 166, 95, 134, 243, 128,
        65, 169, 33, 65, 73, 182, 183, 156, 248, 39, 46, 199, 181, 85, 96, 126,
        155, 189, 10, 211, 145, 230, 94, 69, 232, 74, 87, 211, 46, 216, 30, 24,
        38, 104, 192, 165, 28, 73, 36, 227, 194, 41, 168, 5, 181, 176, 112, 67,
        92, 158, 212, 129, 207, 182, 223, 59, 185, 84, 210, 147, 32, 29, 61,
        56, 185, 21, 156, 114, 34, 115, 29, 25, 89, 152, 56, 55, 238, 43, 0,
        114, 89, 79, 95, 104, 143, 180, 51, 53, 108, 223, 236, 59, 47, 188,
        174, 196, 101, 180, 207, 162, 198, 104, 52, 67, 132, 178, 9, 40, 10,
        88, 206, 25, 132, 60, 136, 13, 213, 223, 81, 196, 131, 118, 15, 53,
        125, 165, 177, 170, 170, 17, 94, 53, 151, 51, 16, 170, 23, 118, 255,
        26, 46, 47, 37, 73, 165, 26, 43, 10, 221, 4, 132, 15, 78, 214, 161, 3,
        220, 10, 87, 139, 85, 61, 39, 131, 242, 216, 235, 52, 93, 46, 180, 196,
        151, 54, 207, 80, 223, 90, 252, 77, 10, 122, 175, 229, 7, 144, 41, 1,
        162, 120, 217, 193, 173, 117, 92, 126, 107, 199, 182, 72, 95, 60, 122,
        52, 9, 134, 72, 4, 167, 41, 187, 171, 17, 124, 114, 84, 191, 75, 37, 2,
        0, 31, 10, 250, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 151, 241, 211, 167, 49, 151, 215, 148, 38, 149, 99, 140, 79, 169,
        172, 15, 195, 104, 140, 79, 151, 116, 185, 5, 161, 78, 58, 63, 23, 27,
        172, 88, 108, 85, 232, 63, 249, 122, 26, 239, 251, 58, 240, 10, 219,
        34, 198, 187, 147, 224, 43, 96, 82, 113, 159, 96, 125, 172, 211, 160,
        136, 39, 79, 101, 89, 107, 208, 208, 153, 32, 182, 26, 181, 218, 97,
        187, 220, 127, 80, 73, 51, 76, 241, 18, 19, 148, 93, 87, 229, 172, 125,
        5, 93, 4, 43, 126, 2, 74, 162, 178, 240, 143, 10, 145, 38, 8, 5, 39,
        45, 197, 16, 81, 198, 228, 122, 212, 250, 64, 59, 2, 180, 81, 11, 100,
        122, 227, 209, 119, 11, 172, 3, 38, 168, 5, 187, 239, 212, 128, 86,
        200, 193, 33, 189, 184, 151, 241, 211, 167, 49, 151, 215, 148, 38, 149,
        99, 140, 79, 169, 172, 15, 195, 104, 140, 79, 151, 116, 185, 5, 161,
        78, 58, 63, 23, 27, 172, 88, 108, 85, 232, 63, 249, 122, 26, 239, 251,
        58, 240, 10, 219, 34, 198, 187, 37, 197, 248, 90, 113, 62, 149, 117,
        145, 118, 42, 241, 60, 208, 83, 57, 96, 143, 17, 128, 92, 118, 158,
        188, 77, 37, 184, 164, 135, 246, 196, 57, 198, 106, 139, 33, 15, 207,
        0, 101, 143, 92, 178, 132, 19, 106, 221, 246, 176, 100, 20, 114, 26,
        55, 163, 14, 173, 255, 121, 181, 58, 121, 140, 3,
    ])
    .expect("Test failed")
}

pub fn arbitrary_masp_tx_with_fee_unshielding() -> Transaction {
    Transaction::try_from_slice(&[
        2, 0, 0, 0, 10, 39, 167, 38, 166, 117, 255, 233, 0, 0, 0, 0, 54, 14, 0,
        0, 0, 1, 132, 75, 163, 63, 233, 122, 16, 179, 171, 48, 165, 210, 73,
        246, 21, 24, 53, 83, 72, 109, 181, 141, 152, 120, 120, 192, 141, 228,
        43, 151, 181, 8, 0, 148, 53, 119, 0, 0, 0, 0, 250, 202, 53, 130, 143,
        250, 251, 227, 54, 126, 179, 56, 3, 85, 98, 1, 48, 171, 177, 47, 1, 62,
        21, 144, 5, 204, 39, 91, 144, 214, 181, 161, 161, 237, 133, 157, 158,
        239, 212, 247, 48, 73, 76, 221, 53, 253, 105, 147, 15, 53, 111, 77,
        195, 140, 207, 94, 202, 227, 254, 242, 102, 190, 217, 45, 218, 223, 85,
        150, 131, 186, 242, 219, 98, 191, 11, 185, 27, 122, 72, 30, 167, 185,
        225, 241, 39, 82, 214, 140, 147, 198, 68, 170, 36, 45, 242, 251, 20,
        76, 103, 129, 200, 100, 82, 165, 190, 67, 203, 120, 246, 182, 167, 231,
        158, 247, 34, 54, 171, 1, 219, 110, 221, 72, 70, 32, 83, 43, 216, 73,
        237, 151, 76, 46, 230, 128, 61, 218, 65, 214, 246, 68, 29, 222, 227,
        175, 7, 113, 190, 190, 5, 209, 2, 25, 99, 15, 86, 219, 198, 61, 135,
        240, 240, 184, 44, 24, 187, 220, 239, 11, 77, 14, 100, 192, 242, 122,
        148, 77, 214, 123, 195, 150, 90, 25, 28, 185, 164, 129, 128, 196, 7,
        106, 113, 35, 27, 144, 8, 102, 114, 78, 214, 216, 187, 119, 211, 106,
        250, 158, 91, 140, 232, 89, 248, 117, 239, 211, 94, 196, 36, 201, 171,
        207, 45, 187, 58, 240, 161, 254, 183, 131, 126, 93, 151, 143, 221, 24,
        38, 109, 196, 206, 184, 49, 106, 182, 98, 147, 3, 255, 173, 66, 68, 45,
        193, 102, 151, 53, 62, 85, 175, 25, 183, 94, 249, 54, 87, 124, 153, 61,
        71, 13, 81, 2, 118, 210, 31, 158, 46, 111, 239, 233, 225, 122, 196,
        185, 41, 242, 60, 237, 203, 69, 40, 74, 86, 216, 57, 39, 227, 100, 189,
        149, 133, 208, 95, 63, 27, 23, 83, 111, 119, 228, 22, 23, 251, 246, 84,
        48, 243, 199, 173, 83, 177, 60, 142, 147, 243, 244, 89, 122, 205, 250,
        99, 133, 45, 55, 39, 200, 49, 203, 119, 120, 60, 234, 33, 15, 73, 182,
        245, 163, 72, 211, 98, 81, 251, 15, 142, 150, 133, 18, 234, 237, 255,
        205, 11, 83, 163, 39, 100, 198, 243, 41, 209, 246, 187, 114, 224, 14,
        146, 231, 44, 131, 120, 24, 205, 189, 205, 4, 64, 54, 164, 77, 59, 159,
        129, 94, 243, 123, 221, 170, 66, 89, 100, 88, 220, 254, 36, 235, 65,
        244, 177, 109, 45, 91, 193, 64, 62, 211, 153, 12, 139, 193, 75, 36,
        133, 61, 174, 84, 3, 41, 225, 247, 129, 134, 186, 53, 58, 14, 203, 227,
        132, 61, 76, 226, 49, 75, 106, 96, 7, 148, 152, 8, 176, 149, 136, 204,
        255, 69, 197, 168, 11, 132, 14, 27, 188, 119, 223, 149, 100, 107, 32,
        56, 162, 232, 152, 160, 158, 92, 212, 225, 192, 83, 106, 98, 42, 198,
        182, 224, 92, 68, 77, 128, 190, 174, 81, 197, 214, 78, 186, 180, 38,
        98, 164, 113, 85, 215, 62, 16, 84, 120, 119, 216, 10, 182, 238, 248,
        132, 214, 46, 81, 90, 166, 234, 161, 230, 246, 200, 129, 141, 161, 222,
        228, 193, 202, 213, 39, 53, 250, 88, 116, 99, 219, 206, 17, 145, 61,
        220, 154, 124, 173, 225, 79, 38, 200, 126, 44, 110, 173, 7, 143, 61,
        213, 71, 51, 194, 103, 47, 67, 182, 132, 72, 0, 220, 217, 206, 232,
        225, 124, 177, 128, 146, 107, 230, 173, 248, 119, 186, 74, 173, 163,
        206, 107, 192, 219, 186, 216, 127, 153, 140, 152, 248, 132, 80, 18,
        126, 31, 159, 100, 161, 228, 247, 139, 28, 33, 210, 61, 222, 180, 1, 2,
        247, 58, 145, 176, 169, 91, 150, 76, 190, 134, 27, 113, 129, 207, 255,
        115, 250, 230, 0, 7, 48, 120, 70, 107, 221, 25, 17, 203, 204, 180, 254,
        100, 113, 176, 178, 67, 198, 43, 13, 237, 125, 246, 61, 190, 82, 195,
        202, 173, 16, 83, 0, 41, 150, 104, 57, 242, 198, 170, 138, 181, 189,
        219, 208, 240, 204, 24, 249, 115, 181, 19, 145, 18, 203, 77, 12, 164,
        253, 121, 2, 133, 233, 108, 234, 26, 66, 44, 75, 122, 187, 234, 33,
        227, 248, 62, 23, 174, 68, 234, 124, 60, 24, 106, 250, 117, 39, 185,
        36, 118, 220, 46, 204, 216, 218, 135, 241, 230, 247, 192, 65, 4, 105,
        139, 91, 219, 231, 9, 58, 252, 19, 63, 65, 210, 17, 204, 117, 138, 210,
        129, 91, 9, 197, 31, 21, 95, 230, 238, 170, 46, 30, 75, 92, 60, 199,
        85, 183, 74, 31, 151, 187, 208, 47, 37, 15, 213, 172, 111, 190, 50,
        120, 242, 75, 125, 17, 188, 137, 5, 47, 190, 255, 180, 70, 115, 159,
        39, 141, 172, 193, 126, 135, 230, 71, 78, 197, 184, 116, 51, 105, 96,
        253, 179, 34, 33, 103, 191, 33, 1, 45, 114, 187, 101, 239, 124, 23,
        196, 78, 102, 123, 88, 249, 145, 35, 158, 94, 48, 4, 86, 125, 228, 12,
        172, 159, 134, 82, 200, 48, 124, 139, 137, 150, 78, 68, 171, 22, 143,
        137, 151, 158, 229, 105, 213, 157, 231, 140, 24, 16, 98, 124, 120, 208,
        51, 186, 217, 229, 177, 84, 183, 183, 159, 250, 192, 73, 36, 103, 165,
        172, 64, 152, 95, 229, 198, 3, 237, 193, 58, 218, 58, 209, 131, 183,
        36, 219, 194, 116, 217, 51, 26, 137, 187, 85, 223, 16, 243, 12, 112,
        51, 92, 190, 43, 101, 218, 96, 75, 137, 165, 115, 147, 165, 72, 151,
        123, 229, 152, 142, 215, 35, 144, 137, 58, 16, 20, 119, 95, 93, 205,
        243, 11, 92, 250, 72, 181, 130, 0, 223, 112, 228, 41, 243, 199, 181,
        101, 178, 140, 137, 56, 220, 31, 49, 194, 13, 96, 252, 202, 187, 169,
        6, 78, 148, 225, 235, 82, 213, 229, 55, 125, 217, 197, 232, 25, 33,
        149, 88, 87, 76, 19, 58, 241, 0, 11, 240, 97, 0, 163, 253, 34, 131, 9,
        234, 150, 107, 180, 117, 22, 188, 163, 112, 235, 96, 148, 95, 170, 122,
        241, 99, 84, 232, 148, 47, 197, 69, 244, 193, 163, 10, 148, 102, 197,
        82, 63, 199, 252, 40, 195, 194, 98, 116, 76, 28, 3, 48, 64, 77, 193,
        203, 158, 254, 96, 138, 149, 6, 187, 144, 105, 165, 82, 245, 115, 249,
        79, 2, 23, 1, 4, 111, 143, 244, 175, 35, 51, 189, 44, 128, 135, 226,
        240, 85, 199, 247, 128, 73, 28, 222, 134, 79, 240, 58, 148, 219, 245,
        4, 156, 196, 196, 41, 231, 28, 15, 118, 234, 215, 112, 87, 240, 60,
        142, 232, 214, 231, 124, 46, 217, 103, 32, 210, 71, 99, 217, 254, 56,
        104, 106, 221, 202, 109, 2, 11, 38, 73, 190, 154, 104, 128, 2, 0, 122,
        125, 179, 216, 173, 74, 47, 203, 167, 132, 97, 46, 8, 79, 251, 240,
        159, 153, 234, 243, 71, 28, 140, 13, 96, 10, 118, 105, 17, 226, 104,
        120, 52, 32, 39, 85, 30, 10, 33, 32, 149, 176, 147, 76, 38, 24, 214,
        44, 169, 137, 233, 233, 41, 154, 160, 99, 134, 171, 124, 158, 1, 95,
        176, 172, 219, 125, 178, 37, 51, 248, 95, 171, 246, 200, 246, 64, 94,
        128, 126, 8, 51, 16, 242, 220, 2, 92, 74, 232, 204, 19, 233, 196, 45,
        82, 75, 184, 230, 250, 42, 113, 11, 198, 1, 143, 170, 0, 139, 157, 182,
        251, 234, 175, 157, 239, 222, 190, 237, 204, 249, 128, 177, 139, 206,
        11, 24, 66, 9, 16, 47, 115, 152, 195, 29, 247, 47, 183, 89, 251, 105,
        8, 202, 241, 166, 223, 96, 8, 156, 44, 171, 66, 86, 66, 255, 108, 212,
        143, 141, 91, 142, 3, 233, 61, 251, 31, 105, 149, 234, 185, 248, 33,
        35, 70, 173, 227, 44, 230, 4, 0, 184, 163, 51, 115, 135, 209, 125, 92,
        237, 238, 18, 133, 176, 250, 51, 9, 253, 56, 236, 155, 215, 116, 17,
        102, 167, 242, 151, 81, 93, 20, 16, 188, 130, 126, 110, 109, 135, 74,
        57, 47, 73, 221, 144, 107, 106, 214, 200, 73, 45, 99, 155, 236, 96, 11,
        115, 45, 210, 167, 100, 230, 60, 38, 107, 102, 147, 200, 109, 79, 234,
        99, 6, 190, 235, 180, 61, 42, 220, 150, 209, 249, 5, 243, 240, 213,
        178, 54, 24, 183, 48, 141, 169, 136, 238, 146, 13, 104, 127, 98, 177,
        95, 4, 35, 137, 8, 63, 218, 234, 52, 93, 202, 23, 20, 227, 141, 158,
        188, 93, 241, 128, 48, 130, 154, 252, 74, 139, 228, 90, 41, 122, 98,
        214, 161, 7, 132, 130, 84, 69, 49, 168, 166, 15, 214, 174, 97, 91, 1,
        239, 124, 16, 31, 182, 140, 53, 225, 246, 167, 184, 37, 208, 173, 200,
        19, 201, 58, 255, 144, 45, 168, 132, 171, 199, 151, 175, 167, 96, 148,
        210, 92, 3, 74, 105, 157, 79, 125, 28, 162, 14, 120, 254, 31, 28, 91,
        190, 82, 30, 228, 153, 52, 47, 246, 225, 254, 157, 24, 62, 23, 187,
        236, 179, 41, 74, 73, 132, 37, 28, 244, 206, 244, 69, 80, 137, 179,
        127, 11, 23, 148, 125, 175, 197, 195, 172, 20, 165, 137, 21, 47, 76,
        151, 114, 121, 70, 160, 221, 28, 170, 224, 212, 80, 133, 96, 198, 53,
        215, 19, 190, 113, 29, 185, 91, 130, 231, 56, 192, 54, 153, 96, 126,
        162, 85, 22, 150, 245, 128, 129, 94, 76, 216, 48, 93, 223, 105, 114,
        73, 222, 251, 103, 217, 146, 204, 0, 51, 192, 91, 218, 115, 172, 47,
        226, 242, 92, 205, 163, 62, 242, 203, 6, 39, 26, 128, 56, 82, 140, 238,
        20, 26, 236, 26, 239, 115, 220, 58, 51, 160, 36, 128, 88, 14, 128, 228,
        134, 242, 61, 170, 117, 151, 222, 173, 106, 246, 68, 56, 86, 66, 164,
        62, 74, 239, 212, 204, 154, 56, 6, 36, 32, 242, 214, 234, 166, 122,
        137, 8, 31, 30, 11, 121, 226, 131, 110, 199, 154, 110, 150, 42, 68, 3,
        221, 157, 207, 33, 189, 232, 174, 174, 173, 253, 83, 239, 159, 166, 37,
        57, 169, 75, 98, 92, 62, 122, 201, 68, 90, 1, 132, 75, 163, 63, 233,
        122, 16, 179, 171, 48, 165, 210, 73, 246, 21, 24, 53, 83, 72, 109, 181,
        141, 152, 120, 120, 192, 141, 228, 43, 151, 181, 8, 0, 148, 53, 119, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 199, 214, 37, 167, 69, 68, 73, 122,
        235, 219, 62, 3, 220, 201, 85, 250, 95, 97, 155, 202, 124, 68, 91, 27,
        16, 228, 9, 4, 194, 14, 227, 98, 176, 5, 138, 20, 103, 224, 93, 110,
        10, 86, 243, 241, 70, 91, 32, 149, 163, 236, 115, 71, 171, 6, 82, 93,
        5, 100, 159, 22, 192, 16, 222, 16, 151, 241, 211, 167, 49, 151, 215,
        148, 38, 149, 99, 140, 79, 169, 172, 15, 195, 104, 140, 79, 151, 116,
        185, 5, 161, 78, 58, 63, 23, 27, 172, 88, 108, 85, 232, 63, 249, 122,
        26, 239, 251, 58, 240, 10, 219, 34, 198, 187, 147, 224, 43, 96, 82,
        113, 159, 96, 125, 172, 211, 160, 136, 39, 79, 101, 89, 107, 208, 208,
        153, 32, 182, 26, 181, 218, 97, 187, 220, 127, 80, 73, 51, 76, 241, 18,
        19, 148, 93, 87, 229, 172, 125, 5, 93, 4, 43, 126, 2, 74, 162, 178,
        240, 143, 10, 145, 38, 8, 5, 39, 45, 197, 16, 81, 198, 228, 122, 212,
        250, 64, 59, 2, 180, 81, 11, 100, 122, 227, 209, 119, 11, 172, 3, 38,
        168, 5, 187, 239, 212, 128, 86, 200, 193, 33, 189, 184, 151, 241, 211,
        167, 49, 151, 215, 148, 38, 149, 99, 140, 79, 169, 172, 15, 195, 104,
        140, 79, 151, 116, 185, 5, 161, 78, 58, 63, 23, 27, 172, 88, 108, 85,
        232, 63, 249, 122, 26, 239, 251, 58, 240, 10, 219, 34, 198, 187, 178,
        31, 240, 104, 171, 67, 69, 159, 141, 32, 22, 220, 23, 81, 212, 162, 75,
        112, 146, 29, 36, 104, 7, 93, 192, 52, 218, 22, 209, 227, 141, 80, 96,
        133, 50, 154, 7, 30, 119, 48, 222, 143, 91, 251, 235, 1, 71, 191, 85,
        203, 75, 242, 150, 60, 120, 220, 176, 102, 195, 205, 87, 148, 35, 14,
        151, 241, 211, 167, 49, 151, 215, 148, 38, 149, 99, 140, 79, 169, 172,
        15, 195, 104, 140, 79, 151, 116, 185, 5, 161, 78, 58, 63, 23, 27, 172,
        88, 108, 85, 232, 63, 249, 122, 26, 239, 251, 58, 240, 10, 219, 34,
        198, 187, 147, 224, 43, 96, 82, 113, 159, 96, 125, 172, 211, 160, 136,
        39, 79, 101, 89, 107, 208, 208, 153, 32, 182, 26, 181, 218, 97, 187,
        220, 127, 80, 73, 51, 76, 241, 18, 19, 148, 93, 87, 229, 172, 125, 5,
        93, 4, 43, 126, 2, 74, 162, 178, 240, 143, 10, 145, 38, 8, 5, 39, 45,
        197, 16, 81, 198, 228, 122, 212, 250, 64, 59, 2, 180, 81, 11, 100, 122,
        227, 209, 119, 11, 172, 3, 38, 168, 5, 187, 239, 212, 128, 86, 200,
        193, 33, 189, 184, 151, 241, 211, 167, 49, 151, 215, 148, 38, 149, 99,
        140, 79, 169, 172, 15, 195, 104, 140, 79, 151, 116, 185, 5, 161, 78,
        58, 63, 23, 27, 172, 88, 108, 85, 232, 63, 249, 122, 26, 239, 251, 58,
        240, 10, 219, 34, 198, 187, 151, 241, 211, 167, 49, 151, 215, 148, 38,
        149, 99, 140, 79, 169, 172, 15, 195, 104, 140, 79, 151, 116, 185, 5,
        161, 78, 58, 63, 23, 27, 172, 88, 108, 85, 232, 63, 249, 122, 26, 239,
        251, 58, 240, 10, 219, 34, 198, 187, 147, 224, 43, 96, 82, 113, 159,
        96, 125, 172, 211, 160, 136, 39, 79, 101, 89, 107, 208, 208, 153, 32,
        182, 26, 181, 218, 97, 187, 220, 127, 80, 73, 51, 76, 241, 18, 19, 148,
        93, 87, 229, 172, 125, 5, 93, 4, 43, 126, 2, 74, 162, 178, 240, 143,
        10, 145, 38, 8, 5, 39, 45, 197, 16, 81, 198, 228, 122, 212, 250, 64,
        59, 2, 180, 81, 11, 100, 122, 227, 209, 119, 11, 172, 3, 38, 168, 5,
        187, 239, 212, 128, 86, 200, 193, 33, 189, 184, 151, 241, 211, 167, 49,
        151, 215, 148, 38, 149, 99, 140, 79, 169, 172, 15, 195, 104, 140, 79,
        151, 116, 185, 5, 161, 78, 58, 63, 23, 27, 172, 88, 108, 85, 232, 63,
        249, 122, 26, 239, 251, 58, 240, 10, 219, 34, 198, 187, 151, 241, 211,
        167, 49, 151, 215, 148, 38, 149, 99, 140, 79, 169, 172, 15, 195, 104,
        140, 79, 151, 116, 185, 5, 161, 78, 58, 63, 23, 27, 172, 88, 108, 85,
        232, 63, 249, 122, 26, 239, 251, 58, 240, 10, 219, 34, 198, 187, 147,
        224, 43, 96, 82, 113, 159, 96, 125, 172, 211, 160, 136, 39, 79, 101,
        89, 107, 208, 208, 153, 32, 182, 26, 181, 218, 97, 187, 220, 127, 80,
        73, 51, 76, 241, 18, 19, 148, 93, 87, 229, 172, 125, 5, 93, 4, 43, 126,
        2, 74, 162, 178, 240, 143, 10, 145, 38, 8, 5, 39, 45, 197, 16, 81, 198,
        228, 122, 212, 250, 64, 59, 2, 180, 81, 11, 100, 122, 227, 209, 119,
        11, 172, 3, 38, 168, 5, 187, 239, 212, 128, 86, 200, 193, 33, 189, 184,
        151, 241, 211, 167, 49, 151, 215, 148, 38, 149, 99, 140, 79, 169, 172,
        15, 195, 104, 140, 79, 151, 116, 185, 5, 161, 78, 58, 63, 23, 27, 172,
        88, 108, 85, 232, 63, 249, 122, 26, 239, 251, 58, 240, 10, 219, 34,
        198, 187, 82, 2, 185, 222, 20, 51, 145, 121, 75, 194, 132, 93, 252,
        178, 133, 111, 188, 186, 87, 138, 98, 35, 247, 243, 58, 208, 231, 236,
        209, 34, 146, 233, 27, 26, 102, 108, 107, 103, 49, 196, 13, 97, 145,
        178, 23, 189, 15, 22, 166, 172, 195, 249, 87, 112, 158, 132, 76, 201,
        191, 134, 250, 101, 74, 7,
    ])
    .expect("Test failed")
}

/// A client for unit tests. It "fetches" a new note
/// when a channel controlled by the unit test sends
/// it one.
#[derive(Clone)]
pub struct TestingMaspClient {
    last_height: BlockHeight,
    tx_recv: flume::Receiver<Option<IndexedNoteEntry>>,
}

impl TestingMaspClient {
    /// Create a new [`TestingMaspClient`] given an rpc client
    /// [`TestingClient`].
    pub fn new(
        last_height: BlockHeight,
    ) -> (Self, flume::Sender<Option<IndexedNoteEntry>>) {
        let (sender, tx_recv) = flume::unbounded();
        (
            Self {
                last_height,
                tx_recv,
            },
            sender,
        )
    }
}

#[derive(Error, Debug)]
pub enum TestError {
    /// Key Retrieval Errors
    #[error("After retrying, could not fetch all MASP txs.")]
    FetchFailure,
}

impl MaspClient for TestingMaspClient {
    type Error = TestError;

    fn hint(&mut self, _from: BlockHeight, _to: BlockHeight) {}

    async fn last_block_height(
        &self,
    ) -> Result<Option<BlockHeight>, Self::Error> {
        Ok(Some(self.last_height))
    }

    async fn fetch_shielded_transfers(
        &self,
        from: BlockHeight,
        to: BlockHeight,
    ) -> Result<Vec<IndexedNoteEntry>, Self::Error> {
        let mut txs = vec![];

        for _height in from.0..=to.0 {
            if let Some(tx) = self.tx_recv.recv_async().await.unwrap() {
                txs.push(tx);
            } else {
                return Err(TestError::FetchFailure);
            }
        }

        Ok(txs)
    }

    #[inline(always)]
    fn capabilities(&self) -> MaspClientCapabilities {
        MaspClientCapabilities::NONE
    }

    async fn fetch_commitment_tree(
        &self,
        _: BlockHeight,
    ) -> Result<CommitmentTree<Node>, Self::Error> {
        unimplemented!(
            "Commitment tree fetching is not implemented by this client"
        )
    }

    async fn fetch_note_index(
        &self,
        _: BlockHeight,
    ) -> Result<BTreeMap<MaspIndexedTx, NotePosition>, Self::Error> {
        unimplemented!(
            "Transaction notes map fetching is not implemented by this client"
        )
    }

    async fn fetch_witness_map(
        &self,
        _: BlockHeight,
    ) -> Result<HashMap<NotePosition, IncrementalWitness<Node>>, Self::Error>
    {
        unimplemented!("Witness map fetching is not implemented by this client")
    }

    async fn commitment_anchor_exists(
        &self,
        _: &Node,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// A shielded context for testing
#[derive(Debug)]
pub struct TestingContext<U: ShieldedUtils + MaybeSend + MaybeSync> {
    wallet: ShieldedWallet<U>,
}

impl<U: ShieldedUtils + MaybeSend + MaybeSync> TestingContext<U> {
    pub fn new(wallet: ShieldedWallet<U>) -> Self {
        Self { wallet }
    }

    pub fn add_asset_type(&mut self, asset_data: AssetData) {
        self.asset_types
            .insert(asset_data.encode().unwrap(), asset_data);
    }

    /// Add a note to a given viewing key
    pub fn add_note(&mut self, note: CompactNote, vk: ViewingKey) {
        let next_note_idx = self
            .wallet
            .note_map
            .keys()
            .max()
            .map(|ix| ix.checked_add(1).unwrap())
            .unwrap_or_default();
        self.wallet.note_map.insert(next_note_idx, note);
        let avail_notes = self.wallet.pos_map.entry(vk).or_default();
        avail_notes.insert(next_note_idx);
    }

    pub fn spend_note(&mut self, note: &CompactNote) {
        let other = note.into_note().unwrap();
        let idx = self
            .wallet
            .note_map
            .iter()
            .find(|(_, compact_note)| {
                compact_note.into_note().unwrap() == other
            })
            .map(|(idx, _)| idx)
            .expect("Could find the note to spend in the note map");
        self.wallet.spents.insert(*idx);
    }
}

impl<U: ShieldedUtils + MaybeSend + MaybeSync> std::ops::Deref
    for TestingContext<U>
{
    type Target = ShieldedWallet<U>;

    fn deref(&self) -> &Self::Target {
        &self.wallet
    }
}

impl<U: ShieldedUtils + MaybeSend + MaybeSync> std::ops::DerefMut
    for TestingContext<U>
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.wallet
    }
}

impl<U: ShieldedUtils + MaybeSync + MaybeSend> ShieldedQueries<U>
    for TestingContext<U>
{
    async fn query_native_token<C: Client + MaybeSync>(
        _: &C,
    ) -> Result<Address, eyre::Error> {
        Ok(Address::Established([0u8; 20].into()))
    }

    async fn query_denom<C: Client + Sync>(
        client: &C,
        token: &Address,
    ) -> Option<Denomination> {
        Some(
            if *token
                == Self::query_native_token(client).await.expect("Infallible")
            {
                Denomination(6)
            } else {
                Denomination(0)
            },
        )
    }

    async fn query_conversion<C: Client + Sync>(
        client: &C,
        asset_type: AssetType,
    ) -> Option<ConversionResp> {
        let resp = client
            .request(asset_type.to_string(), None, None, false)
            .await
            .ok()?;
        BorshDeserialize::try_from_slice(&resp.data).unwrap()
    }

    async fn query_block<C: Client + Sync>(
        _: &C,
    ) -> Result<Option<u64>, eyre::Error> {
        unimplemented!()
    }

    async fn query_max_block_time_estimate<C: Client + Sync>(
        _: &C,
    ) -> Result<DurationSecs, eyre::Error> {
        unimplemented!()
    }

    async fn query_masp_epoch<C: Client + MaybeSync>(
        client: &C,
    ) -> Result<MaspEpoch, eyre::Error> {
        let resp = client
            .request("".to_string(), None, None, false)
            .await
            .map_err(|e| eyre!("{}", e))?;
        BorshDeserialize::try_from_slice(&resp.data).map_err(|e| eyre!("{}", e))
    }
}

pub type ConversionResp = (
    Address,
    Denomination,
    MaspDigitPos,
    MaspEpoch,
    I128Sum,
    MerklePath<Node>,
);

/// A mock client for making "queries" on behalf
/// of a `TestingContext`
pub struct MockClient {
    channel: Arc<Mutex<UnboundedReceiver<Vec<u8>>>>,
    pub conversions: HashMap<AssetType, ConversionResp>,
}

impl MockClient {
    pub fn new() -> (UnboundedSender<Vec<u8>>, Self) {
        let (send, recv) = tokio::sync::mpsc::unbounded_channel();
        (
            send,
            Self {
                channel: Arc::new(Mutex::new(recv)),
                conversions: Default::default(),
            },
        )
    }
}

#[cfg(test)]
#[cfg_attr(feature = "async-send", async_trait::async_trait)]
#[cfg_attr(not(feature = "async-send"), async_trait::async_trait(?Send))]
impl Client for MockClient {
    type Error = eyre::Error;

    async fn request(
        &self,
        req: String,
        _: Option<Vec<u8>>,
        _: Option<BlockHeight>,
        _: bool,
    ) -> Result<EncodedResponseQuery, Self::Error> {
        let resp = if let Ok(asset_type) = AssetType::from_str(&req) {
            self.conversions.get(&asset_type).serialize_to_vec()
        } else {
            let mut locked = self.channel.lock().await;
            locked
                .recv()
                .await
                .ok_or_else(|| eyre!("Client did not respond"))?
        };
        Ok(EncodedResponseQuery {
            data: resp,
            info: "".to_string(),
            proof: None,
            height: Default::default(),
        })
    }

    async fn perform<R>(
        &self,
        _: R,
    ) -> Result<R::Output, tendermint_rpc::error::Error>
    where
        R: tendermint_rpc::request::SimpleRequest,
    {
        unimplemented!()
    }
}

pub struct MockNamadaIo {
    client: MockClient,
    io: NullIo,
}

impl MockNamadaIo {
    pub fn new() -> (UnboundedSender<Vec<u8>>, Self) {
        let (send, client) = MockClient::new();
        (send, Self { client, io: NullIo })
    }

    pub fn add_conversions(
        &mut self,
        asset_data: AssetData,
        conv: ConversionResp,
    ) {
        self.client
            .conversions
            .insert(asset_data.encode().unwrap(), conv);
    }
}

impl NamadaIo for MockNamadaIo {
    type Client = MockClient;
    type Io = NullIo;

    fn client(&self) -> &Self::Client {
        &self.client
    }

    fn io(&self) -> &Self::Io {
        &self.io
    }
}

pub fn create_note(
    asset_data: AssetData,
    value: u64,
    pa: PaymentAddress,
) -> CompactNote {
    let payment_addr: masp_primitives::sapling::PaymentAddress = pa.into();
    CompactNote {
        value,
        diversifier: *payment_addr.diversifier(),
        pk_d: *payment_addr.pk_d(),
        asset_type: asset_data.encode().unwrap(),
        rseed: Rseed::AfterZip212([0; 32]),
    }
}
