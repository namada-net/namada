//! A basic fungible token

use std::cmp::Ordering;
use std::fmt::Display;
use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use data_encoding::BASE32HEX_NOPAD;
use ethabi::ethereum_types::U256;
use ibc::apps::transfer::types::Amount as IbcAmount;
use namada_macros::BorshDeserializer;
#[cfg(feature = "migrations")]
use namada_migrations::*;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::arith::{self, CheckedAdd, CheckedSub, One, Zero, checked};
use crate::dec::{Dec, POS_DECIMAL_PRECISION};
use crate::storage;
use crate::storage::{DbKeySeg, KeySeg};
use crate::uint::{self, I256, Uint};

/// Amount in micro units. For different granularity another representation
/// might be more appropriate.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    Clone,
    Copy,
    Default,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Debug,
    Hash,
)]
pub struct Amount {
    raw: Uint,
}

/// Maximum decimal places in a native token [`Amount`] and [`Change`].
/// For non-native (e.g. ERC20 tokens) one must read the `denom_key` storage
/// key.
pub const NATIVE_MAX_DECIMAL_PLACES: u8 = 6;

/// Decimal scale of a native token [`Amount`] and [`Change`].
/// For non-native (e.g. ERC20 tokens) one must read the `denom_key` storage
/// key.
pub const NATIVE_SCALE: u64 = 1_000_000;

/// A change in tokens amount
pub type Change = I256;

impl Amount {
    /// Iterate over all words in this [`Amount`].
    pub fn iter_words(self) -> impl Iterator<Item = u64> {
        self.raw.0.into_iter()
    }

    /// Convert a [`u64`] to an [`Amount`].
    pub const fn from_u64(x: u64) -> Self {
        Self {
            raw: Uint::from_u64(x),
        }
    }

    /// Convert a [`u128`] to an [`Amount`].
    pub const fn from_u128(value: u128) -> Self {
        let mut ret = [0; 4];
        #[allow(clippy::cast_possible_truncation)]
        {
            ret[0] = value as u64;
        }
        ret[1] = (value >> 64) as u64;
        Self { raw: Uint(ret) }
    }

    /// Get the amount as a [`Change`]
    pub fn change(&self) -> Change {
        self.raw.try_into().unwrap()
    }

    /// Spend a given amount.
    pub fn spend(&mut self, amount: &Amount) -> Result<(), AmountError> {
        self.raw = self
            .raw
            .checked_sub(amount.raw)
            .ok_or(AmountError::Insufficient)?;
        Ok(())
    }

    /// Check if there are enough funds.
    pub fn can_spend(&self, amount: &Amount) -> bool {
        self.raw >= amount.raw
    }

    /// Receive a given amount.
    pub fn receive(&mut self, amount: &Amount) -> Result<(), AmountError> {
        self.raw = self
            .raw
            .checked_add(amount.raw)
            .ok_or(AmountError::Overflow)?;
        Ok(())
    }

    /// Create a new amount of native token from whole number of tokens
    pub fn native_whole(amount: u64) -> Self {
        let raw = Uint::from(amount)
            .checked_mul(Uint::from(NATIVE_SCALE))
            .expect("u64 cannot overflow token amount");
        Self { raw }
    }

    /// Get the raw [`Uint`] value, which represents namnam
    pub fn raw_amount(&self) -> Uint {
        self.raw
    }

    /// Create a new amount with the maximum value
    pub fn max() -> Self {
        Self {
            raw: uint::MAX_VALUE,
        }
    }

    /// Create a new amount with the maximum signed value
    pub fn max_signed() -> Self {
        Self {
            raw: uint::MAX_SIGNED_VALUE,
        }
    }

    /// Zero [`Amount`].
    pub fn zero() -> Self {
        Self::default()
    }

    /// Check if [`Amount`] is zero.
    pub fn is_zero(&self) -> bool {
        self.raw == Uint::from(0)
    }

    /// Check if [`Amount`] is greater than zero.
    pub fn is_positive(&self) -> bool {
        !self.is_zero()
    }

    /// Checked addition. Returns `None` on overflow or if
    /// the amount exceed [`uint::MAX_VALUE`]
    #[must_use]
    pub fn checked_add(&self, amount: Amount) -> Option<Self> {
        self.raw.checked_add(amount.raw).and_then(|result| {
            if result <= uint::MAX_VALUE {
                Some(Self { raw: result })
            } else {
                None
            }
        })
    }

    /// Checked addition. Returns `None` on overflow or if
    /// the amount exceed [`uint::MAX_SIGNED_VALUE`]
    #[must_use]
    pub fn checked_signed_add(&self, amount: Amount) -> Option<Self> {
        self.raw.checked_add(amount.raw).and_then(|result| {
            if result <= uint::MAX_SIGNED_VALUE {
                Some(Self { raw: result })
            } else {
                None
            }
        })
    }

    /// Checked subtraction. Returns `None` on underflow.
    #[must_use]
    pub fn checked_sub(&self, amount: Amount) -> Option<Self> {
        self.raw
            .checked_sub(amount.raw)
            .map(|result| Self { raw: result })
    }

    /// Create amount from the absolute value of `Change`.
    pub fn from_change(change: Change) -> Self {
        Self { raw: change.abs() }
    }

    /// Checked division. Returns `None` on underflow.
    #[must_use]
    pub fn checked_div(&self, amount: Amount) -> Option<Self> {
        self.raw
            .checked_div(amount.raw)
            .map(|result| Self { raw: result })
    }

    /// Checked multiplication. Returns `None` on overflow.
    #[must_use]
    pub fn checked_mul<T>(&self, amount: T) -> Option<Self>
    where
        T: Into<Self>,
    {
        self.raw
            .checked_mul(amount.into().raw)
            .map(|result| Self { raw: result })
    }

    /// Given a string and a denomination, parse an amount from string.
    pub fn from_str(
        string: impl AsRef<str>,
        denom: impl Into<u8>,
    ) -> Result<Amount, AmountParseError> {
        DenominatedAmount::from_str(string.as_ref())?.scale(denom)
    }

    /// Attempt to convert an unsigned integer to an `Amount` with the
    /// specified precision.
    pub fn from_uint(
        uint: impl Into<Uint>,
        denom: impl Into<u8>,
    ) -> Result<Self, AmountParseError> {
        let denom = denom.into();
        let uint = uint.into();
        if denom == 0 {
            return Ok(uint.into());
        }
        match Uint::from(10)
            .checked_pow(Uint::from(denom))
            .and_then(|scaling| scaling.checked_mul(uint))
        {
            Some(amount) => Ok(Self { raw: amount }),
            None => Err(AmountParseError::ConvertToDecimal),
        }
    }

    /// Given a u64 and [`MaspDigitPos`], construct the corresponding
    /// amount.
    pub fn from_masp_denominated(val: u64, denom: MaspDigitPos) -> Self {
        let mut raw = [0u64; 4];
        raw[denom as usize] = val;
        Self { raw: Uint(raw) }
    }

    /// Given a i128 and [`MaspDigitPos`], construct the corresponding
    /// amount.
    pub fn from_masp_denominated_i128(
        val: i128,
        denom: MaspDigitPos,
    ) -> Option<Self> {
        #[allow(clippy::cast_sign_loss)]
        #[allow(clippy::cast_possible_truncation)]
        let lo = val as u64;
        #[allow(clippy::cast_sign_loss)]
        let hi = (val >> 64) as u64;
        let lo_pos = denom as usize;
        let hi_pos = lo_pos.checked_add(1)?;
        let mut raw = [0u64; 4];
        raw[lo_pos] = lo;
        if hi != 0 && hi_pos >= 4 {
            return None;
        } else if hi != 0 {
            raw[hi_pos] = hi;
        }
        Some(Self { raw: Uint(raw) })
    }

    /// Get a string representation of a native token amount.
    pub fn to_string_native(&self) -> String {
        DenominatedAmount {
            amount: *self,
            denom: NATIVE_MAX_DECIMAL_PLACES.into(),
        }
        .to_string_precise()
    }

    /// Return a denominated native token amount.
    #[inline]
    pub const fn native_denominated(self) -> DenominatedAmount {
        DenominatedAmount::native(self)
    }

    /// Convert to an [`Amount`] under the assumption that the input
    /// string encodes all necessary decimal places.
    pub fn from_string_precise(string: &str) -> Result<Self, AmountParseError> {
        DenominatedAmount::from_str(string).map(|den| den.amount)
    }

    /// Multiply by a decimal [`Dec`] with the result rounded up. Returns an
    /// error if the dec is negative. Checks for overflow.
    pub fn mul_ceil(&self, dec: Dec) -> Result<Self, arith::Error> {
        // Fails if the dec negative
        let _ = checked!(Dec(I256::maximum()) - dec)?;

        let tot = checked!(self.raw * dec.abs())?;
        let denom = Uint::from(10u64.pow(u32::from(POS_DECIMAL_PRECISION)));
        let floor_div = checked!(tot / denom)?;
        let rem = checked!(tot % denom)?;
        // dbg!(tot, denom, floor_div, rem);
        let raw = if !rem.is_zero() {
            checked!(floor_div + Uint::one())?
        } else {
            floor_div
        };
        Ok(Self { raw })
    }

    /// Multiply by a decimal [`Dec`] with the result rounded down. Returns an
    /// error if the dec is negative. Checks for overflow.
    pub fn mul_floor(&self, dec: Dec) -> Result<Self, arith::Error> {
        // Fails if the dec negative
        let _ = checked!(Dec(I256::maximum()) - dec)?;

        let raw = checked!(
            (Uint::from(*self) * dec.0.abs())
                / Uint::from(10u64.pow(u32::from(POS_DECIMAL_PRECISION)))
        )?;
        Ok(Self { raw })
    }

    /// Sum with overflow check
    pub fn sum<I: Iterator<Item = Self>>(mut iter: I) -> Option<Self> {
        iter.try_fold(Amount::zero(), |acc, amt| acc.checked_add(amt))
    }

    /// Divide by `u64` with zero divisor and overflow check.
    pub fn checked_div_u64(self, rhs: u64) -> Option<Self> {
        if rhs == 0 {
            return None;
        }
        let raw = self.raw.checked_div(Uint::from(rhs))?;
        Some(Self { raw })
    }

    /// A combination of Euclidean division and fractions:
    /// x*(a,b) = (a*(x//b), x%b).
    pub fn u128_eucl_div_rem(
        mut self,
        (a, b): (u128, u128),
    ) -> Option<(Amount, Amount)> {
        let a = Uint::from(a);
        let b = Uint::from(b);
        let raw = (self.raw.checked_div(b))?.checked_mul(a)?;
        let amt = Amount { raw };
        self.raw = self.raw.checked_rem(b)?;
        Some((amt, self))
    }
}

impl Zero for Amount {
    fn zero() -> Self {
        Self { raw: uint::ZERO }
    }

    fn is_zero(&self) -> bool {
        self.raw == uint::ZERO
    }
}

impl One for Amount {
    fn one() -> Self {
        Self { raw: uint::ONE }
    }

    fn is_one(&self) -> bool {
        self.raw == uint::ONE
    }
}

impl CheckedAdd for Amount {
    type Output = Amount;

    fn checked_add(self, rhs: Self) -> Option<Self::Output> {
        Amount::checked_add(&self, rhs)
    }
}

impl CheckedAdd for &Amount {
    type Output = Amount;

    fn checked_add(self, rhs: Self) -> Option<Self::Output> {
        self.checked_add(*rhs)
    }
}

impl CheckedSub for Amount {
    type Output = Amount;

    fn checked_sub(self, amount: Self) -> Option<Self::Output> {
        self.raw
            .checked_sub(amount.raw)
            .map(|result| Self { raw: result })
    }
}

impl CheckedSub for &Amount {
    type Output = Amount;

    fn checked_sub(self, amount: Self) -> Option<Self::Output> {
        self.raw
            .checked_sub(amount.raw)
            .map(|result| Amount { raw: result })
    }
}

impl Display for Amount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.raw)
    }
}

/// Given a number represented as `M*B^D`, then
/// `M` is the matissa, `B` is the base and `D`
/// is the denomination, represented by this struct.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    Debug,
    Copy,
    Clone,
    Hash,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
    Serialize,
    Deserialize,
)]
#[serde(transparent)]
pub struct Denomination(pub u8);

impl From<u8> for Denomination {
    fn from(denom: u8) -> Self {
        Self(denom)
    }
}

impl From<Denomination> for u8 {
    fn from(denom: Denomination) -> Self {
        denom.0
    }
}

/// An amount with its denomination.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    Debug,
    Copy,
    Clone,
    Hash,
    PartialEq,
    Eq,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
)]
pub struct DenominatedAmount {
    /// The mantissa
    amount: Amount,
    /// The number of decimal places in base ten.
    denom: Denomination,
}

impl DenominatedAmount {
    /// Make a new denominated amount representing amount*10^(-denom)
    pub const fn new(amount: Amount, denom: Denomination) -> Self {
        Self { amount, denom }
    }

    /// Return a denominated native token amount.
    pub const fn native(amount: Amount) -> Self {
        Self {
            amount,
            denom: Denomination(NATIVE_MAX_DECIMAL_PLACES),
        }
    }

    /// Check if the inner [`Amount`] is zero.
    #[inline]
    pub fn is_zero(&self) -> bool {
        self.amount.is_zero()
    }

    /// A precise string representation. The number of
    /// decimal places in this string gives the denomination.
    /// This not true of the string produced by the `Display`
    /// trait.
    pub fn to_string_precise(&self) -> String {
        let decimals = self.denom.0 as usize;
        let mut string = self.amount.raw.to_string();
        // escape hatch if there are no decimal places
        if decimals == 0 {
            return string;
        }
        if string.len() > decimals {
            // Cannot underflow cause `string.len` > `decimals`
            #[allow(clippy::arithmetic_side_effects)]
            let idx = string.len() - decimals;
            string.insert(idx, '.');
        } else {
            for _ in string.len()..decimals {
                string.insert(0, '0');
            }
            string.insert(0, '.');
            string.insert(0, '0');
        }
        string
    }

    /// Find the minimal precision that holds this value losslessly.
    /// This equates to stripping trailing zeros after the decimal
    /// place.
    pub fn canonical(self) -> Self {
        let mut value = self.amount.raw;
        let ten = Uint::from(10);
        let mut denom = self.denom.0;
        for _ in 0..self.denom.0 {
            let (div, rem) = value.div_mod(ten);
            if rem == Uint::zero() {
                value = div;
                denom = denom.checked_sub(1).unwrap_or_default();
            }
        }
        Self {
            amount: Amount { raw: value },
            denom: denom.into(),
        }
    }

    /// Return an equivalent denominated amount with the given denomination. Can
    /// fail if the resulting amount does not fit into 256 bits.
    pub fn increase_precision(
        self,
        denom: Denomination,
    ) -> Result<Self, AmountParseError> {
        if denom.0 < self.denom.0 {
            return Err(AmountParseError::PrecisionDecrease);
        }
        // Cannot underflow cause `denom` >= `self.denom`
        #[allow(clippy::arithmetic_side_effects)]
        let denom_diff = denom.0 - self.denom.0;
        Uint::from(10)
            .checked_pow(Uint::from(denom_diff))
            .and_then(|scaling| self.amount.raw.checked_mul(scaling))
            .map(|amount| Self {
                amount: Amount { raw: amount },
                denom,
            })
            .ok_or(AmountParseError::PrecisionOverflow)
    }

    /// Return the closest denominated amount with the given denomination and
    /// the error.
    pub fn approximate(
        self,
        denom: Denomination,
    ) -> Result<(Self, Self), AmountParseError> {
        if denom.0 < self.denom.0 {
            // Divide numerator and denominator by a power of 10
            let amount = self.amount.raw_amount();
            #[allow(clippy::arithmetic_side_effects)]
            let (quot, rem) = Uint::from(10)
                .checked_pow(Uint::from(self.denom.0 - denom.0))
                .and_then(|scaling| {
                    amount.checked_div(scaling).zip(amount.checked_rem(scaling))
                })
                .ok_or(AmountParseError::PrecisionOverflow)?;
            let approx = Self {
                amount: quot.into(),
                denom,
            };
            let error = Self {
                amount: rem.into(),
                denom: self.denom,
            };
            Ok((approx, error))
        } else {
            // Multiply numerator and denominator by a power of 10
            let error = Self {
                amount: 0.into(),
                denom: self.denom,
            };
            self.increase_precision(denom).map(|x| (x, error))
        }
    }

    /// Create a new [`DenominatedAmount`] with the same underlying
    /// amount but a new denomination.
    pub fn redenominate(self, new_denom: u8) -> Self {
        Self {
            amount: self.amount,
            denom: new_denom.into(),
        }
    }

    /// Multiply this number by 10^denom and return the computed integer if
    /// possible. Otherwise error out.
    pub fn scale(
        self,
        denom: impl Into<u8>,
    ) -> Result<Amount, AmountParseError> {
        self.increase_precision(Denomination(denom.into()))
            .map(|x| x.amount)
    }

    /// Checked multiplication. Returns `None` on overflow.
    pub fn checked_mul(&self, rhs: DenominatedAmount) -> Option<Self> {
        let amount = self.amount.checked_mul(rhs.amount)?;
        let denom = self.denom.0.checked_add(rhs.denom.0)?.into();
        Some(Self { amount, denom })
    }

    /// Checked subtraction. Returns `None` on overflow.
    pub fn checked_sub(&self, mut rhs: DenominatedAmount) -> Option<Self> {
        let mut lhs = *self;
        if lhs.denom < rhs.denom {
            lhs = lhs.increase_precision(rhs.denom).ok()?;
        } else {
            rhs = rhs.increase_precision(lhs.denom).ok()?;
        }
        let amount = lhs.amount.checked_sub(rhs.amount)?;
        Some(Self {
            amount,
            denom: lhs.denom,
        })
    }

    /// Checked addition. Returns `None` on overflow.
    pub fn checked_add(&self, mut rhs: DenominatedAmount) -> Option<Self> {
        let mut lhs = *self;
        if lhs.denom < rhs.denom {
            lhs = lhs.increase_precision(rhs.denom).ok()?;
        } else {
            rhs = rhs.increase_precision(lhs.denom).ok()?;
        }
        let amount = lhs.amount.checked_add(rhs.amount)?;
        Some(Self {
            amount,
            denom: lhs.denom,
        })
    }

    /// Checked division computed to the given precision. Returns `None` on
    /// overflow.
    pub fn checked_div_precision(
        &self,
        rhs: DenominatedAmount,
        denom: Denomination,
    ) -> Option<Self> {
        #[allow(clippy::arithmetic_side_effects)]
        let pow = i16::from(rhs.denom.0) + i16::from(denom.0)
            - i16::from(self.denom.0);
        if pow < 0 {
            return None;
        }
        let amount = Uint::from(10).checked_pow(Uint::from(pow)).and_then(
            |scaling| {
                scaling.checked_mul_div(
                    self.amount.raw_amount(),
                    rhs.amount.raw_amount(),
                )
            },
        )?;
        Some(Self {
            amount: amount.0.into(),
            denom,
        })
    }

    /// Checked division. Returns `None` on overflow.
    pub fn checked_div(&self, rhs: DenominatedAmount) -> Option<Self> {
        self.checked_div_precision(rhs, self.denom)
    }

    /// Returns the significand of this number
    pub const fn amount(&self) -> Amount {
        self.amount
    }

    /// Returns the denomination of this number
    pub const fn denom(&self) -> Denomination {
        self.denom
    }
}

impl Display for DenominatedAmount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let string = self.to_string_precise();
        let string = if self.denom.0 > 0 {
            string.trim_end_matches(['0'])
        } else {
            &string
        };
        let string = string.trim_end_matches(['.']);
        f.write_str(string)
    }
}

impl FromStr for DenominatedAmount {
    type Err = AmountParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let precision = s.find('.').map(|pos| {
            s.len()
                .checked_sub(pos.checked_add(1).unwrap_or(pos))
                .unwrap_or_default()
        });
        let digits = s
            .chars()
            .filter_map(|c| {
                if c.is_numeric() {
                    c.to_digit(10).map(Uint::from)
                } else {
                    None
                }
            })
            .rev()
            .collect::<Vec<_>>();
        if digits.len() != s.len() && precision.is_none()
            || digits.len() != s.len().checked_sub(1).unwrap_or_default()
                && precision.is_some()
        {
            return Err(AmountParseError::NotNumeric);
        }
        if digits.len() > 77 {
            return Err(AmountParseError::ScaleTooLarge(digits.len(), 77));
        }
        let mut value = Uint::default();
        let ten = Uint::from(10);
        for (pow, digit) in digits.into_iter().enumerate() {
            value = ten
                .checked_pow(Uint::from(pow))
                .and_then(|scaling| scaling.checked_mul(digit))
                .and_then(|scaled| value.checked_add(scaled))
                .ok_or(AmountParseError::InvalidRange)?;
        }
        let denom = Denomination(
            u8::try_from(precision.unwrap_or_default())
                .map_err(|_e| AmountParseError::PrecisionOverflow)?,
        );
        Ok(Self {
            amount: Amount { raw: value },
            denom,
        })
    }
}

impl PartialOrd for DenominatedAmount {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for DenominatedAmount {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.amount.is_zero() && other.is_zero() {
            Ordering::Equal
        } else if self.amount.is_zero() {
            Ordering::Less
        } else if other.amount.is_zero() {
            Ordering::Greater
        } else if self.denom < other.denom {
            // Cannot underflow cause `self.denom` < `other.denom`
            #[allow(clippy::arithmetic_side_effects)]
            let diff = other.denom.0 - self.denom.0;
            if diff > 77 {
                // This branch catches case where exponentiation overflows
                return Ordering::Greater;
            }
            let (div, rem) =
                other.amount.raw.div_mod(Uint::exp10(diff as usize));
            let div_ceil = if rem.is_zero() {
                div
            } else {
                div.checked_add(Uint::one()).unwrap_or(Uint::MAX)
            };
            let ord = self.amount.raw.cmp(&div_ceil);
            if let Ordering::Equal = ord {
                if rem.is_zero() {
                    Ordering::Equal
                } else {
                    Ordering::Greater
                }
            } else {
                ord
            }
        } else {
            // Cannot underflow cause `other.denom` >= `self.denom`
            #[allow(clippy::arithmetic_side_effects)]
            let diff = self.denom.0 - other.denom.0;
            if diff > 77 {
                // This branch catches case where exponentiation overflows
                return Ordering::Less;
            }
            let (div, rem) =
                self.amount.raw.div_mod(Uint::exp10(diff as usize));
            let div_ceil = if rem.is_zero() {
                div
            } else {
                div.checked_add(Uint::one()).unwrap_or(Uint::MAX)
            };
            let ord = div_ceil.cmp(&other.amount.raw);
            if let Ordering::Equal = ord {
                if rem.is_zero() {
                    Ordering::Equal
                } else {
                    Ordering::Less
                }
            } else {
                ord
            }
        }
    }
}

impl serde::Serialize for Amount {
    fn serialize<S>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let amount_string = self.raw.to_string();
        serde::Serialize::serialize(&amount_string, serializer)
    }
}

impl<'de> serde::Deserialize<'de> for Amount {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let amount_string: String =
            serde::Deserialize::deserialize(deserializer)?;
        let amt = DenominatedAmount::from_str(&amount_string).unwrap();
        Ok(amt.amount)
    }
}

impl serde::Serialize for DenominatedAmount {
    fn serialize<S>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let amount_string = self.to_string_precise();
        serde::Serialize::serialize(&amount_string, serializer)
    }
}

impl<'de> serde::Deserialize<'de> for DenominatedAmount {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;
        let amount_string: String =
            serde::Deserialize::deserialize(deserializer)?;
        Self::from_str(&amount_string).map_err(D::Error::custom)
    }
}

impl From<Amount> for DenominatedAmount {
    fn from(amount: Amount) -> Self {
        DenominatedAmount::new(amount, 0.into())
    }
}

// Treats the u64 as a value of the raw amount (namnam)
impl From<u64> for Amount {
    fn from(val: u64) -> Amount {
        Amount {
            raw: Uint::from(val),
        }
    }
}

impl From<Amount> for U256 {
    fn from(amt: Amount) -> Self {
        Self(amt.raw.0)
    }
}

impl TryFrom<Dec> for Amount {
    type Error = arith::Error;

    fn try_from(dec: Dec) -> Result<Amount, Self::Error> {
        // Fails if the dec negative
        let _ = checked!(Dec(I256::maximum()) - dec)?;

        // Division cannot panic as divisor is non-zero
        #[allow(clippy::arithmetic_side_effects)]
        let raw = dec.0.abs() / Uint::exp10(POS_DECIMAL_PRECISION as usize);
        Ok(Amount { raw })
    }
}

impl TryFrom<Amount> for u128 {
    type Error = std::io::Error;

    fn try_from(value: Amount) -> Result<Self, Self::Error> {
        let Uint(arr) = value.raw;
        for word in arr.iter().skip(2) {
            if *word != 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Integer overflow when casting to u128",
                ));
            }
        }
        Ok(value.raw.low_u128())
    }
}

impl KeySeg for Amount {
    fn parse(string: String) -> super::storage::Result<Self>
    where
        Self: Sized,
    {
        let bytes = BASE32HEX_NOPAD.decode(string.as_ref()).map_err(|err| {
            storage::Error::ParseKeySeg(format!(
                "Failed parsing {} with {}",
                string, err
            ))
        })?;
        Ok(Amount {
            raw: Uint::from_big_endian(&bytes),
        })
    }

    fn raw(&self) -> String {
        let buf = self.raw.to_big_endian();
        BASE32HEX_NOPAD.encode(&buf)
    }

    fn to_db_key(&self) -> DbKeySeg {
        DbKeySeg::StringSeg(self.raw())
    }
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum AmountParseError {
    #[error(
        "Error decoding token amount, too many decimal places: {0}. Maximum \
         {1}"
    )]
    ScaleTooLarge(usize, u8),
    #[error(
        "Error decoding token amount, the value is not within invalid range."
    )]
    InvalidRange,
    #[error("Error converting amount to decimal, number too large.")]
    ConvertToDecimal,
    #[error(
        "Could not convert from string, expected an unsigned 256-bit integer."
    )]
    FromString,
    #[error("Could not parse string as a correctly formatted number.")]
    NotNumeric,
    #[error("This amount cannot handle the requested precision in 256 bits.")]
    PrecisionOverflow,
    #[error("More precision given in the amount than requested.")]
    PrecisionDecrease,
}

impl From<Amount> for Change {
    fn from(amount: Amount) -> Self {
        amount.raw.try_into().unwrap()
    }
}

impl From<Change> for Amount {
    fn from(change: Change) -> Self {
        Amount { raw: change.abs() }
    }
}

impl From<Amount> for Uint {
    fn from(amount: Amount) -> Self {
        amount.raw
    }
}

impl From<Uint> for Amount {
    fn from(raw: Uint) -> Self {
        Self { raw }
    }
}

/// The four possible u64 words in a [`Uint`].
/// Used for converting to MASP amounts.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    Copy,
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
    Serialize,
    Deserialize,
)]
#[repr(u8)]
#[allow(missing_docs)]
#[borsh(use_discriminant = true)]
pub enum MaspDigitPos {
    Zero = 0,
    One,
    Two,
    Three,
}

impl TryFrom<u8> for MaspDigitPos {
    type Error = &'static str;

    fn try_from(denom: u8) -> Result<Self, Self::Error> {
        match denom {
            0 => Ok(Self::Zero),
            1 => Ok(Self::One),
            2 => Ok(Self::Two),
            3 => Ok(Self::Three),
            _ => Err("Possible MASP denominations must be between 0 and 3"),
        }
    }
}

impl MaspDigitPos {
    /// Iterator over the possible denominations
    pub fn iter() -> impl Iterator<Item = MaspDigitPos> {
        [
            MaspDigitPos::Zero,
            MaspDigitPos::One,
            MaspDigitPos::Two,
            MaspDigitPos::Three,
        ]
        .into_iter()
    }

    /// Get the corresponding u64 word from the input uint256.
    pub fn denominate<'a>(&self, amount: impl Into<&'a Amount>) -> u64 {
        let amount = amount.into();
        amount.raw.0[*self as usize]
    }
}

impl From<Amount> for IbcAmount {
    fn from(amount: Amount) -> Self {
        primitive_types::U256(amount.raw.0).into()
    }
}

impl From<IbcAmount> for Amount {
    fn from(amount: IbcAmount) -> Self {
        Uint(primitive_types::U256::from(amount).0).into()
    }
}

impl From<DenominatedAmount> for IbcAmount {
    fn from(amount: DenominatedAmount) -> Self {
        amount.amount.into()
    }
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum AmountError {
    #[error("Insufficient amount")]
    Insufficient,
    #[error("Amount overlofow")]
    Overflow,
}

#[cfg(any(test, feature = "testing"))]
/// Testing helpers and strategies for tokens
#[allow(clippy::arithmetic_side_effects)]
pub mod testing {
    use proptest::prelude::*;

    use super::*;

    impl std::ops::Add for Amount {
        type Output = Self;

        fn add(self, rhs: Self) -> Self::Output {
            self.checked_add(rhs).unwrap()
        }
    }

    impl std::ops::AddAssign for Amount {
        fn add_assign(&mut self, rhs: Self) {
            *self = self.checked_add(rhs).unwrap();
        }
    }

    impl std::ops::Sub for Amount {
        type Output = Self;

        fn sub(self, rhs: Self) -> Self::Output {
            self.checked_sub(rhs).unwrap()
        }
    }

    impl std::ops::SubAssign for Amount {
        fn sub_assign(&mut self, rhs: Self) {
            *self = *self - rhs;
        }
    }

    impl<T> std::ops::Mul<T> for Amount
    where
        T: Into<Self>,
    {
        type Output = Amount;

        fn mul(self, rhs: T) -> Self::Output {
            self.checked_mul(rhs.into()).unwrap()
        }
    }

    impl std::ops::Mul<Amount> for u64 {
        type Output = Amount;

        fn mul(self, rhs: Amount) -> Self::Output {
            rhs * self
        }
    }

    impl std::ops::Div<u64> for Amount {
        type Output = Self;

        fn div(self, rhs: u64) -> Self::Output {
            Self {
                raw: self.raw / Uint::from(rhs),
            }
        }
    }

    impl std::iter::Sum for Amount {
        fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
            iter.fold(Amount::zero(), |a, b| a + b)
        }
    }

    prop_compose! {
        /// Generate an arbitrary denomination
        pub fn arb_denomination()(denom in 0u8..) -> Denomination {
            Denomination(denom)
        }
    }

    prop_compose! {
        /// Generate a denominated amount
        pub fn arb_denominated_amount()(
            amount in arb_amount(),
            denom in arb_denomination(),
        ) -> DenominatedAmount {
            DenominatedAmount::new(amount, denom)
        }
    }

    /// Generate an arbitrary token amount
    pub fn arb_amount() -> impl Strategy<Value = Amount> {
        any::<u64>().prop_map(|val| Amount::from_uint(val, 0).unwrap())
    }

    /// Generate an arbitrary token amount up to and including given `max` value
    pub fn arb_amount_ceiled(max: u64) -> impl Strategy<Value = Amount> {
        (0..=max).prop_map(|val| Amount::from_uint(val, 0).unwrap())
    }

    /// Generate an arbitrary non-zero token amount up to and including given
    /// `max` value
    pub fn arb_amount_non_zero_ceiled(
        max: u64,
    ) -> impl Strategy<Value = Amount> {
        (1..=max).prop_map(|val| Amount::from_uint(val, 0).unwrap())
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;

    use super::*;

    #[test]
    fn test_token_display() {
        let max = Amount::from_uint(u64::MAX, 0).expect("Test failed");
        assert_eq!("18446744073709.551615", max.to_string_native());
        let max = DenominatedAmount {
            amount: max,
            denom: NATIVE_MAX_DECIMAL_PLACES.into(),
        };
        assert_eq!("18446744073709.551615", max.to_string());

        let whole =
            Amount::from_uint(u64::MAX / NATIVE_SCALE * NATIVE_SCALE, 0)
                .expect("Test failed");
        assert_eq!("18446744073709.000000", whole.to_string_native());
        let whole = DenominatedAmount {
            amount: whole,
            denom: NATIVE_MAX_DECIMAL_PLACES.into(),
        };
        assert_eq!("18446744073709", whole.to_string());

        let trailing_zeroes =
            Amount::from_uint(123000, 0).expect("Test failed");
        assert_eq!("0.123000", trailing_zeroes.to_string_native());
        let trailing_zeroes = DenominatedAmount {
            amount: trailing_zeroes,
            denom: NATIVE_MAX_DECIMAL_PLACES.into(),
        };
        assert_eq!("0.123", trailing_zeroes.to_string());

        let zero = Amount::default();
        assert_eq!("0.000000", zero.to_string_native());
        let zero = DenominatedAmount {
            amount: zero,
            denom: NATIVE_MAX_DECIMAL_PLACES.into(),
        };
        assert_eq!("0", zero.to_string());

        let amount = DenominatedAmount {
            amount: Amount::from_uint(1120, 0).expect("Test failed"),
            denom: 3u8.into(),
        };
        assert_eq!("1.12", amount.to_string());
        assert_eq!("1.120", amount.to_string_precise());

        let amount = DenominatedAmount {
            amount: Amount::from_uint(1120, 0).expect("Test failed"),
            denom: 5u8.into(),
        };
        assert_eq!("0.0112", amount.to_string());
        assert_eq!("0.01120", amount.to_string_precise());

        let amount = DenominatedAmount {
            amount: Amount::from_uint(200, 0).expect("Test failed"),
            denom: 0.into(),
        };
        assert_eq!("200", amount.to_string());
        assert_eq!("200", amount.to_string_precise());
    }

    #[test]
    fn test_amount_checked_sub() {
        let max = Amount::native_whole(u64::MAX);
        let one = Amount::native_whole(1);
        let zero = Amount::native_whole(0);

        assert_eq!(zero.checked_sub(zero), Some(zero));
        assert_eq!(zero.checked_sub(one), None);
        assert_eq!(zero.checked_sub(max), None);

        assert_eq!(max.checked_sub(zero), Some(max));
        assert_eq!(max.checked_sub(one), Some(max - one));
        assert_eq!(max.checked_sub(max), Some(zero));
    }

    #[test]
    fn test_serialization_round_trip() {
        let amount: Amount = serde_json::from_str(r#""1000000000""#).unwrap();
        assert_eq!(
            amount,
            Amount {
                raw: Uint::from(1000000000)
            }
        );
        let serialized = serde_json::to_string(&amount).unwrap();
        assert_eq!(serialized, r#""1000000000""#);
    }

    #[test]
    fn test_amount_checked_add() {
        let max = Amount::max();
        let max_signed = Amount::max_signed();
        let one = Amount::native_whole(1);
        let zero = Amount::native_whole(0);

        assert_eq!(zero.checked_add(zero), Some(zero));
        assert_eq!(zero.checked_signed_add(zero), Some(zero));
        assert_eq!(zero.checked_add(one), Some(one));
        assert_eq!(zero.checked_add(max - one), Some(max - one));
        assert_eq!(
            zero.checked_signed_add(max_signed - one),
            Some(max_signed - one)
        );
        assert_eq!(zero.checked_add(max), Some(max));
        assert_eq!(zero.checked_signed_add(max_signed), Some(max_signed));

        assert_eq!(max.checked_add(zero), Some(max));
        assert_eq!(max.checked_signed_add(zero), None);
        assert_eq!(max.checked_add(one), None);
        assert_eq!(max.checked_add(max), None);

        assert_eq!(max_signed.checked_add(zero), Some(max_signed));
        assert_eq!(max_signed.checked_add(one), Some(max_signed + one));
        assert_eq!(max_signed.checked_signed_add(max_signed), None);
    }

    #[test]
    fn test_amount_from_string() {
        assert!(Amount::from_str("1.12", 1).is_err());
        assert!(Amount::from_str("0.0", 0).is_err());
        assert!(Amount::from_str("1.12", 80).is_err());
        assert!(Amount::from_str("1.12.1", 3).is_err());
        assert!(Amount::from_str("1.1a", 3).is_err());
        assert_eq!(
            Amount::zero(),
            Amount::from_str("0.0", 1).expect("Test failed")
        );
        assert_eq!(
            Amount::zero(),
            Amount::from_str(".0", 1).expect("Test failed")
        );

        let amount = Amount::from_str("1.12", 3).expect("Test failed");
        assert_eq!(amount, Amount::from_uint(1120, 0).expect("Test failed"));
        let amount = Amount::from_str(".34", 3).expect("Test failed");
        assert_eq!(amount, Amount::from_uint(340, 0).expect("Test failed"));
        let amount = Amount::from_str("0.34", 3).expect("Test failed");
        assert_eq!(amount, Amount::from_uint(340, 0).expect("Test failed"));
        let amount = Amount::from_str("34", 1).expect("Test failed");
        assert_eq!(amount, Amount::from_uint(340, 0).expect("Test failed"));
    }

    #[test]
    fn test_from_masp_denominated() {
        let uint = Uint([15u64, 16, 17, 18]);
        let original = Amount::from_uint(uint, 0).expect("Test failed");
        for denom in MaspDigitPos::iter() {
            let word = denom.denominate(&original);
            assert_eq!(word, denom as u64 + 15u64);
            let amount = Amount::from_masp_denominated(word, denom);
            let raw = Uint::from(amount).0;
            let mut expected = [0u64; 4];
            expected[denom as usize] = word;
            assert_eq!(raw, expected);
        }
    }

    #[test]
    fn test_key_seg() {
        let original = Amount::from_uint(1234560000, 0).expect("Test failed");
        let key = original.raw();
        let amount = Amount::parse(key).expect("Test failed");
        assert_eq!(amount, original);
    }

    #[test]
    fn test_amount_is_zero() {
        let zero = Amount::zero();
        assert!(zero.is_zero());

        let non_zero = Amount::from_uint(1, 0).expect("Test failed");
        assert!(!non_zero.is_zero());
    }

    #[test]
    fn test_token_amount_mul_ceil() {
        let one = Amount::from(1);
        let two = Amount::from(2);
        let three = Amount::from(3);
        let dec = Dec::from_str("0.34").unwrap();
        assert_eq!(one.mul_ceil(dec).unwrap(), one);
        assert_eq!(two.mul_ceil(dec).unwrap(), one);
        assert_eq!(three.mul_ceil(dec).unwrap(), two);

        assert_matches!(one.mul_ceil(-dec), Err(_));
        assert_matches!(one.mul_ceil(-Dec::new(1, 12).unwrap()), Err(_));
        assert_matches!(
            Amount::native_whole(1).mul_ceil(-Dec::new(1, 12).unwrap()),
            Err(_)
        );
    }

    #[test]
    fn test_token_amount_mul_floor() {
        let zero = Amount::zero();
        let one = Amount::from(1);
        let two = Amount::from(2);
        let three = Amount::from(3);
        let dec = Dec::from_str("0.34").unwrap();
        assert_eq!(one.mul_floor(dec).unwrap(), zero);
        assert_eq!(two.mul_floor(dec).unwrap(), zero);
        assert_eq!(three.mul_floor(dec).unwrap(), one);

        assert_matches!(one.mul_floor(-dec), Err(_));
        assert_matches!(one.mul_floor(-Dec::new(1, 12).unwrap()), Err(_));
        assert_matches!(
            Amount::native_whole(1).mul_floor(-Dec::new(1, 12).unwrap()),
            Err(_)
        );
    }

    #[test]
    fn test_denominateed_arithmetic() {
        let a = DenominatedAmount::new(10.into(), 3.into());
        let b = DenominatedAmount::new(10.into(), 2.into());
        let c = DenominatedAmount::new(110.into(), 3.into());
        let d = DenominatedAmount::new(90.into(), 3.into());
        let e = DenominatedAmount::new(100.into(), 5.into());
        let f = DenominatedAmount::new(100.into(), 3.into());
        let g = DenominatedAmount::new(0.into(), 3.into());
        assert_eq!(a.checked_add(b).unwrap(), c);
        assert_eq!(b.checked_sub(a).unwrap(), d);
        assert_eq!(a.checked_mul(b).unwrap(), e);
        assert!(a.checked_sub(b).is_none());
        assert_eq!(c.checked_sub(a).unwrap(), f);
        assert_eq!(c.checked_sub(c).unwrap(), g);
    }

    #[test]
    fn test_denominated_amt_ord() {
        let denom_1 = DenominatedAmount {
            amount: Amount::from_uint(15, 0).expect("Test failed"),
            denom: 1.into(),
        };
        let denom_2 = DenominatedAmount {
            amount: Amount::from_uint(1500, 0).expect("Test failed"),
            denom: 3.into(),
        };
        // The psychedelic case. Partial ordering works on the underlying
        // amounts but `Eq` also checks the equality of denoms.
        assert_eq!(
            denom_1.partial_cmp(&denom_2).expect("Test failed"),
            Ordering::Equal
        );
        assert_eq!(
            denom_2.partial_cmp(&denom_1).expect("Test failed"),
            Ordering::Equal
        );
        assert_ne!(denom_1, denom_2);

        let denom_1 = DenominatedAmount {
            amount: Amount::from_uint(15, 0).expect("Test failed"),
            denom: 1.into(),
        };
        let denom_2 = DenominatedAmount {
            amount: Amount::from_uint(1501, 0).expect("Test failed"),
            denom: 3.into(),
        };
        assert_eq!(
            denom_1.partial_cmp(&denom_2).expect("Test failed"),
            Ordering::Less
        );
        assert_eq!(
            denom_2.partial_cmp(&denom_1).expect("Test failed"),
            Ordering::Greater
        );
        let denom_1 = DenominatedAmount {
            amount: Amount::from_uint(15, 0).expect("Test failed"),
            denom: 1.into(),
        };
        let denom_2 = DenominatedAmount {
            amount: Amount::from_uint(1499, 0).expect("Test failed"),
            denom: 3.into(),
        };
        assert_eq!(
            denom_1.partial_cmp(&denom_2).expect("Test failed"),
            Ordering::Greater
        );
        assert_eq!(
            denom_2.partial_cmp(&denom_1).expect("Test failed"),
            Ordering::Less
        );
    }

    #[test]
    fn test_token_amount_from_u128() {
        for val in [
            u128::MIN,
            u128::MIN + 1,
            u128::from(u64::MAX) - 1,
            u128::from(u64::MAX),
            u128::from(u64::MAX) + 1,
            u128::MAX - 1,
            u128::MAX,
        ] {
            let raw = Uint::from(val);
            let amount = Amount::from_u128(val);
            assert_eq!(raw, amount.raw);
            assert_eq!(amount.raw.as_u128(), val);
        }
    }
}
