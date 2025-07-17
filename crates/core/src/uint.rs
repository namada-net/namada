//! An unsigned 256 integer type. Used for, among other things,
//! the backing type of token amounts.

// Used in `construct_uint!`
#![allow(clippy::assign_op_pattern)]
// Missing in `construct_uint!`
#![allow(missing_docs)]
// Done in `construct_uint!`
#![allow(clippy::manual_div_ceil)]

use std::cmp::Ordering;
use std::fmt;
use std::ops::Not;
use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use impl_num_traits::impl_uint_num_traits;
use namada_macros::BorshDeserializer;
#[cfg(feature = "migrations")]
use namada_migrations::*;
use num_integer::Integer;
use uint::construct_uint;

use super::dec::{Dec, POS_DECIMAL_PRECISION};
use crate::arith::{
    self, CheckedAdd, CheckedNeg, CheckedSub, One, OverflowingAdd,
    OverflowingSub, Zero, checked,
};
use crate::token;
use crate::token::{AmountParseError, MaspDigitPos};

/// The value zero.
pub const ZERO: Uint = Uint::from_u64(0);

/// The value one.
pub const ONE: Uint = Uint::from_u64(1);

// Allowed because the value is a const `64`
#[allow(clippy::cast_possible_truncation)]
const UINT_U32_WORD_BITS: u32 = Uint::WORD_BITS as u32;

impl Uint {
    const N_WORDS: usize = 4;

    /// Convert a [`u64`] to a [`Uint`].
    pub const fn from_u64(x: u64) -> Uint {
        Uint([x.to_le(), 0, 0, 0])
    }

    /// Return the least number of bits needed to represent the number
    #[inline]
    #[allow(clippy::arithmetic_side_effects)]
    pub fn bits_512(arr: &[u64; 2 * Self::N_WORDS]) -> usize {
        for i in 1..arr.len() {
            if arr[arr.len() - i] > 0 {
                return (0x40 * (arr.len() - i + 1))
                    - arr[arr.len() - i].leading_zeros() as usize;
            }
        }
        0x40 - arr[0].leading_zeros() as usize
    }

    fn div_mod_small_512(
        mut slf: [u64; 2 * Self::N_WORDS],
        other: u64,
    ) -> ([u64; 2 * Self::N_WORDS], Self) {
        let mut rem = 0u64;
        slf.iter_mut().rev().for_each(|d| {
            let (q, r) = Self::div_mod_word(rem, *d, other);
            *d = q;
            rem = r;
        });
        (slf, rem.into())
    }

    #[allow(clippy::arithmetic_side_effects)]
    fn shr_512(
        original: [u64; 2 * Self::N_WORDS],
        shift: u32,
    ) -> [u64; 2 * Self::N_WORDS] {
        let shift = shift as usize;
        let mut ret = [0u64; 2 * Self::N_WORDS];
        let word_shift = shift / 64;
        let bit_shift = shift % 64;

        // shift
        for i in word_shift..original.len() {
            ret[i - word_shift] = original[i] >> bit_shift;
        }

        // Carry
        if bit_shift > 0 {
            for i in word_shift + 1..original.len() {
                ret[i - word_shift - 1] += original[i] << (64 - bit_shift);
            }
        }

        ret
    }

    #[allow(clippy::arithmetic_side_effects)]
    fn full_shl_512(
        slf: [u64; 2 * Self::N_WORDS],
        shift: u32,
    ) -> [u64; 2 * Self::N_WORDS + 1] {
        debug_assert!(shift < UINT_U32_WORD_BITS);
        let mut u = [0u64; 2 * Self::N_WORDS + 1];
        let u_lo = slf[0] << shift;
        let u_hi = Self::shr_512(slf, UINT_U32_WORD_BITS - shift);
        u[0] = u_lo;
        u[1..].copy_from_slice(&u_hi[..]);
        u
    }

    #[allow(clippy::arithmetic_side_effects)]
    fn full_shr_512(
        u: [u64; 2 * Self::N_WORDS + 1],
        shift: u32,
    ) -> [u64; 2 * Self::N_WORDS] {
        debug_assert!(shift < UINT_U32_WORD_BITS);
        let mut res = [0; 2 * Self::N_WORDS];
        for i in 0..res.len() {
            res[i] = u[i] >> shift;
        }
        // carry
        if shift > 0 {
            for i in 1..=res.len() {
                res[i - 1] |= u[i] << (UINT_U32_WORD_BITS - shift);
            }
        }
        res
    }

    // See Knuth, TAOCP, Volume 2, section 4.3.1, Algorithm D.
    #[allow(clippy::arithmetic_side_effects)]
    fn div_mod_knuth_512(
        slf: [u64; 2 * Self::N_WORDS],
        mut v: Self,
        n: usize,
        m: usize,
    ) -> ([u64; 2 * Self::N_WORDS], Self) {
        debug_assert!(Self::bits_512(&slf) >= v.bits() && !v.fits_word());
        debug_assert!(n + m <= slf.len());
        // D1.
        // Make sure 64th bit in v's highest word is set.
        // If we shift both self and v, it won't affect the quotient
        // and the remainder will only need to be shifted back.
        let shift = v.0[n - 1].leading_zeros();
        v <<= shift;
        // u will store the remainder (shifted)
        let mut u = Self::full_shl_512(slf, shift);

        // quotient
        let mut q = [0; 2 * Self::N_WORDS];
        let v_n_1 = v.0[n - 1];
        let v_n_2 = v.0[n - 2];

        // D2. D7.
        // iterate from m downto 0
        for j in (0..=m).rev() {
            let u_jn = u[j + n];

            // D3.
            // q_hat is our guess for the j-th quotient digit
            // q_hat = min(b - 1, (u_{j+n} * b + u_{j+n-1}) / v_{n-1})
            // b = 1 << WORD_BITS
            // Theorem B: q_hat >= q_j >= q_hat - 2
            let mut q_hat = if u_jn < v_n_1 {
                let (mut q_hat, mut r_hat) =
                    Self::div_mod_word(u_jn, u[j + n - 1], v_n_1);
                // this loop takes at most 2 iterations
                loop {
                    // check if q_hat * v_{n-2} > b * r_hat + u_{j+n-2}
                    let (hi, lo) =
                        Self::split_u128(u128::from(q_hat) * u128::from(v_n_2));
                    if (hi, lo) <= (r_hat, u[j + n - 2]) {
                        break;
                    }
                    // then iterate till it doesn't hold
                    q_hat -= 1;
                    let (new_r_hat, overflow) = r_hat.overflowing_add(v_n_1);
                    r_hat = new_r_hat;
                    // if r_hat overflowed, we're done
                    if overflow {
                        break;
                    }
                }
                q_hat
            } else {
                // here q_hat >= q_j >= q_hat - 1
                u64::MAX
            };

            // ex. 20:
            // since q_hat * v_{n-2} <= b * r_hat + u_{j+n-2},
            // either q_hat == q_j, or q_hat == q_j + 1

            // D4.
            // let's assume optimistically q_hat == q_j
            // subtract (q_hat * v) from u[j..]
            let q_hat_v = v.full_mul_u64(q_hat);
            // u[j..] -= q_hat_v;
            let c = Self::sub_slice(&mut u[j..], &q_hat_v[..n + 1]);

            // D6.
            // actually, q_hat == q_j + 1 and u[j..] has overflowed
            // highly unlikely ~ (1 / 2^63)
            if c {
                q_hat -= 1;
                // add v to u[j..]
                let c = Self::add_slice(&mut u[j..], &v.0[..n]);
                u[j + n] = u[j + n].wrapping_add(u64::from(c));
            }

            // D5.
            q[j] = q_hat;
        }

        // D8.
        let remainder = Self::full_shr_512(u, shift);
        // The remainder should never exceed the capacity of Self
        debug_assert!(
            Self::bits_512(&remainder) <= Self::N_WORDS * Self::WORD_BITS
        );
        (q, Self(remainder[..Self::N_WORDS].try_into().unwrap()))
    }

    /// Returns a pair `(self / other, self % other)`.
    pub fn div_mod_512(
        slf: [u64; 2 * Self::N_WORDS],
        other: Self,
    ) -> Option<([u64; 2 * Self::N_WORDS], Self)> {
        let my_bits = Self::bits_512(&slf);
        let your_bits = other.bits();

        assert!(your_bits != 0, "division by zero");

        // Early return in case we are dividing by a larger number than us
        if my_bits < your_bits {
            return Some((
                [0; 2 * Self::N_WORDS],
                Self(slf[..Self::N_WORDS].try_into().unwrap()),
            ));
        }

        if your_bits <= Self::WORD_BITS {
            return Some(Self::div_mod_small_512(slf, other.low_u64()));
        }

        let (n, m) = {
            let my_words = Self::words(my_bits);
            let your_words = Self::words(your_bits);
            (your_words, my_words.checked_sub(your_words)?)
        };

        Some(Self::div_mod_knuth_512(slf, other, n, m))
    }

    /// Returns a pair `(Some((self * num) / denom), (self * num) % denom)` if
    /// the quotient fits into Self. Otherwise `(None, (self * num) % denom)` is
    /// returned.
    pub fn checked_mul_div(
        &self,
        num: Self,
        denom: Self,
    ) -> Option<(Self, Self)> {
        if denom.is_zero() {
            None
        } else {
            let prod = uint::uint_full_mul_reg!(Uint, 4, self, num);
            let (quotient, remainder) = Self::div_mod_512(prod, denom)?;
            // The compiler WILL NOT inline this if you remove this annotation.
            #[inline(always)]
            fn any_nonzero(arr: &[u64]) -> bool {
                use uint::unroll;
                unroll! {
                    for i in 0..4 {
                        if arr[i] != 0 {
                            return true;
                        }
                    }
                }

                false
            }
            if any_nonzero(&quotient[Self::N_WORDS..]) {
                None
            } else {
                Some((
                    Self(quotient[0..Self::N_WORDS].try_into().unwrap()),
                    remainder,
                ))
            }
        }
    }

    /// Return the ceiling of the product of an integer and a fraction
    /// (represented as `num / denom`)
    pub fn frac_mul_ceil(
        &self,
        num: Self,
        denom: Self,
    ) -> Result<Self, arith::Error> {
        let val = checked!(self * num)?;
        let adj_den = checked!(denom - Uint::one())?;
        let val = checked!(val + adj_den)?;
        checked!(val / denom)
    }
}

construct_uint! {
    /// Namada native type to replace for unsigned 256 bit
    /// integers.
    #[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
    #[derive(
        BorshSerialize,
        BorshDeserialize,
        BorshDeserializer,
        BorshSchema,
    )]
    #[repr(align(32))]
    pub struct Uint(4);
}

impl serde::Serialize for Uint {
    fn serialize<S>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let amount_string = self.to_string();
        serde::Serialize::serialize(&amount_string, serializer)
    }
}

impl<'de> serde::Deserialize<'de> for Uint {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error as serdeError;
        let amount_string: String =
            serde::Deserialize::deserialize(deserializer)?;

        let digits = amount_string
            .chars()
            .filter_map(|c| {
                if c.is_ascii_digit() {
                    c.to_digit(10).map(Uint::from)
                } else {
                    None
                }
            })
            .rev()
            .collect::<Vec<_>>();
        if digits.len() != amount_string.len() {
            return Err(D::Error::custom(AmountParseError::FromString));
        }
        if digits.len() > 77 {
            return Err(D::Error::custom(AmountParseError::ScaleTooLarge(
                digits.len(),
                77,
            )));
        }
        let mut value = Uint::default();
        let ten = Uint::from(10);
        for (pow, digit) in digits.into_iter().enumerate() {
            value = ten
                .checked_pow(Uint::from(pow))
                .and_then(|scaling| scaling.checked_mul(digit))
                .and_then(|scaled| value.checked_add(scaled))
                .ok_or(AmountParseError::PrecisionOverflow)
                .map_err(D::Error::custom)?;
        }
        Ok(value)
    }
}

impl_uint_num_traits!(Uint, 4);

// Required for Ratio used in `voting_power::FractionalVotingPower`.
// Use with care as some of the methods may panic.
#[allow(clippy::arithmetic_side_effects)]
impl Integer for Uint {
    fn div_floor(&self, other: &Self) -> Self {
        self.checked_div(*other).unwrap()
    }

    fn mod_floor(&self, other: &Self) -> Self {
        let (_, rem) = self.div_mod(*other);
        rem
    }

    fn gcd(&self, other: &Self) -> Self {
        if self.is_zero() {
            return *self;
        }
        if other.is_zero() {
            return *other;
        }

        let shift = (*self | *other).trailing_zeros();
        let mut u = *self;
        let mut v = *other;
        u >>= shift;
        v >>= shift;
        u >>= u.trailing_zeros();

        loop {
            v >>= v.trailing_zeros();
            if u > v {
                std::mem::swap(&mut u, &mut v);
            }
            v -= u; // here v >= u
            if v.is_zero() {
                break;
            }
        }
        u << shift
    }

    fn lcm(&self, other: &Self) -> Self {
        (*self * *other).checked_div(self.gcd(other)).unwrap()
    }

    fn is_multiple_of(&self, other: &Self) -> bool {
        other
            .checked_rem(*self)
            .map(|rem| rem.is_zero())
            .unwrap_or_default()
    }

    fn divides(&self, other: &Self) -> bool {
        self.is_multiple_of(other)
    }

    fn is_even(&self) -> bool {
        use std::ops::BitAnd;
        self.bitand(Self::one()) != Self::one()
    }

    fn is_odd(&self) -> bool {
        !self.is_even()
    }

    fn div_rem(&self, other: &Self) -> (Self, Self) {
        self.div_mod(*other)
    }
}

/// The maximum 256 bit integer
pub const MAX_VALUE: Uint = Uint([u64::MAX; 4]);

impl Uint {
    /// Divide two [`Uint`]s with scaled to allow the `denom` number
    /// of decimal places.
    ///
    /// This method is checked and will return `None` if
    ///  * `self` * 10^(`denom`) overflows 256 bits
    ///  * `other` is  zero (`checked_div` will return `None`).
    pub fn fixed_precision_div(&self, rhs: &Self, denom: u8) -> Option<Self> {
        Uint::from(10)
            .checked_pow(Uint::from(denom))
            .and_then(|res| res.checked_mul_div(*self, *rhs))
            .map(|x| x.0)
    }

    /// Compute the two's complement of a number. Returns a flag if the negation
    /// overflows.
    fn negate(&self) -> (Self, bool) {
        let mut output = self.0;
        for byte in output.iter_mut() {
            *byte ^= u64::MAX;
        }
        let (res, overflow) = Self(output).overflowing_add(Uint::from(1u64));
        (res.canonical(), overflow)
    }

    /// There are two valid representations of zero: plus and
    /// minus. We only allow the positive representation.
    fn canonical(self) -> Self {
        if self == MINUS_ZERO {
            Self::zero()
        } else {
            self
        }
    }
}

/// The maximum absolute value a [`I256`] may have.
/// Note the last digit is 2^63 - 1. We add this cap so
/// we can use two's complement.
pub const MAX_SIGNED_VALUE: Uint =
    Uint([u64::MAX, u64::MAX, u64::MAX, 9223372036854775807]);

const MINUS_ZERO: Uint = Uint([0u64, 0u64, 0u64, 9223372036854775808]);

/// A signed 256 big integer.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    Copy,
    Clone,
    Default,
    PartialEq,
    Eq,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
)]
pub struct I256(pub Uint);

impl fmt::Debug for I256 {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        <Self as fmt::Display>::fmt(self, f)
    }
}

impl fmt::Display for I256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_negative() {
            write!(f, "-")?;
        }
        write!(f, "{}", self.abs())
    }
}

impl FromStr for I256 {
    type Err = Box<dyn 'static + std::error::Error>;

    fn from_str(num: &str) -> Result<Self, Self::Err> {
        if let Some(("", neg_num)) = num.split_once('-') {
            let (uint, overflow) = neg_num.parse::<Uint>()?.negate();
            if overflow {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "I256 overflow",
                )));
            }
            Ok(I256(uint))
        } else {
            let uint = num.parse::<Uint>()?;
            Ok(I256(uint))
        }
    }
}

impl I256 {
    const N_WORDS: usize = 4;

    /// Compute the two's complement of a number.
    pub fn negate(&self) -> Option<Self> {
        let (uint, overflow) = self.0.negate();
        if overflow { None } else { Some(Self(uint)) }
    }

    /// Check if the amount is not negative (greater
    /// than or equal to zero)
    pub fn non_negative(&self) -> bool {
        self.0.0[3].leading_zeros() > 0
    }

    /// Check if the amount is negative (less than zero)
    pub fn is_negative(&self) -> bool {
        !self.non_negative()
    }

    /// Check if the amount is positive (greater than zero)
    pub fn is_positive(&self) -> bool {
        self.non_negative() && !self.is_zero()
    }

    /// Get the absolute value
    pub fn abs(&self) -> Uint {
        if self.non_negative() {
            self.0
        } else {
            self.0.negate().0
        }
    }

    /// Check if this value is zero
    pub fn is_zero(&self) -> bool {
        self.0 == Uint::zero()
    }

    /// Gives the zero value of an I256
    pub fn zero() -> I256 {
        Self(Uint::zero())
    }

    /// Gives the one value of an I256
    pub fn one() -> I256 {
        Self(Uint::one())
    }

    /// Get a string representation of `self` as a
    /// native token amount.
    pub fn to_string_native(&self) -> String {
        let mut sign = if !self.non_negative() {
            String::from("-")
        } else {
            String::new()
        };
        sign.push_str(&token::Amount::from(*self).to_string_native());
        sign
    }

    /// Changed the inner Uint into a canonical representation.
    fn canonical(self) -> Self {
        Self(self.0.canonical())
    }

    /// The maximum value of an [`I256`].
    pub fn maximum() -> Self {
        Self(MAX_SIGNED_VALUE)
    }

    /// Given an i128 and [`MaspDigitPos`], construct the corresponding
    /// amount.
    pub fn from_masp_denominated(
        val: i128,
        denom: MaspDigitPos,
    ) -> Result<Self, <i64 as TryFrom<u64>>::Error> {
        let abs = val.unsigned_abs();
        #[allow(clippy::cast_possible_truncation)]
        let lo = abs as u64;
        let hi = (abs >> 64) as u64;
        let lo_pos = denom as usize;
        #[allow(clippy::arithmetic_side_effects)]
        let hi_pos = lo_pos + 1;
        let mut raw = [0u64; Self::N_WORDS];
        raw[lo_pos] = lo;
        raw[hi_pos] = hi;
        i64::try_from(raw[Self::N_WORDS - 1]).map(|_| {
            let res = Self(Uint(raw));
            if val.is_negative() {
                res.checked_neg().unwrap()
            } else {
                res
            }
        })
    }

    /// Multiply by a decimal [`Dec`] with the result rounded up. Checks for
    /// overflow.
    pub fn mul_ceil(&self, dec: Dec) -> Result<Self, arith::Error> {
        let is_res_negative = self.is_negative() ^ dec.is_negative();
        let tot = checked!(self.abs() * dec.0.abs())?;
        let denom = Uint::from(10u64.pow(u32::from(POS_DECIMAL_PRECISION)));
        let floor_div = checked!(tot / denom)?;
        let rem = checked!(tot % denom)?;
        let abs_res = Self(if !rem.is_zero() && !is_res_negative {
            checked!(floor_div + Uint::from(1_u64))?
        } else {
            floor_div
        });
        Ok(if is_res_negative {
            checked!(-abs_res)?
        } else {
            abs_res
        })
    }

    /// Sum with overflow check
    pub fn sum<I: Iterator<Item = Self>>(mut iter: I) -> Option<Self> {
        iter.try_fold(I256::zero(), |acc, amt| acc.checked_add(amt))
    }

    /// Adds two [`I256`]'s if the absolute value does
    /// not exceed [`MAX_SIGNED_VALUE`], else returns `None`.
    pub fn checked_add(&self, rhs: Self) -> Option<Self> {
        let result = match (self.non_negative(), rhs.non_negative()) {
            (true, true) => {
                let inner = self.0.checked_add(rhs.0)?;
                if inner > MAX_SIGNED_VALUE {
                    return None;
                }
                Self(inner)
            }
            (false, false) => {
                let inner = self.abs().checked_add(rhs.abs())?;
                if inner > MAX_SIGNED_VALUE {
                    return None;
                }
                Self(inner).checked_neg()?
            }
            (true, false) => {
                if self.0 >= rhs.abs() {
                    Self(self.0.checked_sub(rhs.abs())?)
                } else {
                    Self(rhs.abs().checked_sub(self.0)?).checked_neg()?
                }
            }
            (false, true) => {
                if rhs.0 >= self.abs() {
                    Self(rhs.abs().checked_sub(self.abs())?)
                } else {
                    Self(self.abs().checked_sub(rhs.0)?).checked_neg()?
                }
            }
        }
        .canonical();
        Some(result)
    }

    /// Subtracts two [`I256`]'s if the absolute value does
    /// not exceed [`MAX_SIGNED_VALUE`], else returns `None`.
    pub fn checked_sub(&self, other: Self) -> Option<Self> {
        self.checked_add(other.checked_neg()?)
    }

    /// Checked negation
    pub fn checked_neg(&self) -> Option<Self> {
        if self.is_zero() {
            return Some(*self);
        }
        let (inner, overflow) = self.0.negate();
        if overflow { None } else { Some(Self(inner)) }
    }

    /// Checked multiplication
    pub fn checked_mul(&self, v: Self) -> Option<Self> {
        let is_negative = self.is_negative() != v.is_negative();
        let unsigned_res =
            I256::try_from(self.abs().checked_mul(v.abs())?).ok()?;
        Some(if is_negative {
            unsigned_res.checked_neg()?
        } else {
            unsigned_res
        })
    }

    /// Checked division
    pub fn checked_div(&self, rhs: Self) -> Option<Self> {
        if rhs.is_zero() {
            None
        } else {
            let quot = self
                .abs()
                .fixed_precision_div(&rhs.abs(), 0u8)
                .unwrap_or_default();
            Some(if self.is_negative() == rhs.is_negative() {
                Self(quot)
            } else {
                Self(quot).checked_neg()?
            })
        }
    }

    /// Checked division remnant
    pub fn checked_rem(&self, rhs: Self) -> Option<Self> {
        let inner: Uint = self.abs().checked_rem(rhs.abs())?;
        if self.is_negative() {
            Some(Self(inner).checked_neg()?)
        } else {
            Some(Self(inner))
        }
    }
}

impl Zero for I256 {
    fn zero() -> Self {
        Self(ZERO)
    }

    fn is_zero(&self) -> bool {
        self.0 == ZERO
    }
}

impl One for I256 {
    fn one() -> Self {
        Self(ONE)
    }

    fn is_one(&self) -> bool {
        self.0 == ONE
    }
}

// NOTE: This is here only because MASP requires it for `ValueSum` addition
impl CheckedAdd for &I256 {
    type Output = I256;

    fn checked_add(self, rhs: Self) -> Option<Self::Output> {
        self.checked_add(*rhs)
    }
}

impl CheckedAdd for I256 {
    type Output = I256;

    fn checked_add(self, rhs: Self) -> Option<Self::Output> {
        I256::checked_add(&self, rhs)
    }
}

// NOTE: This is here only because MASP requires it for `ValueSum` subtraction
impl CheckedSub for &I256 {
    type Output = I256;

    fn checked_sub(self, rhs: Self) -> Option<Self::Output> {
        self.checked_sub(*rhs)
    }
}

impl CheckedSub for I256 {
    type Output = I256;

    fn checked_sub(self, rhs: Self) -> Option<Self::Output> {
        I256::checked_sub(&self, rhs)
    }
}

// NOTE: This is here only because num_traits::CheckedAdd requires it
impl std::ops::Add for I256 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        self.checked_add(rhs).unwrap()
    }
}

impl From<u64> for I256 {
    fn from(val: u64) -> Self {
        I256::try_from(Uint::from(val))
            .expect("A u64 will always fit in this type")
    }
}

impl TryFrom<Uint> for I256 {
    type Error = Box<dyn 'static + std::error::Error>;

    fn try_from(value: Uint) -> Result<Self, Self::Error> {
        if value <= MAX_SIGNED_VALUE {
            Ok(Self(value))
        } else {
            Err("The given integer is too large to be represented asa \
                 SignedUint"
                .into())
        }
    }
}

impl PartialOrd for I256 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for I256 {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self.non_negative(), other.non_negative()) {
            (true, false) => Ordering::Greater,
            (false, true) => Ordering::Less,
            (true, true) => {
                let this = self.abs();
                let that = other.abs();
                this.cmp(&that)
            }
            (false, false) => {
                let this = self.abs();
                let that = other.abs();
                that.cmp(&this)
            }
        }
    }
}

impl From<i128> for I256 {
    fn from(val: i128) -> Self {
        if val == i128::MIN {
            Self(170141183460469231731687303715884105728_u128.into())
                .checked_neg()
                .expect(
                    "This cannot panic as the value is greater than \
                     `I256::MIN`",
                )
        } else if val < 0 {
            let abs = Self(
                (val.checked_neg().expect(
                    "This cannot panic as we're checking for `i128::MIN` above",
                ))
                .into(),
            );

            //
            abs.checked_neg().expect(
                "This cannot panic as the value is limited to `i128` range",
            )
        } else {
            Self(val.into())
        }
    }
}

impl From<i64> for I256 {
    fn from(val: i64) -> Self {
        Self::from(i128::from(val))
    }
}

impl From<i32> for I256 {
    fn from(val: i32) -> Self {
        Self::from(i128::from(val))
    }
}

impl TryFrom<I256> for i128 {
    type Error = std::io::Error;

    fn try_from(value: I256) -> Result<Self, Self::Error> {
        // The negation cannot panic as `i128::MIN` > `I256::MIN`.
        #[allow(clippy::arithmetic_side_effects)]
        let i128_min =
            I256(170141183460469231731687303715884105728_u128.into())
                .checked_neg()
                .expect("const value neg in range");
        // Because we're converting abs value, `i128::MIN` would be overflow it
        // so we have to check for it first.
        if value == i128_min {
            return Ok(i128::MIN);
        }
        let raw = i128::try_from(value.abs().low_u128()).map_err(|err| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, err)
        })?;
        if !value.non_negative() {
            // This cannot panic as we're checking for `i128::MIN`
            #[allow(clippy::arithmetic_side_effects)]
            Ok(-raw)
        } else {
            Ok(raw)
        }
    }
}

construct_uint! {
    #[derive(
        BorshSerialize,
        BorshDeserialize,
        BorshSchema,
    )]

    struct SignedAmountInt(5);
}

/// A positive or negative amount
#[derive(
    Copy,
    Clone,
    Eq,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
    Default,
)]
pub struct I320(SignedAmountInt);

impl Zero for I320 {
    fn zero() -> Self {
        Self(SignedAmountInt::from(0))
    }

    fn is_zero(&self) -> bool {
        self.0 == SignedAmountInt::from(0)
    }
}

impl One for I320 {
    fn one() -> Self {
        Self(SignedAmountInt::from(1))
    }

    fn is_one(&self) -> bool {
        self.0 == SignedAmountInt::from(1)
    }
}

impl<T> OverflowingAdd<T> for I320
where
    T: Into<I320>,
{
    type Output = Self;

    fn overflowing_add(self, other: T) -> (Self, bool) {
        let (res, overflow) = self.0.overflowing_add(other.into().0);
        (Self(res), overflow)
    }
}

impl<T> OverflowingAdd<T> for &I320
where
    T: Into<I320>,
{
    type Output = I320;

    fn overflowing_add(self, other: T) -> (I320, bool) {
        let (res, overflow) = self.0.overflowing_add(other.into().0);
        (I320(res), overflow)
    }
}

impl<T> OverflowingSub<T> for I320
where
    T: Into<I320>,
{
    type Output = Self;

    fn overflowing_sub(self, other: T) -> (Self, bool) {
        let (res, overflow) = self.0.overflowing_sub(other.into().0);
        (I320(res), overflow)
    }
}

impl<T> OverflowingSub<T> for &I320
where
    T: Into<I320>,
{
    type Output = I320;

    fn overflowing_sub(self, other: T) -> (I320, bool) {
        let (res, overflow) = self.0.overflowing_sub(other.into().0);
        (I320(res), overflow)
    }
}

impl From<Uint> for I320 {
    fn from(lo: Uint) -> Self {
        let mut arr = [0u64; Self::N_WORDS];
        arr[..4].copy_from_slice(&lo.0);
        Self(SignedAmountInt(arr))
    }
}

impl From<u64> for I320 {
    fn from(val: u64) -> Self {
        Self::from(Uint::from(val))
    }
}

impl From<token::Amount> for I320 {
    fn from(lo: token::Amount) -> Self {
        let mut arr = [0u64; Self::N_WORDS];
        arr[..4].copy_from_slice(&lo.raw_amount().0);
        Self(SignedAmountInt(arr))
    }
}

impl TryInto<token::Amount> for I320 {
    type Error = std::io::Error;

    fn try_into(self) -> Result<token::Amount, Self::Error> {
        if self.0.0[Self::N_WORDS - 1] == 0 {
            Ok(token::Amount::from_uint(
                Uint([self.0.0[0], self.0.0[1], self.0.0[2], self.0.0[3]]),
                0,
            )
            .unwrap())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Integer overflow when casting to Amount",
            ))
        }
    }
}

impl I320 {
    const N_WORDS: usize = 5;

    /// Gives the one value of an SignedAmount
    pub fn one() -> Self {
        Self(SignedAmountInt::one())
    }

    /// Check if the amount is negative (less than zero)
    pub fn is_negative(&self) -> bool {
        self.0.bit(Self::N_WORDS * SignedAmountInt::WORD_BITS - 1)
    }

    /// Check if the amount is positive (greater than zero)
    pub fn is_positive(&self) -> bool {
        !self.is_negative() && !self.0.is_zero()
    }

    /// Get the absolute value
    fn abs(&self) -> Self {
        if self.is_negative() {
            self.overflowing_neg()
        } else {
            *self
        }
    }

    /// Get the absolute value
    pub fn checked_abs(&self) -> Option<Self> {
        if self.is_negative() {
            self.checked_neg()
        } else {
            Some(*self)
        }
    }

    /// Compute the negation of a number.
    pub fn overflowing_neg(self) -> Self {
        (!self).overflowing_add(Self::one()).0
    }

    /// Get a string representation of `self` as a
    /// native token amount.
    pub fn to_string_native(self) -> String {
        let mut res = self.abs().0.to_string();
        if self.is_negative() {
            res.insert(0, '-');
        }
        res
    }

    /// Given a u128 and [`MaspDigitPos`], construct the corresponding
    /// amount.
    pub fn from_masp_denominated(
        val: i128,
        denom: MaspDigitPos,
    ) -> Result<Self, <i64 as TryFrom<u64>>::Error> {
        let abs = val.unsigned_abs();
        #[allow(clippy::cast_possible_truncation)]
        let lo = abs as u64;
        let hi = (abs >> 64) as u64;
        let lo_pos = denom as usize;
        #[allow(clippy::arithmetic_side_effects)]
        let hi_pos = lo_pos + 1;
        let mut raw = [0u64; Self::N_WORDS];
        raw[lo_pos] = lo;
        raw[hi_pos] = hi;
        i64::try_from(raw[Self::N_WORDS - 1]).map(|_| {
            let res = Self(SignedAmountInt(raw));
            if val.is_negative() {
                res.checked_neg().unwrap()
            } else {
                res
            }
        })
    }
}

impl Not for I320 {
    type Output = Self;

    fn not(self) -> Self {
        Self(!self.0)
    }
}

impl CheckedNeg for I320 {
    type Output = I320;

    fn checked_neg(self) -> Option<Self::Output> {
        let neg = self.overflowing_neg();
        (neg != self).then_some(neg)
    }
}

impl CheckedAdd for I320 {
    type Output = I320;

    fn checked_add(self, rhs: Self) -> Option<Self::Output> {
        let res = self.overflowing_add(rhs).0;
        ((self.is_negative() != rhs.is_negative())
            || (self.is_negative() == res.is_negative()))
        .then_some(res)
    }
}

impl CheckedSub for I320 {
    type Output = I320;

    fn checked_sub(self, rhs: Self) -> Option<Self::Output> {
        let res = self.overflowing_add(rhs.overflowing_neg()).0;
        ((self.is_negative() == rhs.is_negative())
            || (res.is_negative() == self.is_negative()))
        .then_some(res)
    }
}

impl PartialOrd for I320 {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        #[allow(clippy::arithmetic_side_effects)]
        (!self.is_negative(), self.0 << 1)
            .partial_cmp(&(!other.is_negative(), other.0 << 1))
    }
}

/// Testing helpers
#[cfg(any(test, feature = "testing"))]
#[allow(clippy::arithmetic_side_effects)]
pub mod testing {
    use super::*;

    impl Uint {
        /// Returns a pair `((self * num) / denom, (self * num) % denom)`.
        ///
        /// # Panics
        ///
        /// Panics if `denom` is zero.
        pub fn mul_div(&self, num: Self, denom: Self) -> (Self, Self) {
            self.checked_mul_div(num, denom).unwrap()
        }
    }

    impl std::ops::AddAssign for I256 {
        fn add_assign(&mut self, rhs: Self) {
            *self = self.checked_add(rhs).unwrap();
        }
    }

    impl std::ops::Sub<I256> for I256 {
        type Output = Self;

        fn sub(self, rhs: I256) -> Self::Output {
            self.checked_sub(rhs).unwrap()
        }
    }

    impl std::ops::SubAssign<I256> for I256 {
        fn sub_assign(&mut self, rhs: I256) {
            *self = *self - rhs;
        }
    }

    impl std::ops::Mul<I256> for I256 {
        type Output = Self;

        fn mul(self, rhs: I256) -> Self::Output {
            self.checked_mul(rhs).unwrap()
        }
    }

    impl std::ops::Neg for I256 {
        type Output = Self;

        fn neg(self) -> Self::Output {
            self.checked_neg().unwrap()
        }
    }

    impl std::ops::Add for I320 {
        type Output = Self;

        fn add(self, rhs: Self) -> Self::Output {
            self.checked_add(rhs).unwrap()
        }
    }

    impl std::ops::Neg for I320 {
        type Output = Self;

        fn neg(self) -> Self::Output {
            self.checked_neg().unwrap()
        }
    }
}

#[cfg(test)]
mod test_uint {
    use std::str::FromStr;

    use assert_matches::assert_matches;

    use super::*;

    /// Test that dividing two [`Uint`]s with the specified precision
    /// works correctly and performs correct checks.
    #[test]
    fn test_fixed_precision_div() {
        let zero = Uint::zero();
        let two = Uint::from(2);
        let three = Uint::from(3);

        assert_eq!(
            zero.fixed_precision_div(&two, 10).expect("Test failed"),
            zero
        );
        assert!(two.fixed_precision_div(&zero, 3).is_none());
        assert_eq!(
            three.fixed_precision_div(&two, 1).expect("Test failed"),
            Uint::from(15)
        );
        assert_eq!(
            two.fixed_precision_div(&three, 2).expect("Test failed"),
            Uint::from(66)
        );
        assert_eq!(
            two.fixed_precision_div(&three, 3).expect("Satan lives"),
            Uint::from(666)
        );
        assert_eq!(
            two.fixed_precision_div(&three, 77).expect("Test failed"),
            Uint::from_str("9363ff047551e60c314a09cf62a269d471bafcf44a8c6aaaaaaaaaaaaaaaaaaa").unwrap()
        );
        assert_eq!(
            Uint::from(20).fixed_precision_div(&three, 76).expect("Test failed"),
            Uint::from_str("9363ff047551e60c314a09cf62a269d471bafcf44a8c6aaaaaaaaaaaaaaaaaaa").unwrap()
        );
    }

    /// Test that checked add and sub stays below max signed value
    #[test]
    fn test_max_signed_value() {
        let signed = I256::try_from(MAX_SIGNED_VALUE).expect("Test failed");
        let one = I256::try_from(Uint::from(1u64)).expect("Test failed");
        assert!(signed.checked_add(one).is_none());
        assert!((-signed).checked_sub(one).is_none());
    }

    /// Sanity on our constants and that the minus zero representation
    /// is not allowed.
    #[test]
    fn test_minus_zero_not_allowed() {
        let larger = Uint([0, 0, 0, 2u64.pow(63)]);
        let smaller = Uint([u64::MAX, u64::MAX, u64::MAX, 2u64.pow(63) - 1]);
        assert!(larger > smaller);
        assert_eq!(smaller, MAX_SIGNED_VALUE);
        assert_eq!(larger, MINUS_ZERO);
        assert!(I256::try_from(MINUS_ZERO).is_err());
        let zero = Uint::zero();
        assert_eq!(zero, zero.negate().0);
    }

    /// Test that we correctly reserve the right bit for indicating the
    /// sign.
    #[test]
    fn test_non_negative() {
        let zero = I256::try_from(Uint::zero()).expect("Test failed");
        assert!(zero.non_negative());
        assert!((-zero).non_negative());
        let negative = I256(Uint([1u64, 0, 0, 2u64.pow(63)]));
        assert!(!negative.non_negative());
        assert!((-negative).non_negative());
        let positive = I256(MAX_SIGNED_VALUE);
        assert!(positive.non_negative());
        assert!(!(-positive).non_negative());
    }

    /// Test that the absolute value is computed correctly.
    #[test]
    fn test_abs() {
        let zero = I256::try_from(Uint::zero()).expect("Test failed");
        let neg_one = I256(Uint::max_value());
        let neg_eight = I256(Uint::max_value() - Uint::from(7));
        let two = I256(Uint::from(2));
        let ten = I256(Uint::from(10));

        assert_eq!(zero.abs(), Uint::zero());
        assert_eq!(neg_one.abs(), Uint::from(1));
        assert_eq!(neg_eight.abs(), Uint::from(8));
        assert_eq!(two.abs(), Uint::from(2));
        assert_eq!(ten.abs(), Uint::from(10));
    }

    /// Test that the string representation is created correctly.
    #[test]
    fn test_to_string_native() {
        let native_scaling = Uint::exp10(6);
        let zero = I256::try_from(Uint::zero()).expect("Test failed");
        let neg_one = -I256(native_scaling);
        let neg_eight = -I256(Uint::from(8) * native_scaling);
        let two = I256(Uint::from(2) * native_scaling);
        let ten = I256(Uint::from(10) * native_scaling);

        assert_eq!(zero.to_string_native(), "0.000000");
        assert_eq!(neg_one.to_string_native(), "-1.000000");
        assert_eq!(neg_eight.to_string_native(), "-8.000000");
        assert_eq!(two.to_string_native(), "2.000000");
        assert_eq!(ten.to_string_native(), "10.000000");
    }

    /// Test that we correctly handle arithmetic with two's complement
    #[test]
    fn test_arithmetic() {
        let zero = I256::try_from(Uint::zero()).expect("Test failed");
        let neg_one = I256(Uint::max_value());
        let neg_eight = I256(Uint::max_value() - Uint::from(7));
        let two = I256(Uint::from(2));
        let ten = I256(Uint::from(10));

        assert_eq!(zero + neg_one, neg_one);
        assert_eq!(neg_one - zero, neg_one);
        assert_eq!(zero - neg_one, I256(Uint::one()));
        assert_eq!(two - neg_eight, ten);
        assert_eq!(two + ten, I256(Uint::from(12)));
        assert_eq!(ten - two, -neg_eight);
        assert_eq!(two - ten, neg_eight);
        assert_eq!(neg_eight + neg_one, -I256(Uint::from(9)));
        assert_eq!(neg_one - neg_eight, I256(Uint::from(7)));
        assert_eq!(neg_eight - neg_one, -I256(Uint::from(7)));
        assert_eq!(neg_eight - two, -ten);
        assert!((two - two).is_zero());
    }

    /// Test that ordering is correctly implemented
    #[test]
    fn test_ord() {
        let this = token::Amount::from_uint(1, 0).unwrap().change();
        let that = token::Amount::native_whole(1000).change();
        assert!(this <= that);
        assert!(-this <= that);
        assert!(-this >= -that);
        assert!(this >= -that);
        assert!(that >= this);
        assert!(that >= -this);
        assert!(-that <= -this);
        assert!(-that <= this);
    }

    #[test]
    fn test_serialization_roundtrip() {
        let amount: Uint = serde_json::from_str(r#""1000000000""#).unwrap();
        assert_eq!(amount, Uint::from(1000000000));
        let serialized = serde_json::to_string(&amount).unwrap();
        assert_eq!(serialized, r#""1000000000""#);

        let amount: Result<Uint, _> = serde_json::from_str(r#""1000000000.2""#);
        assert!(amount.is_err());
    }

    #[test]
    fn test_i256_mul_ceil() {
        let one = I256::from(1);
        let two = I256::from(2);
        let dec = Dec::from_str("0.25").unwrap();
        let neg_dec = dec.checked_neg().unwrap();
        assert_eq!(one.mul_ceil(dec).unwrap(), one);
        assert_eq!(two.mul_ceil(dec).unwrap(), one);
        assert_eq!(I256::from(4).mul_ceil(dec).unwrap(), one);
        assert_eq!(I256::from(5).mul_ceil(dec).unwrap(), two);

        assert_eq!((-one).mul_ceil(neg_dec).unwrap(), one);

        assert_eq!((-one).mul_ceil(dec).unwrap(), I256::zero());
        assert_eq!(one.mul_ceil(neg_dec).unwrap(), I256::zero());
    }

    #[test]
    fn test_mul_div() {
        use std::str::FromStr;
        let a: Uint = Uint::from_str(
            "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        ).unwrap();
        let b: Uint = Uint::from_str(
            "0x8000000000000000000000000000000000000000000000000000000000000000",
        ).unwrap();
        let c: Uint = Uint::from_str(
            "0x4000000000000000000000000000000000000000000000000000000000000000",
        ).unwrap();
        let d: Uint = Uint::from_str(
            "0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        ).unwrap();
        let e: Uint = Uint::from_str(
            "0x0000000000000000000000000000000000000000000000000000000000000001",
        ).unwrap();
        let f: Uint = Uint::from_str(
            "0x0000000000000000000000000000000000000000000000000000000000000000",
        ).unwrap();
        assert_eq!(a.mul_div(a, a), (a, Uint::zero()));
        assert_eq!(b.mul_div(c, b), (c, Uint::zero()));
        assert_eq!(a.mul_div(c, b), (d, c));
        assert_eq!(a.mul_div(e, e), (a, Uint::zero()));
        assert_eq!(e.mul_div(c, b), (Uint::zero(), c));
        assert_eq!(f.mul_div(a, e), (Uint::zero(), Uint::zero()));
        assert_eq!(a.checked_mul_div(a, a), Some((a, Uint::zero())));
        assert_eq!(b.checked_mul_div(c, b), Some((c, Uint::zero())));
        assert_eq!(a.checked_mul_div(c, b), Some((d, c)));
        assert_eq!(a.checked_mul_div(e, e), Some((a, Uint::zero())));
        assert_eq!(e.checked_mul_div(c, b), Some((Uint::zero(), c)));
        assert_eq!(d.checked_mul_div(a, e), None);
    }

    #[test]
    fn test_i256_str_roundtrip() {
        let minus_one = I256::one().negate().unwrap();
        let minus_one_str = minus_one.to_string();
        assert_eq!(minus_one_str, "-1");

        let parsed: I256 = minus_one_str.parse().unwrap();
        assert_eq!(minus_one, parsed);
    }

    #[test]
    fn test_i128_try_from_i256() {
        for src in [
            I256::from(0),
            I256::from(1),
            I256::from(-1),
            I256::from(i128::MAX),
            I256::from(i128::MIN),
        ] {
            println!("Src val {src}");
            let res = i128::try_from(src);
            // Source value is constructed from a valid i128 range
            assert_matches!(res, Ok(_));
        }

        for src in [
            I256::maximum(),
            I256::maximum() - I256::from(1),
            -I256::maximum(),
            -(I256::maximum() - I256::from(1)),
        ] {
            println!("Src val {src}");
            // Out of i128 range, but must not panic!
            let _res = i128::try_from(src);
        }
    }
}
