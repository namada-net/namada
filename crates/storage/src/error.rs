//! Storage API error type, extensible with custom user errors and static string
//! messages.

use std::convert::Infallible;
use std::num::TryFromIntError;

use namada_core::arith;
use thiserror::Error;

use crate::db;

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum Error {
    #[error("{0}")]
    SimpleMessage(&'static str),
    #[error("{0}")]
    AllocMessage(String),
    #[error("{0}")]
    Custom(CustomError),
    #[error("{0}: {1}")]
    CustomWithMessage(&'static str, CustomError),
}

/// Result of a storage API call.
pub type Result<T> = std::result::Result<T, Error>;

/// Result extension to easily wrap custom errors into [`enum@Error`].
// This is separate from `ResultExt`, because the implementation requires
// different bounds for `T`.
pub trait ResultExt<T> {
    /// Convert a [`std::result::Result`] into storage_api [`Result`].
    fn into_storage_result(self) -> Result<T>;

    /// Add a static message to a possible error in [`Result`].
    fn wrap_err(self, msg: &'static str) -> Result<T>;
}

impl<T, E> ResultExt<T> for std::result::Result<T, E>
where
    E: std::error::Error + Send + Sync + 'static,
{
    fn into_storage_result(self) -> Result<T> {
        self.map_err(Error::new)
    }

    fn wrap_err(self, msg: &'static str) -> Result<T> {
        self.map_err(|err| Error::wrap(msg, err))
    }
}

impl Error {
    /// Create an [`enum@Error`] from another [`std::error::Error`].
    pub fn new<E>(error: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        Self::Custom(CustomError(error.into()))
    }

    /// Create an [`enum@Error`] from a static message.
    #[inline]
    pub const fn new_const(msg: &'static str) -> Self {
        Self::SimpleMessage(msg)
    }

    /// Create an [`enum@Error`] from a heap allocated message.
    #[inline]
    pub const fn new_alloc(msg: String) -> Self {
        Self::AllocMessage(msg)
    }

    /// Wrap another [`std::error::Error`] with a static message.
    pub fn wrap<E>(msg: &'static str, error: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        Self::CustomWithMessage(msg, CustomError(error.into()))
    }

    /// Attempt to downgrade the inner error to `E` if any.
    ///
    /// If this [`enum@Error`] was constructed via [`new`] or [`wrap`] then this
    /// function will attempt to perform downgrade on it, otherwise it will
    /// return [`Err`].
    ///
    /// [`new`]: Error::new
    /// [`wrap`]: Error::wrap
    ///
    /// To match on the inner error type when the downcast is successful, you'll
    /// typically want to [`std::ops::Deref::deref`] it out of the [`Box`].
    pub fn downcast<E>(self) -> std::result::Result<Box<E>, Self>
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        match self {
            Self::Custom(CustomError(b))
            | Self::CustomWithMessage(_, CustomError(b))
                if b.is::<E>() =>
            {
                let res = b.downcast::<E>();
                Ok(res.unwrap())
            }
            _ => Err(self),
        }
    }

    /// Returns some reference to the inner value if it is of type `E`, or
    /// `None` if it isn't.
    pub fn downcast_ref<E>(&self) -> Option<&E>
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        match self {
            Self::Custom(CustomError(b))
            | Self::CustomWithMessage(_, CustomError(b))
                if b.is::<E>() =>
            {
                b.downcast_ref::<E>()
            }
            _ => None,
        }
    }
}

/// A custom error
#[derive(Debug)]
pub struct CustomError(pub Box<dyn std::error::Error + Send + Sync>);

impl std::fmt::Display for CustomError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// An extension to [`Option`] to allow turning `None` case to an Error from a
/// static string (handy for WASM).
pub trait OptionExt<T> {
    /// Transforms the [`Option<T>`] into a [`Result<T>`], mapping
    /// `Some(v)` to `Ok(v)` and `None` to the given static error message.
    fn ok_or_err_msg(self, msg: &'static str) -> Result<T>;
}

impl<T> OptionExt<T> for Option<T> {
    fn ok_or_err_msg(self, msg: &'static str) -> Result<T> {
        self.ok_or_else(|| Error::new_const(msg))
    }
}

/// Convert `namada_storage::Error` into IBC `HandlerError`.
/// It always returns `HostError::Other` though the storage error could happen
/// in any storage access.
impl From<Error> for namada_core::ibc::core::host::types::error::HostError {
    fn from(error: Error) -> Self {
        namada_core::ibc::core::host::types::error::HostError::Other {
            description: format!("Storage error: {error}"),
        }
    }
}

impl From<arith::Error> for Error {
    fn from(value: arith::Error) -> Self {
        Error::new(value)
    }
}

impl From<db::Error> for Error {
    fn from(value: db::Error) -> Self {
        Error::new(value)
    }
}

impl From<namada_core::storage::Error> for Error {
    fn from(value: namada_core::storage::Error) -> Self {
        Error::new(value)
    }
}

impl From<namada_core::DecodeError> for Error {
    fn from(value: namada_core::DecodeError) -> Self {
        Error::new(value)
    }
}
impl From<namada_core::string_encoding::DecodeError> for Error {
    fn from(value: namada_core::string_encoding::DecodeError) -> Self {
        Error::new(value)
    }
}

impl From<namada_core::hash::Error> for Error {
    fn from(value: namada_core::hash::Error) -> Self {
        Error::new(value)
    }
}

impl From<namada_merkle_tree::Error> for Error {
    fn from(value: namada_merkle_tree::Error) -> Self {
        Error::new(value)
    }
}

impl From<Infallible> for Error {
    fn from(_value: Infallible) -> Self {
        panic!("Infallible error can never be constructed")
    }
}

impl From<TryFromIntError> for Error {
    fn from(value: TryFromIntError) -> Self {
        Error::new(value)
    }
}
