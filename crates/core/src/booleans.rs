//! Boolean related functionality.

/// Extend [`bool`] values with the possibility to create
/// [`Result`] values of unit and some error type.
pub trait BoolResultUnitExt<E> {
    /// Return `Ok(())` if true, or `error` if false.
    fn ext_ok_or(self, error: E) -> Result<(), E>;

    /// Return `Ok(())` if true, or the value returned by
    /// `handle_err` if false.
    fn ext_ok_or_else<F>(self, handle_err: F) -> Result<(), E>
    where
        F: FnOnce() -> E;
}

impl<E> BoolResultUnitExt<E> for bool {
    #[inline]
    fn ext_ok_or(self, error: E) -> Result<(), E> {
        if self { Ok(()) } else { Err(error) }
    }

    #[inline]
    fn ext_ok_or_else<F>(self, handle_err: F) -> Result<(), E>
    where
        F: FnOnce() -> E,
    {
        if self { Ok(()) } else { Err(handle_err()) }
    }
}

/// Extend [`Result`] of [`bool`] values with the possibility to
/// create [`Result`] values of unit and some error type.
pub trait ResultBoolExt<E> {
    /// Return `Ok(())` if `Ok(true)`, `Err(error)` if `Ok(false)`
    /// or pass back the error if `Err(_)`.
    fn ext_true_or(self, error: E) -> Result<(), E>;

    /// Return `Ok(())` if `Ok(true)`, `Err(handle_err())` if `Ok(false)`
    /// or pass back the error if `Err(_)`.
    fn ext_true_or_else<F>(self, handle_err: F) -> Result<(), E>
    where
        F: FnOnce() -> E;
}

impl<E> ResultBoolExt<E> for Result<bool, E> {
    /// Return `Ok(())` if `Ok(true)`, `Err(error)` if `Ok(false)`
    /// or pass back the error if `Err(_)`.
    #[inline]
    fn ext_true_or(self, error: E) -> Result<(), E> {
        self.and_then(|ok| ok.ext_ok_or(error))
    }

    /// Return `Ok(())` if `Ok(true)`, `Err(handle_err())` if `Ok(false)`
    /// or pass back the error if `Err(_)`.
    #[inline]
    fn ext_true_or_else<F>(self, handle_err: F) -> Result<(), E>
    where
        F: FnOnce() -> E,
    {
        self.and_then(|ok| ok.ext_ok_or_else(handle_err))
    }
}
