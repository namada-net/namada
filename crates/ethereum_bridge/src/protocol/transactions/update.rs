//! Helpers for writing to storage
use eyre::Result;
use namada_core::borsh::{BorshDeserialize, BorshSerialize};
use namada_core::hash::StorageHasher;
use namada_core::storage;
use namada_state::{DBIter, DBRead, WlState};
use namada_storage::StorageWrite;

#[allow(dead_code)]
/// Reads an arbitrary value, applies update then writes it back
pub fn value<D, H, T: BorshSerialize + BorshDeserialize>(
    state: &mut WlState<'_, D, H>,
    key: &storage::Key,
    update: impl FnOnce(&mut T),
) -> Result<T>
where
    D: 'static + DBRead + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let mut value = super::read::value(state, key)?;
    update(&mut value);
    state.write(key, &value)?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use eyre::eyre;
    use namada_state::testing::TestState;
    use namada_storage::StorageRead;

    use super::*;

    #[test]
    /// Test updating a value
    fn test_value() -> Result<()> {
        let key = storage::Key::parse("some arbitrary key")
            .expect("could not set up test");
        let value = 21i32;
        let mut state = TestState::default();
        state.write(&key, value).expect("could not set up test");

        super::value(&mut state, &key, |v: &mut i32| *v *= 2)?;

        let new_val = state
            .read::<i32>(&key)?
            .ok_or_else(|| eyre!("no value found"))?;
        assert_eq!(new_val, 42);
        Ok(())
    }
}
