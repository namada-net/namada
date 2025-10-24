//! Primitives that facilitate keeping track of the number
//! of bytes utilized by some Tendermint consensus round's proposal.
//!
//! This is important, because Tendermint places an upper bound
//! on the size of a block, rejecting blocks whose size exceeds
//! the limit stated in [`RequestPrepareProposal`].
//!
//! The code in this module doesn't perform any deserializing to
//! verify if we are, in fact, allocating space for the correct
//! kind of tx for the current [`BlockAllocator`] state. It
//! is up to `PrepareProposal` to dispatch the correct kind of tx
//! into the current state of the allocator.
//!
//! # How space is allocated
//!
//! In the current implementation, we allot space for user submitted txs until the block is filled.
//!
//! # How gas is allocated
//!
//! Gas is only relevant to non-protocol txs. Every such tx defines its
//! gas limit. We take this entire gas limit as the amount of gas requested by
//! the tx.

// TODO(namada#3250): what if a tx has a size greater than the threshold
// for its bin? how do we handle this? if we keep it in the mempool
// forever, it'll be a DoS vec, as we can make nodes run out of
// memory! maybe we should allow block decisions for txs that are
// too big to fit in their respective bin? in these special block
// decisions, we would only decide proposals with "large" txs??

use std::marker::PhantomData;

use namada_sdk::parameters;
use namada_sdk::state::{self, WlState};

#[allow(unused_imports)]
use crate::tendermint_proto::abci::RequestPrepareProposal;

/// Block allocation failure status responses.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum AllocFailure {
    /// The transaction can only be included in an upcoming block.
    ///
    /// We return the resource left in the tx bin for logging purposes.
    Rejected { bin_resource_left: u64 },
    /// The transaction would overflow the allotted bin resource,
    /// therefore it needs to be handled separately.
    ///
    /// We return the resource allotted to the tx bin for logging purposes.
    OverflowsBin { bin_resource: u64 },
}

/// The block resources that need to be allocated
pub struct BlockResources<'tx> {
    tx: &'tx [u8],
    gas: u64,
}

impl<'tx> BlockResources<'tx> {
    /// Generates a new block resource instance
    pub fn new(tx: &'tx [u8], gas: u64) -> Self {
        Self { tx, gas }
    }
}

/// Marker type for the block space
#[derive(Debug, Default, Clone, Copy)]
pub struct BlockSpace;
/// Marker type for the block gas
#[derive(Debug, Default, Clone, Copy)]
pub struct BlockGas;

pub trait Resource {
    type Input<'r>;

    fn usage_of(input: Self::Input<'_>) -> u64;
}

impl Resource for BlockSpace {
    type Input<'r> = &'r [u8];

    fn usage_of(input: Self::Input<'_>) -> u64 {
        input.len() as u64
    }
}

impl Resource for BlockGas {
    type Input<'r> = u64;

    fn usage_of(input: Self::Input<'_>) -> u64 {
        input
    }
}

/// Allotted resources for a batch of transactions in some proposed block.
///
/// We keep track of the current space utilized by transactions.
///
/// Gas usage of normal txs is also tracked.
#[derive(Debug, Default)]
pub struct BlockAllocator {
    /// The current space and gas utilized by normal user transactions.
    normal_txs: NormalTxsBins,
}

impl<D, H> From<&WlState<D, H>> for BlockAllocator
where
    D: 'static + state::DB + for<'iter> state::DBIter<'iter>,
    H: 'static + state::StorageHasher,
{
    #[inline]
    fn from(storage: &WlState<D, H>) -> Self {
        Self::init(
            parameters::read_max_proposal_bytes(storage)
                .expect("Must be able to read ProposalBytes from storage")
                .get(),
            parameters::get_max_block_gas(storage).unwrap(),
        )
    }
}

impl BlockAllocator {
    /// Construct a new [`BlockAllocator`], with an upper bound
    /// on the max size of all txs in a block defined by Tendermint and an upper
    /// bound on the max gas in a block.
    #[inline]
    pub fn init(
        tendermint_max_block_space_in_bytes: u64,
        max_block_gas: u64,
    ) -> Self {
        Self {
            normal_txs: NormalTxsBins {
                space: TxBin::init(tendermint_max_block_space_in_bytes),
                gas: TxBin::init(max_block_gas),
            },
        }
    }

    #[inline]
    pub fn try_alloc(
        &mut self,
        resource_required: BlockResources<'_>,
    ) -> Result<(), AllocFailure> {
        self.normal_txs.space.try_dump(resource_required.tx)?;
        self.normal_txs.gas.try_dump(resource_required.gas)
    }
}

/// Allotted resource for a batch of transactions of the same kind in some
/// proposed block.
///
/// At the moment this is used to track two resources of the block: space and
/// gas. Space is measured in bytes while gas in gas units.
#[derive(Debug, Copy, Clone, Default)]
pub struct TxBin<R: Resource> {
    /// The current resource utilization of the batch of transactions.
    occupied: u64,
    /// The maximum resource amount the batch of transactions may occupy.
    allotted: u64,
    /// The resource that this bin is tracking
    _resource: PhantomData<R>,
}

impl<R: Resource> TxBin<R> {
    /// Return the amount of resource left in this [`TxBin`].
    #[inline]
    pub fn resource_left(&self) -> u64 {
        self.allotted
            .checked_sub(self.occupied)
            .expect("Shouldn't underflow")
    }

    /// Construct a new [`TxBin`], with a capacity of `max_capacity`.
    #[inline]
    pub fn init(max_capacity: u64) -> Self {
        Self {
            allotted: max_capacity,
            occupied: 0,
            _resource: PhantomData,
        }
    }

    /// Shrink the allotted resource of this [`TxBin`] to whatever
    /// amount is currently being utilized.
    #[inline]
    pub fn shrink_to_fit(&mut self) {
        self.allotted = self.occupied;
    }

    /// Try to dump a new transaction into this [`TxBin`].
    ///
    /// Signal the caller if the tx requires more resource than its max
    /// allotted.
    pub fn try_dump(
        &mut self,
        resource: R::Input<'_>,
    ) -> Result<(), AllocFailure> {
        let resource = R::usage_of(resource);
        if resource > self.allotted {
            let bin_size = self.allotted;
            return Err(AllocFailure::OverflowsBin {
                bin_resource: bin_size,
            });
        }
        let occupied = self
            .occupied
            .checked_add(resource)
            .expect("Shouldn't overflow");
        if occupied <= self.allotted {
            self.occupied = occupied;
            Ok(())
        } else {
            let bin_resource_left = self.resource_left();
            Err(AllocFailure::Rejected { bin_resource_left })
        }
    }
}

#[derive(Debug, Default)]
pub struct NormalTxsBins {
    space: TxBin<BlockSpace>,
    gas: TxBin<BlockGas>,
}

impl NormalTxsBins {
    pub fn new(max_gas: u64) -> Self {
        Self {
            space: TxBin::default(),
            gas: TxBin::init(max_gas),
        }
    }

    pub fn try_dump(&mut self, tx: &[u8], gas: u64) -> Result<(), String> {
        self.space.try_dump(tx).map_err(|e| match e {
            AllocFailure::Rejected { .. } => {
                "No more space left in the block for normal txs".to_string()
            }
            AllocFailure::OverflowsBin { .. } => "The given wrapper tx is \
                                                  larger than the remaining \
                                                  available block space"
                .to_string(),
        })?;
        self.gas.try_dump(gas).map_err(|e| match e {
            AllocFailure::Rejected { .. } => {
                "No more gas left in the block for wrapper txs".to_string()
            }
            AllocFailure::OverflowsBin { .. } => {
                "The given wrapper tx requires more gas than available to the \
                 entire block"
                    .to_string()
            }
        })
    }
}

pub mod threshold {
    //! Transaction allotment thresholds.

    use num_rational::Ratio;

    /// Threshold over a portion of block space.
    #[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
    pub struct Threshold(Ratio<u64>);

    impl Threshold {
        /// Return a new [`Threshold`].
        const fn new(numer: u64, denom: u64) -> Self {
            // constrain ratio to a max of 1
            let numer = if numer > denom { denom } else { numer };
            Self(Ratio::new_raw(numer, denom))
        }

        /// Return a [`Threshold`] over some free space.
        pub fn over(self, free_space_in_bytes: u64) -> u64 {
            use num_traits::ops::checked::CheckedMul;
            (self
                .0
                .checked_mul(&free_space_in_bytes.into())
                .expect("Must not overflow"))
            .to_integer()
        }
    }

    /// Divide free space in half.
    pub const ONE_HALF: Threshold = Threshold::new(1, 2);
}

#[allow(clippy::arithmetic_side_effects, clippy::cast_possible_truncation)]
#[cfg(test)]
mod tests {

    use assert_matches::assert_matches;
    use proptest::prelude::*;

    use super::*;
    use crate::shell::abci::TxBytes;

    /// Proptest generated txs.
    #[derive(Debug)]
    struct PropTx {
        tendermint_max_block_space_in_bytes: u64,
        max_block_gas: u64,
        normal_txs: Vec<TxBytes>,
    }

    proptest! {
        /// Check if we reject a tx when its respective bin
        /// capacity has been reached on a [`BlockAllocator`].
        #[test]
        fn test_reject_tx_on_bin_cap_reached(max in prop::num::u64::ANY) {
            proptest_reject_tx_on_bin_cap_reached(max)
        }

        /// Test that dumping txs whose total combined size
        /// is less than the bin cap does not fill up the bin.
        #[test]
        fn test_tx_dump_doesnt_fill_up_bin(args in arb_transactions()) {
            proptest_tx_dump_doesnt_fill_up_bin(args)
        }
    }

    /// Implementation of [`test_reject_tx_on_bin_cap_reached`].
    fn proptest_reject_tx_on_bin_cap_reached(
        tendermint_max_block_space_in_bytes: u64,
    ) {
        let mut bins =
            BlockAllocator::init(tendermint_max_block_space_in_bytes, 1_000);

        // fill the entire bin of protocol txs
        bins.normal_txs.space.occupied = bins.normal_txs.space.allotted;

        // make sure we can't dump any new protocol txs in the bin
        assert_matches!(
            bins.try_alloc(BlockResources::new(b"arbitrary tx bytes", 0)),
            Err(AllocFailure::Rejected { .. })
        );

        // Reset space bin
        bins.normal_txs.space.occupied = 0;
        // Fill the entire gas bin
        bins.normal_txs.gas.occupied = bins.normal_txs.gas.allotted;

        // Make sure we can't dump any new wrapper txs in the bin
        assert_matches!(
            bins.try_alloc(BlockResources::new(b"arbitrary tx bytes", 1)),
            Err(AllocFailure::Rejected { .. })
        )
    }

    /// Implementation of [`test_tx_dump_doesnt_fill_up_bin`].
    fn proptest_tx_dump_doesnt_fill_up_bin(args: PropTx) {
        let PropTx {
            tendermint_max_block_space_in_bytes,
            max_block_gas,
            normal_txs,
        } = args;

        // produce new txs until the moment we would have
        // filled up the bins.
        //
        // iterate over the produced txs to make sure we can keep
        // dumping new txs without filling up the bins

        let mut bins = BlockAllocator::init(
            tendermint_max_block_space_in_bytes,
            max_block_gas,
        );
        let mut new_size = bins.normal_txs.space.allotted;
        let mut decrypted_txs = vec![];
        for tx in normal_txs {
            let bin = bins.normal_txs.space;
            if (new_size + tx.len() as u64) < bin.allotted {
                new_size += tx.len() as u64;
                decrypted_txs.push(tx);
            } else {
                break;
            }
        }
        for tx in decrypted_txs {
            assert!(bins.try_alloc(BlockResources::new(&tx, 0)).is_ok());
        }
    }

    prop_compose! {
        /// Generate arbitrarily sized txs of different kinds.
        fn arb_transactions()
            // create base strategies
            (
                (tendermint_max_block_space_in_bytes, max_block_gas,
                 decrypted_tx_max_bin_size) in arb_max_bin_sizes(),
            )
            // compose strategies
            (
                tendermint_max_block_space_in_bytes in Just(tendermint_max_block_space_in_bytes),
                max_block_gas in Just(max_block_gas),
                normal_txs in arb_tx_list(decrypted_tx_max_bin_size),
            )
            -> PropTx {
                PropTx {
                    tendermint_max_block_space_in_bytes,
                    max_block_gas,
                    normal_txs: normal_txs.into_iter().map(prost::bytes::Bytes::from).collect(),
                }
            }
    }

    /// Return random bin sizes for a [`BlockAllocator`].
    fn arb_max_bin_sizes() -> impl Strategy<Value = (u64, u64, usize)> {
        const MAX_BLOCK_SIZE_BYTES: u64 = 1000;
        (1..=MAX_BLOCK_SIZE_BYTES).prop_map(
            |tendermint_max_block_space_in_bytes| {
                (
                    tendermint_max_block_space_in_bytes,
                    tendermint_max_block_space_in_bytes,
                    threshold::ONE_HALF
                        .over(tendermint_max_block_space_in_bytes)
                        as usize,
                )
            },
        )
    }

    /// Return a list of txs.
    fn arb_tx_list(max_bin_size: usize) -> impl Strategy<Value = Vec<Vec<u8>>> {
        const MAX_TX_NUM: usize = 64;
        let tx = prop::collection::vec(prop::num::u8::ANY, 0..=max_bin_size);
        prop::collection::vec(tx, 0..=MAX_TX_NUM)
    }
}
