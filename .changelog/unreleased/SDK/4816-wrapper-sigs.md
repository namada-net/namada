- Reworked SDK wrapping and signatures, including some breaking changes.
  More specifically:
  - The wrapper arguments have been extracted into a separate type and their
    presence signals the need to wrap the tx
  - The dump and dry-run arguments have been turned into enumerations
  - The wrapper signer data has been removed from SigningTxData and moved into
    SigningWrapperData
  - Simplified the interface of aux_signing_data
  - Removed redundant dispatcher functions
  - Prevent casting from a wrapped to a raw transaction type
  - Prevent submitting an unwrapped transaction
  - Avoided passing the MASP internal address as a transaction's owner
  - Updated the interface of build_batch
  - Removed the owner for reveal_pk
  ([\#4816](https://github.com/anoma/namada/pull/4816))