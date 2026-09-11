- Fixed multiple attack vectors that could drain IBC and PoS escrow
  accounts through crafted transactions. The IBC VP now rejects escrow
  balance changes not reproduced by its pseudo-execution, the PoS VP
  rejects unauthorized debits of the PoS escrow, and the Multitoken VP
  tightens balance change rules for protocol-owned accounts.
  Additionally, middleware-only IBC state changes are now rejected to
  prevent overflow-receive attacks.
  ([\#5036](https://github.com/namada-net/namada/pull/5036))
