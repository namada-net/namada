- Closes #4714
  - When dry-running, dummy signatures are used in
    txs
  - Validation does not perform signature checks when dry-running
  
I have tested that the gas estimation hasn't changed between dry-running
with signatures and with dummies. It is curious however that in both cases there is a small discrepancy between dry-running and the actual tx.
([\#4714](https://github.com/namada-net/namada/issues/4714))