- On every new epoch, compact the diffs column family of the epoch that just
  ended. Since diffs keys are prefixed with the block height, leveled
  compaction only moved the small table files written on every flush down the
  levels without merging them, so their number grew without bound (over a
  million files on mainnet nodes).
  ([\#5064](https://github.com/namada-net/namada/pull/5064))
