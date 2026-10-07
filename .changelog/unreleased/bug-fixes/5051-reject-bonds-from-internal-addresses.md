- Fixed the PoS VP to reject bonds whose source is an internal address.
  Previously, a bond naming the PoS internal address as the source was
  accepted: the token transfer was a no-op, while the bond, validator
  deltas and total stake were still written, creating unbacked stake.
  ([\#5051](https://github.com/namada-net/namada/pull/5051))
