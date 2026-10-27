- Before starting, the ledger now compacts the diffs column family when it
  has at least `NAMADA_COMPACT_DIFFS_ON_BOOT_MIN_FILES` table files (10000 by
  default, 0 to always compact). This cleans up the small files accumulated
  by existing nodes. ([\#5065](https://github.com/namada-net/namada/pull/5065))
