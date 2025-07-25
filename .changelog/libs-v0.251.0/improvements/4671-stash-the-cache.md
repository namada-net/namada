 - Conversions are cached when performing Masp balance queries. Futhermore, the decoded asset type cache is used more
 - effectively. Care must be taken to clear the masp conversions cache on load if the masp epoch has changed. If the 
 - masp epoch changes during a balance query, it may produce invalid output. However, repeating the query after the epoch
 - has completed will yield the correct result. The new cache resides on the shielded wallet, so a migration has been added.

 ([\#4671](https://github.com/anoma/namada/pull/4671))