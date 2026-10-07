- Fixed the IBC VP to reject (NFT) transfers whose packet sender is an
  internal address, such as the IBC escrow. Previously, such transfers
  were a no-op for the escrow balance while still writing the withdraw
  counter and packet commitment, allowing vouchers minted by the
  counterparty to be returned in exchange for genuine escrowed tokens,
  with rate limits skipped.
  ([\#5052](https://github.com/namada-net/namada/pull/5052))
