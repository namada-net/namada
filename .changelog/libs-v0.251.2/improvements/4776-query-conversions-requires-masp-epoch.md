- Querying the conversion state becomes more difficult as nodes progress
  to higher and higher epochs. For instance, on a mainnet clone running on
  accelerated epochs, client queries for conversions always timeout (even after
  modifying timeout_broadcast_tx_commit) when the node goes beyond a certain
  MASP epoch. This happens because the conversion state grows linearly with
  the MASP epoch counter. This PR attempts to address this problem by making
  the conversions RPC endpoint require that clients specify the MASP epoch
  they want conversions from. This implies two things: first the size of the
  response from the conversions RPC endpoint should now be constant (equal to
  the number of tokens in the shielded rewards program), and second a client
  requiring all conversions now has to do a separate query for each MASP epoch.
  ([\#4776](https://github.com/namada-net/namada/pull/4776))