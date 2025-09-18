- Modified the protocol logic of fees so that only the tip is sent to the
  block proposer. The base fee is instead burnt if fees are paid with the
  native token or sent to an internal account in case of a foreign token.
  ([\#4644](https://github.com/anoma/namada/pull/4644))