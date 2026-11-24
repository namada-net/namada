- The PoS VP now rejects any transaction that leaves a new validator, or a
  validator whose consensus key changed, with a consensus key that isn't
  Ed25519 at the pipeline epoch, as is already required when changing a
  consensus key. CometBFT only accepts Ed25519 validator keys and rejects
  any validator set update with another key type, so a new validator with
  such a key would halt the chain once it entered the consensus set.
