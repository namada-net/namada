# Genesis templates

An example setup with a single validator used to run a localnet can be found in [localnet](localnet/README.md) directory.

[Starter templates](starter/README.md) can be used to configure new networks.

The required genesis templates to setup a network are:

- [`validity-predicates.toml`](#validity-predicates)
- [`tokens.toml`](#tokens)
- [`balances.toml`](#balances)
- [`parameters.toml`](#parameters)
- [`transactions.toml`](#transactions)

## Validity predicates

The [validity-predicates.toml file](validity-predicates) contains definitions of WASM validity predicates, which can be used in the [tokens](#tokens), [parameters](#parameters) and [transactions.toml](#transactions) files as validity predicates of established accounts.

## Tokens

The [tokens.toml file](tokens.toml) contains tokens with their aliases and validity predicates.

## Balances

The [balances.toml file](balances.toml) contains token balances associated with the public keys.

## Parameters

The [parameters.toml file](parameters.toml) contains the general chain parameters, PoS and governance parameters.

## Transactions

The [transactions.toml file](transactions.toml) contains any transactions that can be applied at genesis. These are:

### Genesis tx `established_account`

An established account with some `alias`, a validity predicate `vp` and optionally a `public_key`. When a public key is used, the transaction must be [signed](#signing-genesis-txs) with it to authorize its use.

An unsigned `established_account` tx example:

```toml
[[established_account]]
alias = "Albert" # Aliases are case-insensitive
vp = "vp_user"
public_key = "tpknam1qz0aphcsrw37j8fy742cjwhphu9jwx7esd3ad4xxtxrkwv07ff63we33t3r"
```

### Genesis tx `validator_account`

A validator account with some `alias`, a validity predicate `vp`, various keys and validator variables. Public keys used in the transaction must also [sign](#signing-validator-genesis-txs) the transaction to authorize their use.

An unsigned `validator_account` tx example:

```toml
[[validator_account]]
alias = "validator-0"
vp = "vp_user"
commission_rate = "0.05"
max_commission_rate_change = "0.01"
net_address = "127.0.0.1:27656"
account_key = "tpknam1qzjnu45v9uvvz4shwkxrgq44l7l4ncs0ryt9mwt7973fdjvm76tgkulmxll"
consensus_key = "tpknam1qp4dcws0fthlrt69erz854efxxtxvympw9m3npy2w8rphqgxu2ufcluhhva"
protocol_key = "tpknam1qqwg6uwuxn70spl9x377v0q6fzr6d29gpkdfc0tmp8uj97p5awnukum3d4q"
tendermint_node_key = "tpknam1qzmajsm6a5uamaq7el4kkp6txe9jt0ld3q0jy0er7cuz0u0k2yck64je49d"
dkg_key = "dpknam1vqqqqqqzlgrsdkkjc0yg842xqkffy7g2vwvx3x8389ydprz2qwncruzxr8cg8u939z4yy76wkx6uwfe7qur95yrftsd0r8lu0ayhu4zqsrkf9em3n5zpm7jkcmjtg0a24h2fa5gejvt0ywddwc6xa72f3z8czkcwrz38vq"
```

### Genesis tx `transfer`

A transfer can only be applied from one of the keys used in [Balances file](#balances) as the `source`. The target may be another key or an alias of an account to be created with `established_account` or `validator_account` genesis transactions.

An unsigned `transfer` tx example:

```toml
[[transfer]]
token = "NAM"
source = "tpknam1qz0aphcsrw37j8fy742cjwhphu9jwx7esd3ad4xxtxrkwv07ff63we33t3r"
target = "albert"
amount = 1_000_000
```

### Genesis tx `bond`

A bond may be either a self-bond when the `source` is the same as `validator` or a delegation otherwise.

An example of an unsigned delegation `bond` tx from `established_account` with alias "albert":

```toml
[[bond]]
source = "albert"
validator = "validator-0" # There must be a `validator_account` tx with this alias
amount = 20_000 # in native token NAM
```

For a delegation `bond` tx from an implicit account, one can use a public key as the source:

```toml
[[bond]]
source = "tpknam1qz0aphcsrw37j8fy742cjwhphu9jwx7esd3ad4xxtxrkwv07ff63we33t3r"
validator = "validator-0"
amount = 20_000 # in native token NAM
```

Note that for a delegation, the source key must have the sufficient balance assigned in the Balances file.

An unsigned self-`bond` tx example:

```toml
[[bond]]
source = "validator-0"
validator = "validator-0"
amount = 90_000_000 # The validator must have this amount of NAM available in account
```

### Signing genesis txs

To sign genesis transactions, the data is borsh-encoded into a `Tx` `data` field. For `code` an empty vec is used and for the timestamp we use the minimum UTC timestamp. The transaction must be constructed in exactly the same way to verify the signatures, which is being done by the ledger when we're initializing the genesis. Any transaction that has invalid signature or cannot be applied for any other reason, such as insufficient funds may fail at genesis initialization and the chain will continue to be initialized without it.

For non-validator transactions, a helper tool for producing signatures for transactions can be used with e.g.:

```shell
namada client utils \
  sign-genesis-txs \
  --path "unsigned-tx.toml" \
  --output "signed-txs.toml"
```

For validator txs, see [Signing validator genesis txs](#signing-validator-genesis-txs) below.

#### Signing validator genesis txs

To generate validator wallet and sign validator transactions, run e.g.:

```shell
namadac utils \
  init-genesis-validator \
  --source validator-0-key \
  --alias validator-0 \
  --net-address "127.0.0.1:27656" \
  --commission-rate 0.05 \
  --max-commission-rate-change 0.01 \
  --transfer-from-source-amount 1_000_000_000 \
  --self-bond-amount 900_000_000 \
  --unsafe-dont-encrypt
```

The `--source` key alias must have already have native token `NAM` in the [Balances files](#balances) and the balance must be greater than or equal to `--transfer-from-source-amount`.

The `--self-bond-amount` must be lower than or equal to `--transfer-from-source-amount`, but we recommend to keep at least some tokens in the validator account for submitting validator transactions to be able to pay for fees and gas.

This command will generate a validator pre-genesis wallet and transactions file containing signed `validator_account`, `transfer` and `bond` txs.
