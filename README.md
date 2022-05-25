# ethereum-tx-sign

This is a Rust library that allows you to create and sign Ethereum transactions.
It can work completely offline and does not require external software such as Web3.
Legacy and access list transactions are supported ([EIP-155](https://eips.ethereum.org/EIPS/eip-155) and [EIP-2930](https://eips.ethereum.org/EIPS/eip-2930) respectively).

[![Build Status](https://travis-ci.com/synlestidae/ethereum-tx-sign.svg?branch=master)](https://travis-ci.com/synlestidae/ethereum-tx-sign)

## Usage

Native Rust types are used for transaction fields:

```rust
use ethereum_tx_sign::LegacyTransaction;

let new_transaction = LegacyTransaction {
    chain: 1,
    nonce: 0,
    to: Some([0; 20]),
    value: 1675538,
    gas_price: 250,
    gas: 21000,
    data: vec![/* contract code or other data */],
}
```

Signing a transaction is performed in two steps. First you get the [ECDSA](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm) using your private key. Then sign the transaction using it.

```rust
let ecdsa = new_transaction.sign(&private_key_32_bytes);
let transaction_bytes = new_transaction.sign(&ecdsa);
```

`transaction_bytes` is now a `Vec<u8>` containing the serialized transaction ready to be sent.

[See the Rust documentation on docs.rs for more information and examples](https://docs.rs/ethereum-tx-sign/latest/ethereum_tx_sign/).

## Contributing

This repository accepts contributions. Do not hesitate to raise an issue for any queries, issues, or suggestions. Pull requests must meet the following criteria:

1. Target branch is development.
1. It fixes a bug, supports a new EIP, or improves the library for >50% of all users.
1. You have 95% unit test coverage and all tests pass.
1. [Semantic versioning](https://semver.org/) is followed. 
1. Changes introduce breaking changes only as last resort.

To generate reference test data, see [test/generate](test/generate).

[@synlestidae](https://github.com/synlestidae/) is the repository owner and will oversee
all contributions.

## Acknowledgements

Thank you to these people for their contributions:

* tritone11
* rodoufuT
* victor-wei126
