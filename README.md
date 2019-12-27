# ethereum-tx-sign

[![Build Status](https://travis-ci.com/synlestidae/ethereum-tx-sign.svg?branch=master)](https://travis-ci.com/synlestidae/ethereum-tx-sign)

Allows you to sign Ethereum transactions offline.

```rust
// 1 mainnet, 3 ropsten
const ETH_CHAIN_ID: u32 = 3;

let tx = ethereum_tx_sign::RawTransaction {
    nonce: web3::types::U256::from(0),
    to: Some(web3::types::H160::zero()),
    value: web3::types::U256::zero(),
    gas_price: web3::types::U256::from(10000),
    gas: web3::types::U256::from(21240),
    data: hex::decode(
        "7f7465737432000000000000000000000000000000000000000000000000000000600057"
    ).unwrap(),
};

let mut data: [u8; 32] = Default::default();
data.copy_from_slice(&hex::decode(
    "2a3526dd05ad2ebba87673f711ef8c336115254ef8fcd38c4d8166db9a8120e4"
).unwrap());
let private_key = web3::types::H256(data);
let raw_rlp_bytes = tx.sign(&private_key, &ETH_CHAIN_ID);

let result = "f885808227108252f894000000000000000000000000000000000000000080a\
    47f746573743200000000000000000000000000000000000000000000000000\
    00006000572aa0b4e0309bc4953b1ca0c7eb7c0d15cc812eb4417cbd759aa09\
    3d38cb72851a14ca036e4ee3f3dbb25d6f7b8bd4dac0b4b5c717708d20ae6ff\
    08b6f71cbf0b9ad2f4";
assert_eq!(result, hex::encode(raw_rlp_bytes));
```

That's it!
