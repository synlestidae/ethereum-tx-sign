# ethereum-tx-sign

[![Build Status](https://travis-ci.com/synlestidae/ethereum-tx-sign.svg?branch=master)](https://travis-ci.com/synlestidae/ethereum-tx-sign)

Allows you to sign Ethereum transaction offline.

```
  const ETH_CHAIN_ID: u32 = 1;

  let tx = RawTransaction {
    ...
  }

  let raw_rlp_bytes = tx.sign(&private_key, ETH_CHAIN_ID);

```

That's it!
