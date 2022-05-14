# Test Data Generator

This directory is a Node application that can generate test data for you.
It depends on [@ethereumjs/tx](https://www.npmjs.com/package/@ethereumjs/tx) to sign
transactions given raw transaction data and a private key.
This makes @ethereumjs/tx a reference implementation for ethereum-tx-sign.
Currently it will only generate random transaction data.

To get started first install dependencies:

```bash
npm install
```

Then run it to generate a random transaction

```bash
node index.js --random --number -1
```
