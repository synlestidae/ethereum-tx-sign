#![deny(warnings)]
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate num_traits;
extern crate rlp;
extern crate secp256k1;
extern crate tiny_keccak;
extern crate bytes;

#[cfg(test)]
extern crate ethereum_types;
#[cfg(test)]
extern crate hex;
#[cfg(test)]
extern crate serde_json;

use rlp::{RlpStream, Encodable};
use secp256k1::{Message, Secp256k1, SecretKey};
use tiny_keccak::{Hasher, Keccak};

/// Ethereum transaction
pub trait Transaction {
    /// [EIP-155](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-155.md) chain ID
    fn chain(&self) -> u64;

    /// Compute the unique transaction hash
    fn hash(&self) -> [u8; 32];

    /// Compute the [ECDSA](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm) for the transaction
    fn ecdsa(&self, private_key: &[u8]) -> EcdsaSig;

    /// Sign and encode this transaction using the given ECDSA signature.
    /// Signing is done in two steps. Example:
    /// ```
    /// use ethereum_tx_sign::{LegacyTransaction, Transaction};
    ///
    /// let tx = LegacyTransaction {
    ///     chain: 1,
    ///     nonce: 0,
    ///     to: Some([0x45; 20]),
    ///     value: 1000,
    ///     gas_price: 20 * 10u128.pow(9),
    ///     gas: 21000,
    ///     data: vec![]
    /// };
    /// let ecdsa = tx.ecdsa(&vec![0x35; 32]);
    /// let tx_bytes = tx.sign(&ecdsa);
    /// ```
    fn sign(&self, ecdsa: &EcdsaSig) -> Vec<u8>;

    /// Return the fields of the transaction as a list of RLP-encodable 
    /// parts. The parts must follow the order that they will be encoded,
    /// hashed, or signed.
    fn rlp_parts<'a>(&'a self) -> Vec<Box<dyn Encodable>>;
}

/// EIP-2718 Typed Transaction Envelope
pub trait TypedTransaction: Transaction {
    /// Returns the transaction type byte
    fn transaction_type(&self) -> u8;
}

pub struct FeeMarketTransaction {
    /// Chain ID
    pub chain: u64,
    pub nonce: u128,
    pub max_priority_fee_per_gas: u128,
    pub max_fee_per_gas: u128,
    pub gas_limit: u128,
    /// Destination address
    pub destination: Option<[u8; 20]>,
    pub amount: u128,
    pub data: Vec<u8>,
    // TODO: update access list to proper value
    pub access_list: Vec<u8>,
}

impl Transaction for FeeMarketTransaction {
    fn chain(&self) -> u64 {
        self.chain
    }

    fn hash(&self) -> [u8; 32] {
        unimplemented!()
    }
}

impl TypedTransaction for FeeMarketTransaction {
    fn transaction_type(&self) -> u8 { 2 }
}

/// Description of a Transaction, pending or in the chain.
#[derive(Debug, Default, Clone, PartialEq, Deserialize, Serialize)]
pub struct LegacyTransaction {
    /// Chain ID
    pub chain: u64,
    /// Nonce
    pub nonce: u128,
    /// Recipient (None when contract creation)
    pub to: Option<[u8; 20]>,
    /// Transfered value
    pub value: u128,
    /// Gas Price
    #[serde(rename = "gasPrice")]
    pub gas_price: u128,
    /// Gas amount
    pub gas: u128,
    /// Input data
    pub data: Vec<u8>,
}

impl Transaction for LegacyTransaction {
    fn chain(&self) -> u64 {
        self.chain
    }

    fn hash(&self) -> [u8; 32] {
        let rlp = self.rlp_parts();
        let mut rlp_stream = RlpStream::new();
        rlp_stream.begin_unbounded_list();
        for r in rlp.iter() {
            rlp_stream.append(r);
        }
        rlp_stream.append(&self.chain());
        rlp_stream.append_raw(&[0x80], 1);
        rlp_stream.append_raw(&[0x80], 1);
        rlp_stream.finalize_unbounded_list();
        keccak256_hash(&rlp_stream.out())
    }

    fn sign(&self, ecdsa: &EcdsaSig) -> Vec<u8> {
        let mut rlp_stream = RlpStream::new();
        let rlp = self.rlp_parts();
        rlp_stream.begin_unbounded_list();
        for r in rlp.iter() {
            rlp_stream.append(r);
        }
        match ecdsa {
            EcdsaSig { v, s, r } => {
                rlp_stream.append(v);
                rlp_stream.append(r);
                rlp_stream.append(s);
            }
        }

        rlp_stream.finalize_unbounded_list();

        return rlp_stream.out().to_vec();
    }

    fn ecdsa(&self, private_key: &[u8]) -> EcdsaSig {
        let hash = self.hash();

        EcdsaSig::generate(hash, private_key, self.chain())
    }

    fn rlp_parts<'a>(&'a self) -> Vec<Box<dyn Encodable>> {
        let to: Vec<u8> = match self.to {
            Some(ref to) => to.iter().cloned().collect(),
            None => vec![],
        };
        vec![
            Box::new(self.nonce),
            Box::new(self.gas_price),
            Box::new(self.gas),
            Box::new(to.clone()),
            Box::new(self.value),
            Box::new(self.data.clone())
        ]
    }
}

#[derive(Debug)]
pub struct EcdsaSig {
    v: u64,
    r: Vec<u8>,
    s: Vec<u8>,
}

impl EcdsaSig {
    pub fn generate(hash: [u8; 32], private_key: &[u8], chain_id: u64) -> EcdsaSig {
        let s = Secp256k1::signing_only();
        let msg = Message::from_slice(&hash).unwrap();
        let key = SecretKey::from_slice(private_key).unwrap();
        let (v, sig_bytes) = s.sign_ecdsa_recoverable(&msg, &key).serialize_compact();

        EcdsaSig {
            v: v.to_i32() as u64 + chain_id * 2 + 35,
            r: sig_bytes[0..32].to_vec(),
            s: sig_bytes[32..64].to_vec(),
        }
    }
}

pub fn keccak256_hash(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(bytes);
    let mut resp: [u8; 32] = Default::default();
    hasher.finalize(&mut resp);
    resp
}

#[cfg(test)]
mod test {
    use crate::{LegacyTransaction, Transaction};
    use ethereum_types::H256;
    use serde_json;
    use std::fs::File;
    use std::io::Read;

    #[test]
    fn test_signs_transaction_eth() {
        run_test("./test/test_txs.json");
    }

    #[test]
    fn test_signs_transaction_ropsten() {
        run_test("./test/test_txs_ropsten.json");
    }

    #[test]
    fn test_signs_tx_on_eip_spec() {
        let tx = LegacyTransaction {
            chain: 1,
            nonce: 9,
            gas_price: 20 * 10u128.pow(9),
            gas: 21000,
            to: Some([0x35; 20]),
            value: 10u128.pow(18),
            data: vec![],
        };

        let ecdsa = tx.ecdsa(&[0x46u8; 32]);
        let hash = hex::encode(tx.hash());
        let signed_data = hex::encode(tx.sign(&ecdsa));

        assert_eq!(
            hash,
            "daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53"
        );
        assert_eq!(ecdsa.v, 37);
        assert_eq!(signed_data, "f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83");
    }

    #[derive(Serialize, Deserialize, Clone)]
    struct Signing {
        signed: Vec<u8>,
        private_key: H256,
    }

    fn run_test(path: &str) {
        let mut file = File::open(path).unwrap();
        let mut f_string = String::new();
        file.read_to_string(&mut f_string).unwrap();
        let txs: Vec<(LegacyTransaction, Signing)> = serde_json::from_str(&f_string).unwrap();
        for (tx, signed) in txs.into_iter() {
            let rtx: LegacyTransaction = tx.into();
            assert_eq!(
                signed.signed,
                rtx.sign(&rtx.ecdsa(signed.private_key.as_ref()))
            );
        }
    }
}
