#![deny(warnings)]
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate rlp;
extern crate secp256k1;
extern crate tiny_keccak;
extern crate num_traits;

#[cfg(test)]
extern crate ethereum_types;
#[cfg(test)]
extern crate serde_json;

use secp256k1::{SecretKey, Message, Secp256k1};
use tiny_keccak::{Keccak, Hasher};
use rlp::RlpStream;

pub trait Transaction {
    fn chain(&self) -> u64;
    fn hash(&self) -> [u8; 32];
    fn encode(&self, private_key: &[u8]) -> Vec<u8>;
    fn ecdsa(&self, private_key: &[u8]) -> EcdsaSig;
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

impl LegacyTransaction {
    fn rlp(&self) -> RlpStream {
        let mut rlp = RlpStream::new();
        let to: &[u8] = &self.to.unwrap();
        rlp.begin_unbounded_list();
        rlp.append(&self.nonce);
        rlp.append(&self.gas_price);
        rlp.append(&self.gas);
        rlp.append(&to);
        rlp.append(&self.value);
        rlp.append(&self.data);
        // the list is deliberately left incomplete
        rlp
    }
}

impl Transaction for LegacyTransaction {
    fn chain(&self) -> u64 {
        self.chain
    }

    fn hash(&self) -> [u8; 32] {
        let mut hash = self.rlp();
        hash.append(&self.chain());
        hash.append_raw(&[0x80], 1);
        hash.append_raw(&[0x80], 1);
        hash.finalize_unbounded_list();
        keccak256_hash(&hash.out())
    }

    fn encode(&self, private_key: &[u8]) -> Vec<u8> {
        let mut rlp_stream = self.rlp();

        match self.ecdsa(private_key) {
            EcdsaSig { v, s, r} => {
                rlp_stream.append(&v); 
                rlp_stream.append(&s); 
                rlp_stream.append(&r); 
            }
        }

        rlp_stream.finalize_unbounded_list();

        return rlp_stream.out().to_vec()
    }

    fn ecdsa(&self, private_key: &[u8]) -> EcdsaSig {
        let hash = self.hash();

        EcdsaSig::generate(hash, private_key, self.chain())
    }
}

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
    use crate::{Transaction, LegacyTransaction};
    use serde_json;
    use std::fs::File;
    use std::io::Read;
    use ethereum_types::H256;

    #[test]
    fn test_signs_transaction_eth() {
        run_test("./test/test_txs.json");
    }

    #[test]
    fn test_signs_transaction_ropsten() {
        //run_test("./test/test_txs_ropsten.json", 3);
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
            assert_eq!(signed.signed, rtx.encode(signed.private_key.as_ref()));
        }
    }
}
