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
use rlp::RlpStream;

mod raw_transaction;

pub use self::raw_transaction::RawTransaction;

pub trait Transaction {
    fn transaction_type(&self) -> u8;
    fn chain_id(&self) -> u64;
    fn rlp(&self) -> RlpStream;

    fn signature(&self) -> EcdsaSig {
        // take the RlpStream from data()
        // compute the hash
        // return ecdsa_sign of hash
        unimplemented!()
    }

    fn sign(&self, private_key: &[u8]) -> Vec<u8> {
        // get the signature()
        // take the RlpStream from data()
        // append v, r, s
        let _sig = EcdsaSig::generate(&self.rlp().as_raw(), private_key, &self.chain_id());
        
        unimplemented!()
    }
}

pub struct EcdsaSig {
    v: u64,
    r: Vec<u8>,
    s: Vec<u8>,
}

impl EcdsaSig {
    pub fn generate(hash: &[u8], private_key: &[u8], chain_id: &u64) -> EcdsaSig {
        let s = Secp256k1::signing_only();
        let msg = Message::from_slice(hash).unwrap();
        let key = SecretKey::from_slice(private_key).unwrap();
        let (v, sig_bytes) = s.sign_ecdsa_recoverable(&msg, &key).serialize_compact();

        EcdsaSig {
            v: v.to_i32() as u64 + chain_id * 2 + 35,
            r: sig_bytes[0..32].to_vec(),
            s: sig_bytes[32..64].to_vec(),
        }
    }
}


