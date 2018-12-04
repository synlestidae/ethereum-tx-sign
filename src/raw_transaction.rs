use ethereum_types::{H160, H256, U256};
use rlp::RlpStream;
use tiny_keccak::keccak256;
use secp256k1::key::SecretKey;
use secp256k1::Message;
use secp256k1::Secp256k1;

/// Description of a Transaction, pending or in the chain.
#[derive(Debug, Default, Clone, PartialEq, Deserialize, Serialize)]
pub struct RawTransaction {
    /// Nonce
    pub nonce: U256,
    /// Recipient (None when contract creation)
    pub to: Option<H160>,
    /// Transfered value
    pub value: U256,
    /// Gas Price
    #[serde(rename = "gasPrice")]
    pub gas_price: U256,
    /// Gas amount
    pub gas: U256,
    /// Input data
    pub data: Vec<u8>
}

impl RawTransaction {
    /// Signs and returns the RLP-encoded transaction
    pub fn sign(&self, private_key: &H256,CHAIN_ID : &u8) -> Vec<u8> {
        let hash = self.hash(*CHAIN_ID);
        let sig = ecdsa_sign(&hash, &private_key.0, &CHAIN_ID);
        let mut tx = RlpStream::new(); 
        tx.begin_unbounded_list();
        self.encode(&mut tx);
        tx.append(&sig.v); 
        tx.append(&sig.r); 
        tx.append(&sig.s); 
        tx.complete_unbounded_list();
        tx.out()
    }

    fn hash(&self, CHAIN_ID: u8) -> Vec<u8> {
        let mut hash = RlpStream::new(); 
        hash.begin_unbounded_list();
        self.encode(&mut hash);
        hash.append(&mut vec![CHAIN_ID]);
        hash.append(&mut U256::zero());
        hash.append(&mut U256::zero());
        hash.complete_unbounded_list();
        keccak256_hash(&hash.out())
    }

    fn encode(&self, s: &mut RlpStream) {
        s.append(&self.nonce);
        s.append(&self.gas_price);
        s.append(&self.gas);
        if let Some(ref t) = self.to {
            s.append(t);
        } else {
            s.append(&vec![]);
        }
        s.append(&self.value);
        s.append(&self.data);
    }
}

fn keccak256_hash(bytes: &[u8]) -> Vec<u8> {
    keccak256(bytes).into_iter().cloned().collect()
}

fn ecdsa_sign(hash: &[u8], private_key: &[u8], CHAIN_ID: &u8) -> EcdsaSig {
    let s = Secp256k1::signing_only();
    let msg = Message::from_slice(hash).unwrap();
    let key = SecretKey::from_slice(&s, private_key).unwrap();
    let (v, sig_bytes) = s.sign_recoverable(&msg, &key).serialize_compact(&s);

    println!("V m8 {:?}", v);

    EcdsaSig {
        v: vec![v.to_i32() as u8 + CHAIN_ID * 2 + 35],
        r: sig_bytes[0..32].to_vec(),
        s: sig_bytes[32..64].to_vec(),
    }
}

pub struct EcdsaSig {
    v: Vec<u8>,
    r: Vec<u8>,
    s: Vec<u8>
}

mod test {

    #[test]
    fn test_signs_transaction() {
        use std::io::Read;
        use std::fs::File;
        use ethereum_types::*;
        use raw_transaction::RawTransaction;
        use serde_json;

        #[derive(Deserialize)]
        struct Signing {
            signed: Vec<u8>,
            private_key: H256 
        }

        let mut file = File::open("./test/test_txs.json").unwrap();
        let mut f_string = String::new();
        file.read_to_string(&mut f_string).unwrap();
        let txs: Vec<(RawTransaction, Signing)> = serde_json::from_str(&f_string).unwrap();

        for (tx, signed) in txs.into_iter() {
            assert_eq!(signed.signed, tx.sign(&signed.private_key));
        }
    }
}
