use num_traits::int;
use rlp::RlpStream;
use secp256k1::{SecretKey, Message, Secp256k1};
use tiny_keccak::{Hasher, Keccak};

pub struct Transaction {
    txn_type: u8,
    txn_payload: TransactionType,
}

impl Transaction {
    pub fn sign(&self, private_key: &[u8]) -> Vec<u8> {
        // signs and returns the encoded txn
    }
}

pub enum Transaction {
    FeeMarketEIP1559Txn(EIP1559Txn),
    AccessListEIP2930Txn(EIP2930Txn),
    // aka, LegacyTxn
    RawTransaction(RawTransaction),
}

struct EIP1559Txn {
    chain_id: u8,
    nonce: u128,
    max_priority_fee_per_gas: u128,
    max_fee_per_gas: u128,
    gas_limit: u128,
    destination: [u8; 20],
    amount: u128,
    data: Vec<u8>,
    access_list: Vec<u8>,
    signature_y_parity: bool,
    signature_r: u128,
    signature_s: u128,
}

struct EIP2930Txn {

}

/// Description of a Transaction, pending or in the chain.
#[derive(Debug, Default, Clone, PartialEq, Deserialize, Serialize)]
pub struct RawTransaction {
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

impl RawTransaction {
    /// Creates a new transaction struct
    pub fn new(
        nonce: u128,
        to: [u8; 20],
        value: u128,
        gas_price: u128,
        gas_limit: u128,
        data: Vec<u8>
    ) -> Self {
        RawTransaction {
            nonce,
            to: Some(to),
            value,
            gas_price,
            gas: gas_limit,
            data
        }
    }

    /// Signs and returns the RLP-encoded transaction
    pub fn sign<T: int::PrimInt>(&self, private_key: &[u8], chain_id: &T) -> Vec<u8> {
        let chain_id_u64: u64 = chain_id.to_u64().unwrap();
        let hash = self.hash(chain_id_u64);
        let sig = ecdsa_sign(&hash, private_key, &chain_id_u64);
        let mut r_n = sig.r;
        let mut s_n = sig.s;
        while r_n[0] == 0 {
            r_n.remove(0);
        }
        while s_n[0] == 0 {
            s_n.remove(0);
        }
        let mut tx = RlpStream::new();
        tx.begin_unbounded_list();
        self.encode(&mut tx);
        tx.append(&sig.v);
        tx.append(&r_n);
        tx.append(&s_n);
        tx.finalize_unbounded_list();
        tx.out().to_vec()
    }

    fn hash(&self, chain_id: u64) -> Vec<u8> {
        let mut hash = RlpStream::new();
        hash.begin_unbounded_list();
        self.encode(&mut hash);
        hash.append(&chain_id.clone());
        hash.append_raw(&[0x80], 1);
        hash.append_raw(&[0x80], 1);
        hash.finalize_unbounded_list();
        keccak256_hash(&hash.out())
    }

    fn encode(&self, s: &mut RlpStream) {
        s.append(&self.nonce);
        s.append(&self.gas_price);
        s.append(&self.gas);
        if let Some(ref t) = self.to {
            let to: Vec<u8> = t.iter().cloned().collect();
            s.append(&to);
        } else {
            s.append(&vec![]);
        }
        s.append(&self.value);
        s.append(&self.data);
    }
}

fn keccak256_hash(bytes: &[u8]) -> Vec<u8> {
    let mut hasher = Keccak::v256();
    hasher.update(bytes);
    let mut resp: [u8; 32] = Default::default();
    hasher.finalize(&mut resp);
    resp.iter().cloned().collect()
}

fn ecdsa_sign(hash: &[u8], private_key: &[u8], chain_id: &u64) -> EcdsaSig {
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

pub struct EcdsaSig {
    v: u64,
    r: Vec<u8>,
    s: Vec<u8>,
}

#[cfg(test)]
mod test {
    use raw_transaction::RawTransaction;
    use serde_json;
    use std::fs::File;
    use std::io::Read;
    use ethereum_types::H256;

    #[test]
    fn test_eip2718() {
        let txn = Transaction::FeeMarketEIP1559(EIP1559Txn::new(...));
        let bytes = txn.sign(secret_key);
    }

    #[test]
    fn test_signs_transaction_eth() {
        run_test("./test/test_txs.json", 1);
    }

    #[test]
    fn test_signs_transaction_ropsten() {
        run_test("./test/test_txs_ropsten.json", 3);
    }

    #[derive(Serialize, Deserialize, Clone)]
    struct Signing {
        signed: Vec<u8>,
        private_key: H256,
    }

    fn run_test(path: &str, chain_id: i32) {
        let mut file = File::open(path).unwrap();
        let mut f_string = String::new();
        file.read_to_string(&mut f_string).unwrap();
        let txs: Vec<(RawTransaction, Signing)> = serde_json::from_str(&f_string).unwrap();
        for (tx, signed) in txs.into_iter() {
            let rtx: RawTransaction = tx.into();
            assert_eq!(signed.signed, rtx.sign(signed.private_key.as_ref(), &chain_id));
        }
    }
}
