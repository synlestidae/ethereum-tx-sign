#![deny(warnings)]
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate bytes;
extern crate hex;
extern crate num_traits;
extern crate rlp;
extern crate secp256k1;
extern crate tiny_keccak;

#[cfg(test)]
extern crate ethereum_types;
#[cfg(test)]
extern crate serde_json;

use rlp::{Encodable, RlpStream};
use secp256k1::{Message, Secp256k1, SecretKey};
use serde::de::Error;
use serde::Deserialize;
use tiny_keccak::{Hasher, Keccak};

/// Ethereum transaction
pub trait Transaction {
    /// [EIP-155](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-155.md) chain ID
    fn chain(&self) -> u64;

    /// Compute the unique transaction hash
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

    /// Compute the [ECDSA](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm) for the transaction
    fn ecdsa(&self, private_key: &[u8]) -> EcdsaSig {
        let hash = self.hash();

        EcdsaSig::generate(hash, private_key, self.chain())
    }

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

    /// Return the fields of the transaction as a list of RLP-encodable
    /// parts. The parts must follow the order that they will be encoded,
    /// hashed, or signed.
    fn rlp_parts<'a>(&'a self) -> Vec<Box<dyn Encodable>>;
}

/// EIP-2817 Typed Transaction Envelope
pub trait TypedTransaction: Transaction {
    /// Returns the transaction type byte
    fn transaction_type(&self) -> u8;
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
            Box::new(self.data.clone()),
        ]
    }
}

#[derive(Debug, Default, Clone, Deserialize, Serialize)]
pub struct Access {
    #[serde(serialize_with = "array_u8_20_serialize")]
    #[serde(deserialize_with = "array_u8_20_deserialize")]
    pub address: [u8; 20],
    #[serde(serialize_with = "storage_keys_serialize")]
    #[serde(deserialize_with = "storage_keys_deserialize")]
    pub storage_keys: Vec<[u8; 32]>,
}

#[derive(Debug, Default, Clone, Deserialize, Serialize)]
pub struct AccessList {
    pub list: Vec<Access>,
}

impl Encodable for AccessList {
    /// Encodes the access list according to [EIP-2930](https://eips.ethereum.org/EIPS/eip-2930).
    fn rlp_append(&self, rlp_stream: &mut RlpStream) {
        rlp_stream.begin_unbounded_list();

        for access in self.list.iter() {
            let address_bytes: Vec<u8> = access.address.iter().cloned().collect();

            rlp_stream.begin_unbounded_list();
            rlp_stream.append(&address_bytes);

            // append the list of keys
            {
                rlp_stream.begin_unbounded_list();
                for storage_key in access.storage_keys.iter() {
                    let storage_key_bytes: Vec<u8> = storage_key.iter().cloned().collect();
                    rlp_stream.append(&storage_key_bytes);
                }
                rlp_stream.finalize_unbounded_list();
            }

            rlp_stream.finalize_unbounded_list();
        }

        rlp_stream.finalize_unbounded_list();
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct AccessListTransaction {
    /// Chain ID
    pub chain: u64,
    /// Nonce
    pub nonce: u128,
    /// Gas Price
    #[serde(rename = "gasPrice")]
    pub gas_price: u128,
    /// Gas amount
    pub gas: u128,
    /// Recipient (None when contract creation)
    #[serde(serialize_with = "option_array_u8_serialize")]
    #[serde(deserialize_with = "option_array_u8_deserialize")]
    pub to: Option<[u8; 20]>,
    /// Transfered value
    pub value: u128,
    /// Input data
    #[serde(serialize_with = "slice_u8_serialize")]
    #[serde(deserialize_with = "slice_u8_deserialize")]
    pub data: Vec<u8>,
    /// List of addresses and storage keys the transaction plans to access
    pub access_list: AccessList,
}

fn option_array_u8_serialize<S>(to: &Option<[u8; 20]>, s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match to {
        Some(ref array) => slice_u8_serialize(array, s),
        None => s.serialize_none(),
    }
}

const HEX_PREFIX: &'static str = "0x";

fn slice_u8_deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s: String = String::deserialize(deserializer)?;
    let s = if s.starts_with(HEX_PREFIX) {
        s.replace(HEX_PREFIX, "")
    } else {
        s
    };
    match hex::decode(&s) {
        Ok(s) => Ok(s),
        Err(_) => todo!(),
    }
}

fn storage_keys_deserialize<'de, D>(deserializer: D) -> Result<Vec<[u8; 32]>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    /*let s: String = String::deserialize(deserializer)?;
    let s = if s.starts_with(HEX_PREFIX) { s.replace(HEX_PREFIX, "") } else { s };
    match hex::decode(&s) {
        Ok(s) => Ok(s),
        Err(_) => todo!()
    }*/
    todo!()
}

fn storage_keys_serialize<S>(storage_keys: &Vec<[u8; 32]>, s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    todo!()
}

fn array_u8_20_serialize<S>(storage_keys: &[u8; 20], s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    todo!()
}

fn array_u8_20_deserialize<'de, D>(d: D) -> Result<[u8; 20], D::Error>
where
    D: serde::Deserializer<'de>,
{
    todo!()
}

fn option_array_u8_deserialize<'de, D>(deserializer: D) -> Result<Option<[u8; 20]>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s_option: Option<String> = Option::deserialize(deserializer)?;
    const TO_LEN: usize = 20;
    match s_option {
        None => return Ok(None),
        Some(s) => {
            let s = if s.starts_with(HEX_PREFIX) {
                s.replace(HEX_PREFIX, "")
            } else {
                s
            };
            match hex::decode(&s) {
                Ok(s) => {
                    let mut to = [0u8; 20];
                    if s.len() != TO_LEN {
                        for (i, b) in s.iter().enumerate() {
                            to[i] = *b;
                        }

                        Ok(Some(to))
                    } else {
                        Err(D::Error::invalid_length(20, &"a hex string of length 20"))
                    }
                }
                Err(err) => Err(match err {
                    hex::FromHexError::InvalidHexCharacter { c, .. } => D::Error::invalid_value(
                        serde::de::Unexpected::Char(c),
                        &"a valid hex character",
                    ),
                    hex::FromHexError::OddLength => {
                        D::Error::invalid_length((s.len() / 2) * 2, &"a hex string of even length")
                    }
                    hex::FromHexError::InvalidStringLength => D::Error::invalid_length(
                        s.len() * 2,
                        &"a hex string that matches container length",
                    ),
                }), // TODO use the hex error
            }
        }
    }
}

fn slice_u8_serialize<S>(slice: &[u8], s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    s.serialize_str(&format!("0x{}", hex::encode(slice)))
}

const EIP_2930_TYPE: u8 = 0x01;

impl Transaction for AccessListTransaction {
    fn chain(&self) -> u64 {
        self.chain
    }

    #[allow(warnings)]
    fn rlp_parts(&self) -> Vec<Box<dyn Encodable>> {
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
            Box::new(self.data.clone()),
            Box::new(self.access_list.clone()),
        ]
    }
}

impl TypedTransaction for AccessListTransaction {
    fn transaction_type(&self) -> u8 {
        EIP_2930_TYPE
    }
}

#[derive(Debug)]
pub struct EcdsaSig {
    pub v: u64,
    pub r: Vec<u8>,
    pub s: Vec<u8>,
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
    use crate::{AccessListTransaction, LegacyTransaction, Transaction};
    use ethereum_types::H256;
    use serde_json;
    use std::collections::HashMap;
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

    #[allow(warnings)]
    fn run_signing_test(path: &str, name: &str) -> AccessListTransaction {
        let mut file = File::open(path).unwrap();
        let mut f_string = String::new();
        file.read_to_string(&mut f_string).unwrap();
        let txs: HashMap<String, serde_json::Value> = serde_json::from_str(&f_string).unwrap();
        serde_json::from_value(txs[name].clone()).unwrap()
    }
}
