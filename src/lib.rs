#![deny(warnings)]
#![deny(clippy::all)]
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
use serde::de::Error as SerdeErr;
use serde::ser::SerializeSeq;
use serde::Deserialize;
use std::convert::TryInto;
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

        // `None` means it is legacy
        if Self::transaction_type().is_none() {
            rlp_stream.append(&self.chain());
            rlp_stream.append_raw(&[0x80], 1);
            rlp_stream.append_raw(&[0x80], 1);
        }

        rlp_stream.finalize_unbounded_list();
        let mut rlp_bytes = rlp_stream.out().to_vec();

        if let Some(tt) = Self::transaction_type() {
            rlp_bytes.insert(0usize, tt);
        }

        keccak256_hash(&rlp_bytes)
    }

    /// Compute the [ECDSA](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm) for the transaction
    fn ecdsa(&self, private_key: &[u8]) -> Result<EcdsaSig, Error> {
        let hash = self.hash();

        let chain = match Self::transaction_type() {
            Some(_) => None,
            None => Some(self.chain()),
        };

        EcdsaSig::generate(hash, private_key, chain)
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
    /// let ecdsa = tx.ecdsa(&vec![0x35; 32]).unwrap();
    /// let tx_bytes = tx.sign(&ecdsa);
    /// ```
    fn sign(&self, ecdsa: &EcdsaSig) -> Vec<u8>;

    /// Return the fields of the transaction as a list of RLP-encodable
    /// parts. The parts must follow the order that they will be encoded,
    /// hashed, or signed.
    fn rlp_parts(&self) -> Vec<Box<dyn Encodable>>;

    /// Returns the transaction defined as TransactionType in [EIP-2718](https://eips.ethereum.org/EIPS/eip-2718).
    /// LegacyTransactions do not have a type, so will return None.
    fn transaction_type() -> Option<u8>;
}

#[derive(Debug)]
pub enum Error {
    Secp256k1(secp256k1::Error),
}

impl From<secp256k1::Error> for Error {
    fn from(error: secp256k1::Error) -> Self {
        Error::Secp256k1(error)
    }
}

/// Internal function that avoids duplicating a lot of signing code
fn sign_bytes<T: Transaction>(tx_type: Option<u8>, ecdsa: &EcdsaSig, t: &T) -> Vec<u8> {
    let mut rlp_stream = RlpStream::new();
    let rlp = t.rlp_parts();
    rlp_stream.begin_unbounded_list();
    for r in rlp.iter() {
        rlp_stream.append(r);
    }
    let EcdsaSig { v, s, r } = ecdsa;

    // removes leading zeroes
    let mut r_n = r.clone();
    let mut s_n = s.clone();
    while r_n[0] == 0 {
        r_n.remove(0);
    }
    while s_n[0] == 0 {
        s_n.remove(0);
    }

    rlp_stream.append(v);
    rlp_stream.append(&r_n);
    rlp_stream.append(&s_n);

    rlp_stream.finalize_unbounded_list();

    let mut vec = rlp_stream.out().to_vec();
    if let Some(b) = tx_type {
        vec.insert(0usize, b)
    }
    vec
}

/// Description of a Transaction, pending or in the chain.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct LegacyTransaction {
    /// Chain ID
    pub chain: u64,
    /// Nonce
    pub nonce: u128,
    /// Recipient (None when contract creation)
    #[serde(serialize_with = "option_array_u8_serialize")]
    #[serde(deserialize_with = "option_array_u8_deserialize")]
    #[serde(default)]
    pub to: Option<[u8; 20]>,
    /// Transfered value
    pub value: u128,
    /// Gas price
    #[serde(rename = "gasPrice")]
    pub gas_price: u128,
    /// Gas limit
    #[serde(alias = "gasLimit")]
    pub gas: u128,
    /// Input data
    #[serde(serialize_with = "slice_u8_serialize")]
    #[serde(deserialize_with = "slice_u8_deserialize")]
    #[serde(default)]
    pub data: Vec<u8>,
}

impl Transaction for LegacyTransaction {
    fn chain(&self) -> u64 {
        self.chain
    }

    fn rlp_parts(&self) -> Vec<Box<dyn Encodable>> {
        let to: Vec<u8> = match self.to {
            Some(ref to) => to.to_vec(),
            None => vec![],
        };
        vec![
            Box::new(self.nonce),
            Box::new(self.gas_price),
            Box::new(self.gas),
            Box::new(to),
            Box::new(self.value),
            Box::new(self.data.clone()),
        ]
    }

    fn sign(&self, ecdsa: &EcdsaSig) -> Vec<u8> {
        sign_bytes(None, ecdsa, self)
    }

    fn transaction_type() -> Option<u8> {
        None
    }
}

#[derive(Debug, Default, Clone, Deserialize, Serialize, PartialEq, Eq)]
/// A list of addresses and storage keys that the transaction plans to access.
pub struct Access {
    #[serde(serialize_with = "array_u8_20_serialize")]
    #[serde(deserialize_with = "array_u8_20_deserialize")]
    pub address: [u8; 20],
    #[serde(serialize_with = "storage_keys_serialize")]
    #[serde(deserialize_with = "storage_keys_deserialize")]
    #[serde(rename = "storageKeys")]
    pub storage_keys: Vec<[u8; 32]>,
}

#[derive(Debug, Default, Clone, Deserialize, Serialize, PartialEq, Eq)]
/// [EIP-2930](https://eips.ethereum.org/EIPS/eip-2930) access list.
pub struct AccessList(Vec<Access>);

impl Encodable for AccessList {
    /// Encodes the access list according to [EIP-2930](https://eips.ethereum.org/EIPS/eip-2930).
    fn rlp_append(&self, rlp_stream: &mut RlpStream) {
        rlp_stream.begin_unbounded_list();

        for access in self.0.iter() {
            let address_bytes: Vec<u8> = access.address.to_vec();

            rlp_stream.begin_unbounded_list();
            rlp_stream.append(&address_bytes);

            // append the list of keys
            {
                rlp_stream.begin_unbounded_list();
                for storage_key in access.storage_keys.iter() {
                    let storage_key_bytes: Vec<u8> = storage_key.to_vec();
                    rlp_stream.append(&storage_key_bytes);
                }
                rlp_stream.finalize_unbounded_list();
            }

            rlp_stream.finalize_unbounded_list();
        }

        rlp_stream.finalize_unbounded_list();
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// [EIP-2930](https://eips.ethereum.org/EIPS/eip-2930) access list transaction.
pub struct AccessListTransaction {
    /// Chain ID
    pub chain: u64,
    /// Nonce
    pub nonce: u128,
    /// Gas price
    #[serde(rename = "gasPrice")]
    pub gas_price: u128,
    /// Gas limit
    #[serde(alias = "gasLimit")]
    pub gas: u128,
    /// Recipient (None when contract creation)
    #[serde(serialize_with = "option_array_u8_serialize")]
    #[serde(deserialize_with = "option_array_u8_deserialize")]
    #[serde(default)]
    pub to: Option<[u8; 20]>,
    /// Transfered value
    pub value: u128,
    /// Input data
    #[serde(serialize_with = "slice_u8_serialize")]
    #[serde(deserialize_with = "slice_u8_deserialize")]
    #[serde(default)]
    pub data: Vec<u8>,
    /// List of addresses and storage keys the transaction plans to access
    #[serde(rename = "accessList")]
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

/// We allow hex strings such as "0x00ffaa". The 0x prefix is not necessary when
/// you know it is hex.
const HEX_PREFIX: &str = "0x";

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
        Err(err) => Err(derr::<D>(&s, err)),
    }
}

fn storage_keys_deserialize<'de, D>(deserializer: D) -> Result<Vec<[u8; 32]>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let storage_key_vec: Vec<String> = Vec::deserialize(deserializer)?;
    let mut storage_keys = vec![];
    for storage_key in storage_key_vec.into_iter() {
        let s = if storage_key.starts_with(HEX_PREFIX) {
            storage_key.replace(HEX_PREFIX, "")
        } else {
            storage_key
        };
        let s = match hex::decode(&s) {
            Ok(s) => s,
            Err(err) => return Err(derr::<D>(&s, err)),
        };
        let s_len = s.len();
        let arr = match s.try_into() {
            Ok(a) => a,
            Err(_) => {
                return Err(D::Error::invalid_length(
                    s_len,
                    &"a hex string of length 20",
                ))
            }
        };
        storage_keys.push(arr) // TODO
    }
    Ok(storage_keys)
}

fn storage_keys_serialize<S>(storage_keys: &[[u8; 32]], s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let mut seq = s.serialize_seq(Some(storage_keys.len()))?;
    for storage_key in storage_keys.iter() {
        seq.serialize_element(&hex::encode(storage_key))?;
    }
    seq.end()
}

fn array_u8_20_serialize<S>(storage_keys: &[u8; 20], s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    s.serialize_str(&hex::encode(storage_keys))
}

fn array_u8_20_deserialize<'de, D>(d: D) -> Result<[u8; 20], D::Error>
where
    D: serde::Deserializer<'de>,
{
    match option_array_u8_deserialize(d)? {
        Some(a) => Ok(a),
        None => Err(
            D::Error::invalid_value(serde::de::Unexpected::Option, &"a hex string of length 20"), // TODO is error accurate?
        ),
    }
}

fn option_array_u8_deserialize<'de, D>(deserializer: D) -> Result<Option<[u8; 20]>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    const TO_LEN: usize = 20;
    let s_option: Option<String> = Option::deserialize(deserializer)?;
    match s_option {
        None => Ok(None),
        Some(s) => {
            let s = if s.starts_with(HEX_PREFIX) {
                s.replace(HEX_PREFIX, "")
            } else {
                s
            };
            match hex::decode(&s) {
                Ok(s) => {
                    let mut to = [0u8; 20];
                    if s.len() == TO_LEN {
                        for (i, b) in s.iter().enumerate() {
                            to[i] = *b;
                        }

                        Ok(Some(to))
                    } else {
                        Err(D::Error::invalid_length(
                            s.len(),
                            &"a hex string of length 20",
                        ))
                    }
                }
                Err(err) => Err(derr::<D>(&s, err)),
            }
        }
    }
}

fn derr<'de, D: serde::Deserializer<'de>>(s: &str, err: hex::FromHexError) -> D::Error {
    match err {
        hex::FromHexError::InvalidHexCharacter { c, .. } => {
            D::Error::invalid_value(serde::de::Unexpected::Char(c), &"a valid hex character")
        }
        hex::FromHexError::OddLength => {
            D::Error::invalid_length(s.len(), &"a hex string of even length")
        }
        hex::FromHexError::InvalidStringLength => {
            D::Error::invalid_length(s.len(), &"a hex string that matches container length")
        }
    }
}

fn slice_u8_serialize<S>(slice: &[u8], s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    s.serialize_str(&hex::encode(slice))
}

const EIP_2930_TYPE: u8 = 0x01;

impl Transaction for AccessListTransaction {
    fn chain(&self) -> u64 {
        self.chain
    }

    #[allow(warnings)]
    fn rlp_parts(&self) -> Vec<Box<dyn Encodable>> {
        let to: Vec<u8> = match self.to {
            Some(ref to) => to.to_vec(),
            None => vec![],
        };
        let mut parts: Vec<Box<dyn Encodable>> = vec![
            Box::new(self.chain),
            Box::new(self.nonce),
            Box::new(self.gas_price),
            Box::new(self.gas),
            Box::new(to),
            Box::new(self.value),
            Box::new(self.data.clone()),
            Box::new(self.access_list.clone()),
        ];

        parts
    }

    fn sign(&self, ecdsa: &EcdsaSig) -> Vec<u8> {
        sign_bytes(Some(EIP_2930_TYPE), ecdsa, self)
    }

    fn transaction_type() -> Option<u8> {
        Some(EIP_2930_TYPE)
    }
}

const EIP_1559_TYPE: u8 = 0x02;

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// [EIP-1559](https://eips.ethereum.org/EIPS/eip-1559) fee market transaction.
pub struct FeeMarketTransaction {
  /// Chain ID
  pub chain: u64,
  /// Nonce
  pub nonce: u128,
  /// Gas price
  #[serde(rename = "maxPriorityFeePerGas")]
  pub max_priority_fee_per_gas: u128,
  #[serde(rename = "maxFeePerGas")]
  pub max_fee_per_gas: u128,
  /// Gas limit
  #[serde(alias = "gasLimit")]
  pub gas: u128,
  /// Recipient (None when contract creation)
  #[serde(serialize_with = "option_array_u8_serialize")]
  #[serde(deserialize_with = "option_array_u8_deserialize")]
  #[serde(default)]
  pub to: Option<[u8; 20]>,
  /// Transfered value
  pub value: u128,
  /// Input data
  #[serde(serialize_with = "slice_u8_serialize")]
  #[serde(deserialize_with = "slice_u8_deserialize")]
  #[serde(default)]
  pub data: Vec<u8>,
  /// List of addresses and storage keys the transaction plans to access
  #[serde(rename = "accessList")]
  pub access_list: AccessList,
}

impl Transaction for FeeMarketTransaction {
  fn chain(&self) -> u64 { self.chain }

  fn sign(&self, ecdsa: &EcdsaSig) -> Vec<u8> {
    sign_bytes(Some(EIP_1559_TYPE), ecdsa, self)
  }

  fn rlp_parts(&self) -> Vec<Box<dyn Encodable>> {
    let to: Vec<u8> = match self.to {
      Some(ref to) => to.to_vec(),
      None => vec![],
    };
    vec![
      Box::new(self.chain),
      Box::new(self.nonce),
      Box::new(self.max_priority_fee_per_gas),
      Box::new(self.max_fee_per_gas),
      Box::new(self.gas),
      Box::new(to),
      Box::new(self.value),
      Box::new(self.data.clone()),
      Box::new(self.access_list.clone()),
    ]
  }

  fn transaction_type() -> Option<u8> {
    Some(EIP_1559_TYPE)
  }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
/// Represents an [ECDSA](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm) signature.
pub struct EcdsaSig {
    pub v: u64,
    #[serde(serialize_with = "slice_u8_serialize")]
    #[serde(deserialize_with = "slice_u8_deserialize")]
    pub r: Vec<u8>,
    #[serde(serialize_with = "slice_u8_serialize")]
    #[serde(deserialize_with = "slice_u8_deserialize")]
    pub s: Vec<u8>,
}

impl EcdsaSig {
    fn generate(
        hash: [u8; 32],
        private_key: &[u8],
        chain_id: Option<u64>,
    ) -> Result<EcdsaSig, Error> {
        let s = Secp256k1::signing_only();
        let msg = Message::from_slice(&hash)?;
        let key = SecretKey::from_slice(private_key)?;
        let (v, sig_bytes) = s.sign_ecdsa_recoverable(&msg, &key).serialize_compact();

        let v = v.to_i32() as u64
            + match chain_id {
                Some(c) => c * 2 + 35,
                None => 0,
            };

        Ok(EcdsaSig {
            v,
            r: sig_bytes[0..32].to_vec(),
            s: sig_bytes[32..64].to_vec(),
        })
    }
}

fn keccak256_hash(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(bytes);
    let mut resp: [u8; 32] = Default::default();
    hasher.finalize(&mut resp);
    resp
}

#[cfg(test)]
mod test {
    use crate::{AccessListTransaction, EcdsaSig, LegacyTransaction, Transaction, FeeMarketTransaction};

    use serde_json;
    use std::collections::HashMap;
    use std::fmt::Debug;
    use std::fs::File;
    use std::io::Read;

    // TX RANDOM FEE MARKET 001

    #[test]
    fn test_random_fee_market_transaction_001() {
        run_signing_test::<FeeMarketTransaction>("./test/random_eip_1559_001.json");
    }

    #[test]
    fn test_random_fee_market_transaction_001_ecdsa() {
        run_ecdsa_test::<FeeMarketTransaction>("./test/random_eip_1559_001.json");
    }

    #[test]
    fn test_random_fee_market_transaction_001_hash() {
        run_hash_test::<FeeMarketTransaction>("./test/random_eip_1559_001.json");
    }

    // TX RANDOM FEE MARKET 002

    #[test]
    fn test_random_fee_market_transaction_002() {
        run_signing_test::<FeeMarketTransaction>("./test/random_eip_1559_002.json");
    }

    #[test]
    fn test_random_fee_market_transaction_002_ecdsa() {
        run_ecdsa_test::<FeeMarketTransaction>("./test/random_eip_1559_002.json");
    }

    #[test]
    fn test_random_fee_market_transaction_002_hash() {
        run_hash_test::<FeeMarketTransaction>("./test/random_eip_1559_002.json");
    }

    // TX RANDOM FEE MARKET 003

    #[test]
    fn test_random_fee_market_transaction_003() {
        run_signing_test::<FeeMarketTransaction>("./test/random_eip_1559_003.json");
    }

    #[test]
    fn test_random_fee_market_transaction_003_ecdsa() {
        run_ecdsa_test::<FeeMarketTransaction>("./test/random_eip_1559_003.json");
    }

    #[test]
    fn test_random_fee_market_transaction_003_hash() {
        run_hash_test::<FeeMarketTransaction>("./test/random_eip_1559_003.json");
    }

    // TX RANDOM ACCESS LIST 001

    #[test]
    fn test_random_access_list_transaction_001() {
        run_signing_test::<AccessListTransaction>("./test/random_eip_2930_001.json");
    }

    #[test]
    fn test_random_access_list_transaction_001_ecdsa() {
        run_ecdsa_test::<AccessListTransaction>("./test/random_eip_2930_001.json");
    }

    #[test]
    fn test_random_access_list_transaction_001_hash() {
        run_hash_test::<AccessListTransaction>("./test/random_eip_2930_001.json");
    }

    // TX RANDOM ACCESS LIST 002

    #[test]
    fn test_random_access_list_transaction_002() {
        run_signing_test::<AccessListTransaction>("./test/random_eip_2930_002.json");
    }

    #[test]
    fn test_random_access_list_transaction_002_ecdsa() {
        run_ecdsa_test::<AccessListTransaction>("./test/random_eip_2930_002.json");
    }

    #[test]
    fn test_random_access_list_transaction_002_hash() {
        run_hash_test::<AccessListTransaction>("./test/random_eip_2930_002.json");
    }

    // TX RANDOM ACCESS LIST 003

    #[test]
    fn test_random_access_list_transaction_003() {
        run_signing_test::<AccessListTransaction>("./test/random_eip_2930_003.json");
    }

    #[test]
    fn test_random_access_list_transaction_003_ecdsa() {
        run_ecdsa_test::<AccessListTransaction>("./test/random_eip_2930_003.json");
    }

    #[test]
    fn test_random_access_list_transaction_003_hash() {
        run_hash_test::<AccessListTransaction>("./test/random_eip_2930_003.json");
    }

    // TX RANDOM LEGACY 001

    #[test]
    fn test_random_legacy_001() {
        run_signing_test::<LegacyTransaction>("./test/random_legacy_001.json");
    }

    #[test]
    fn test_random_legacy_001_ecdsa() {
        run_ecdsa_test::<LegacyTransaction>("./test/random_legacy_001.json");
    }

    #[test]
    fn test_random_legacy_001_hash() {
        run_hash_test::<LegacyTransaction>("./test/random_legacy_001.json");
    }

    // TX RANDOM LEGACY 002

    #[test]
    fn test_random_legacy_002() {
        run_signing_test::<LegacyTransaction>("./test/random_legacy_002.json");
    }

    #[test]
    fn test_random_legacy_002_ecdsa() {
        run_ecdsa_test::<LegacyTransaction>("./test/random_legacy_002.json");
    }

    #[test]
    fn test_random_legacy_002_hash() {
      run_hash_test::<LegacyTransaction>("./test/random_legacy_002.json");
    }

    // TX RANDOM LEGACY 003

    #[test]
    fn test_random_legacy_003() {
        run_signing_test::<LegacyTransaction>("./test/random_legacy_003.json");
    }

    #[test]
    fn test_random_legacy_003_ecdsa() {
        run_ecdsa_test::<LegacyTransaction>("./test/random_legacy_003.json");
    }

    #[test]
    fn test_random_legacy_003_hash() {
        run_hash_test::<LegacyTransaction>("./test/random_legacy_003.json");
    }

    // TX RANDOM LEGACY 004

    #[test]
    fn test_random_legacy_004() {
        run_signing_test::<LegacyTransaction>("./test/random_legacy_004.json");
    }

    #[test]
    fn test_random_legacy_004_ecdsa() {
        run_ecdsa_test::<LegacyTransaction>("./test/random_legacy_004.json");
    }

    #[test]
    fn test_random_legacy_004_hash() {
        run_hash_test::<LegacyTransaction>("./test/random_legacy_004.json");
    }

    // TX RANDOM LEGACY 005

    #[test]
    fn test_random_legacy_005() {
        run_signing_test::<LegacyTransaction>("./test/random_legacy_005.json");
    }

    #[test]
    fn test_random_legacy_005_ecdsa() {
        run_ecdsa_test::<LegacyTransaction>("./test/random_legacy_005.json");
    }

    #[test]
    fn test_random_legacy_005_hash() {
        run_hash_test::<LegacyTransaction>("./test/random_legacy_005.json");
    }

    // TX RANDOM LEADING ZEROES 001

    #[test]
    fn test_random_legacy_leading_zeroes_001_ecdsa() {
        run_ecdsa_test::<LegacyTransaction>("./test/random_legacy_leading_zeroes_001.json");
    }

    #[test]
    fn test_random_legacy_leading_zeroes_001_hash() {
        run_hash_test::<LegacyTransaction>("./test/random_legacy_leading_zeroes_001.json");
    }

    // TX RANDOM LEADING ZEROES 002

    #[test]
    fn test_random_legacy_leading_zeroes_002_ecdsa() {
        run_ecdsa_test::<LegacyTransaction>("./test/random_legacy_leading_zeroes_002.json");
    }

    #[test]
    fn test_random_legacy_leading_zeroes_002_hash() {
        run_hash_test::<LegacyTransaction>("./test/random_legacy_leading_zeroes_002.json");
    }

    // TX RANDOM LEADING ZEROES 003

    #[test]
    fn test_random_legacy_leading_zeroes_003_ecdsa() {
        run_ecdsa_test::<LegacyTransaction>("./test/random_legacy_leading_zeroes_003.json");
    }

    #[test]
    fn test_random_legacy_leading_zeroes_003_hash() {
        run_hash_test::<LegacyTransaction>("./test/random_legacy_leading_zeroes_003.json");
    }

    // TX ZERO LEGACY 001

    #[test]
    fn test_zero_legacy_001() {
        run_signing_test::<LegacyTransaction>("./test/zero_legacy_001.json");
    }

    #[test]
    fn test_zero_legacy_001_ecdsa() {
        run_ecdsa_test::<LegacyTransaction>("./test/zero_legacy_001.json");
    }

    #[test]
    fn test_zero_legacy_001_hash() {
        run_hash_test::<LegacyTransaction>("./test/zero_legacy_001.json");
    }

    // TX ZERO LEGACY 002

    #[test]
    fn test_zero_legacy_002() {
        run_signing_test::<LegacyTransaction>("./test/zero_legacy_002.json");
    }

    #[test]
    fn test_zero_legacy_002_ecdsa() {
        run_ecdsa_test::<LegacyTransaction>("./test/zero_legacy_002.json");
    }

    #[test]
    fn test_zero_legacy_002_hash() {
        run_hash_test::<LegacyTransaction>("./test/zero_legacy_002.json");
    }

    // TX ZERO LEGACY 003

    #[test]
    fn test_zero_legacy_003() {
        run_signing_test::<LegacyTransaction>("./test/zero_legacy_003.json");
    }

    #[test]
    fn test_zero_legacy_003_ecdsa() {
        run_ecdsa_test::<LegacyTransaction>("./test/zero_legacy_003.json");
    }

    #[test]
    fn test_zero_legacy_003_hash() {
        run_hash_test::<LegacyTransaction>("./test/zero_legacy_003.json");
    }

    // TX ZERO ACCESS LIST 001

    #[test]
    fn test_zero_access_list_transaction_001() {
        run_signing_test::<AccessListTransaction>("./test/zero_eip_2718_001.json");
    }

    #[test]
    fn test_zero_access_list_transaction_001_ecdsa() {
        run_ecdsa_test::<AccessListTransaction>("./test/zero_eip_2718_001.json");
    }

    #[test]
    fn test_zero_access_list_transaction_001_hash() {
        run_hash_test::<AccessListTransaction>("./test/zero_eip_2718_001.json");
    }

    // TX ZERO ACCESS LIST 002

    #[test]
    fn test_zero_access_list_transaction_002() {
        run_signing_test::<AccessListTransaction>("./test/zero_eip_2718_002.json");
    }

    #[test]
    fn test_zero_access_list_transaction_002_ecdsa() {
        run_ecdsa_test::<AccessListTransaction>("./test/zero_eip_2718_002.json");
    }

    #[test]
    fn test_zero_access_list_transaction_002_hash() {
        run_hash_test::<AccessListTransaction>("./test/zero_eip_2718_002.json");
    }

    // TX ZERO ACCESS LIST 003

    #[test]
    fn test_zero_access_list_transaction_003() {
        run_signing_test::<AccessListTransaction>("./test/zero_eip_2718_003.json");
    }

    #[test]
    fn test_zero_access_list_transaction_003_ecdsa() {
        run_ecdsa_test::<AccessListTransaction>("./test/zero_eip_2718_003.json");
    }

    #[test]
    fn test_zero_access_list_transaction_003_hash() {
        run_ecdsa_test::<AccessListTransaction>("./test/zero_eip_2718_003.json");
    }

    // TX ZERO FEE MARKET 001

    #[test]
    fn test_zero_fee_market_transaction_001() {
        run_signing_test::<FeeMarketTransaction>("./test/zero_eip_1559_001.json");
    }

    #[test]
    fn test_zero_fee_market_transaction_001_ecdsa() {
        run_ecdsa_test::<FeeMarketTransaction>("./test/zero_eip_1559_001.json");
    }

    #[test]
    fn test_zero_fee_market_transaction_001_hash() {
        run_ecdsa_test::<FeeMarketTransaction>("./test/zero_eip_1559_001.json");
    }

    // TX ZERO FEE MARKET 002

    #[test]
    fn test_zero_fee_market_transaction_002() {
        run_signing_test::<FeeMarketTransaction>("./test/zero_eip_1559_002.json");
    }

    #[test]
    fn test_zero_fee_market_transaction_002_ecdsa() {
        run_ecdsa_test::<FeeMarketTransaction>("./test/zero_eip_1559_002.json");
    }

    #[test]
    fn test_zero_fee_market_transaction_002_hash() {
        run_ecdsa_test::<FeeMarketTransaction>("./test/zero_eip_1559_002.json");
    }

    // TX ZERO FEE MARKET 003

    #[test]
    fn test_zero_fee_market_transaction_003() {
        run_signing_test::<FeeMarketTransaction>("./test/zero_eip_1559_003.json");
    }

    #[test]
    fn test_zero_fee_market_transaction_003_ecdsa() {
        run_ecdsa_test::<FeeMarketTransaction>("./test/zero_eip_1559_003.json");
    }

    #[test]
    fn test_zero_fee_market_transaction_003_hash() {
        run_ecdsa_test::<FeeMarketTransaction>("./test/zero_eip_1559_003.json");
    }

    // Serialization tests

    // ACCESS LIST SERIALIZATION

    #[test]
    fn test_serde_random_access_list_transaction_001() {
        run_serialization_deserialization_test::<AccessListTransaction>(
            "./test/random_eip_2930_001.json",
        );
    }

    #[test]
    fn test_serde_random_access_list_transaction_002() {
        run_serialization_deserialization_test::<AccessListTransaction>(
            "./test/random_eip_2930_002.json",
        );
    }

    #[test]
    fn test_serde_random_access_list_transaction_003() {
        run_serialization_deserialization_test::<AccessListTransaction>(
            "./test/random_eip_2930_003.json",
        );
    }

    // FEE MARKET SERIALIZATION

    #[test]
    fn test_serde_random_fee_market_transaction_001() {
      run_serialization_deserialization_test::<FeeMarketTransaction>(
        "./test/random_eip_1559_001.json",
      );
    }

    #[test]
    fn test_serde_random_fee_market_transaction_002() {
      run_serialization_deserialization_test::<FeeMarketTransaction>(
        "./test/random_eip_1559_002.json",
      );
    }

    #[test]
    fn test_serde_random_fee_market_transaction_003() {
      run_serialization_deserialization_test::<FeeMarketTransaction>(
        "./test/random_eip_1559_003.json",
      );
    }

    fn run_serialization_deserialization_test<
        T: Transaction
            + serde::de::DeserializeOwned
            + std::fmt::Debug
            + serde::Serialize
            + serde::de::DeserializeOwned
            + std::cmp::Eq,
    >(
        path: &str,
    ) {
        let mut file = File::open(path).unwrap_or_else(|_| panic!("Failed to open: {}", path));
        let mut f_string = String::new();
        file.read_to_string(&mut f_string).unwrap();

        let values: HashMap<String, serde_json::Value> = serde_json::from_str(&f_string).unwrap();
        let transaction_original: T = serde_json::from_value(values["input"].clone()).unwrap();
        let transaction_string = serde_json::to_string(&transaction_original).unwrap();

        assert_eq!(
            transaction_original,
            serde_json::from_str(&transaction_string).unwrap()
        )
    }

    // TODO refactor some of the below

    fn run_signing_test<T: Transaction + Debug + serde::de::DeserializeOwned>(path: &str) {
        let mut file = File::open(path).unwrap_or_else(|_| panic!("Failed to open: {}", path));
        let mut f_string = String::new();
        file.read_to_string(&mut f_string).unwrap();

        let values: HashMap<String, serde_json::Value> = serde_json::from_str(&f_string).unwrap();

        let transaction: T = serde_json::from_value(values["input"].clone()).unwrap();
        let ecdsa: EcdsaSig = serde_json::from_value(values["output"].clone()).unwrap();
        let expected_bytes_string: String =
            serde_json::from_value(values["output"]["bytes"].clone()).unwrap();
        let expected_bytes_string = expected_bytes_string.replace("0x", "");

        let actual_bytes = transaction.sign(&ecdsa);
        let actual_bytes_string = hex::encode(&actual_bytes);

        println!(
            "Expecting {} byte(s), got {} byte(s)",
            expected_bytes_string.len(),
            actual_bytes_string.len()
        );

        assert_eq!(expected_bytes_string, actual_bytes_string);
    }

    fn run_ecdsa_test<T: Transaction + serde::de::DeserializeOwned>(path: &str)
    where
        T: std::fmt::Debug,
    {
        let mut file = File::open(path).unwrap_or_else(|_| panic!("Failed to open: {}", path));
        let mut f_string = String::new();
        file.read_to_string(&mut f_string).unwrap();

        let values: HashMap<String, serde_json::Value> = serde_json::from_str(&f_string).unwrap();

        let transaction: T = serde_json::from_value(values["input"].clone()).unwrap();
        let private_key: String = match &values["privateKey"] {
            serde_json::Value::String(ref pk) => pk.clone(),
            _ => panic!("Unexpected type for private key (expected string)"),
        };
        let decoded_pk = hex::decode(private_key.replace("0x", "")).unwrap();
        let signed_ecdsa = transaction.ecdsa(&decoded_pk).unwrap();
        let expected_ecdsa: EcdsaSig = serde_json::from_value(values["output"].clone()).unwrap();

        assert_eq!(expected_ecdsa, signed_ecdsa)
    }

    fn run_hash_test<T: Transaction + serde::de::DeserializeOwned>(path: &str)
    where
        T: std::fmt::Debug,
    {
        let mut file = File::open(&path).unwrap_or_else(|_| panic!("Failed to open: {}", path));
        let mut f_string = String::new();
        file.read_to_string(&mut f_string).unwrap();

        let values: HashMap<String, serde_json::Value> = serde_json::from_str(&f_string).unwrap();

        let transaction: T = serde_json::from_value(values["input"].clone()).unwrap();
        let expected_hash = match &values["output"]["hash"] {
            serde_json::Value::String(ref h) => h.clone().replace("0x", ""),
            serde_json::Value::Null => panic!("Test is missing `hash`"),
            v => panic!("Unexpected type for hash (expected string, got {:?})", v),
        };
        let actual_hash = hex::encode(transaction.hash());

        assert_eq!(expected_hash, actual_hash)
    }
}
