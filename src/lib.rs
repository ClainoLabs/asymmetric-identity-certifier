use candid::{CandidType, Deserialize};
use ic_cdk::api;
use ic_cdk::api::management_canister::ecdsa::{
    EcdsaCurve, EcdsaKeyId, EcdsaPublicKeyArgument, SignWithEcdsaArgument, 
    ecdsa_public_key, sign_with_ecdsa
};
use ic_cdk_macros::{init, post_upgrade, pre_upgrade, query, update};
use serde::Serialize;
use std::cell::RefCell;

// Global state to store the encryption public key from init
thread_local! {
    static PUBLIC_KEY: RefCell<String> = RefCell::new(String::new());
    static ECDSA_PUBLIC_KEY: RefCell<Vec<u8>> = RefCell::new(Vec::new());
    static LOCAL_MODE: RefCell<bool> = RefCell::new(false);
}

// Stable storage for the ECDSA public key and local mode
#[derive(CandidType, Deserialize, Default)]
struct StableStorage {
    ecdsa_public_key: Vec<u8>,
    local_mode: bool,
}

#[derive(CandidType, Deserialize)]
struct InitArgs {
    public_key_hex: String,
    local_mode: bool,
}

#[init]
fn init(args: InitArgs) {
    // Validate hex format for encryption key
    if hex::decode(&args.public_key_hex).is_err() {
        ic_cdk::trap("Invalid hex format for public key");
    }
    
    // Store the encryption public key globally
    PUBLIC_KEY.with(|pk| {
        *pk.borrow_mut() = args.public_key_hex;
    });
    
    // Set local mode (default to false if not provided)
    let is_local_mode = args.local_mode;
    LOCAL_MODE.with(|mode| {
        *mode.borrow_mut() = is_local_mode;
    });
}

#[update]
async fn init_ecdsa_key() {
    // reject if the key is already set
    if ECDSA_PUBLIC_KEY.with(|pk| !pk.borrow().is_empty()) {
        ic_cdk::trap("ECDSA key already set");
    }

    // Get ECDSA public key and store it
    let ecdsa_key = get_ecdsa_key().await;
    ECDSA_PUBLIC_KEY.with(|pk| {
        *pk.borrow_mut() = ecdsa_key;
    });
}

#[pre_upgrade]
fn pre_upgrade() {
    let stable_data = StableStorage {
        ecdsa_public_key: ECDSA_PUBLIC_KEY.with(|pk| pk.borrow().clone()),
        local_mode: LOCAL_MODE.with(|mode| *mode.borrow()),
    };
    ic_cdk::storage::stable_save((stable_data,)).expect("Failed to save stable data");
}

#[post_upgrade]
fn post_upgrade() {
    let (stable_data,): (StableStorage,) = ic_cdk::storage::stable_restore().expect("Failed to restore stable data");
    
    ECDSA_PUBLIC_KEY.with(|pk| {
        *pk.borrow_mut() = stable_data.ecdsa_public_key;
    });
    
    LOCAL_MODE.with(|mode| {
        *mode.borrow_mut() = stable_data.local_mode;
    });
}

// Helper function to get the appropriate key name based on local mode
fn get_key_name() -> String {
    LOCAL_MODE.with(|mode| {
        if *mode.borrow() {
            "dfx_test_key".to_string() // Local mode key for testing
        } else {
            "key_1".to_string() // Production key for mainnet
        }
    })
}

async fn get_ecdsa_key() -> Vec<u8> {
    let key_name = get_key_name();
    
    let request = EcdsaPublicKeyArgument {
        canister_id: None, // Use this canister's ID
        derivation_path: vec![], // Empty for root key
        key_id: EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: key_name,
        },
    };
    
    match ecdsa_public_key(request).await {
        Ok((response,)) => response.public_key,
        Err((_, err)) => {
            // Using unreachable_expr! to silence the warning
            ic_cdk::trap(&format!("Failed to get ECDSA public key: {}", err));
            #[allow(unreachable_code)]
            Vec::new()
        }
    }
}

#[derive(CandidType, Serialize, Clone)]
struct Certificate {
    principal: String,
    timestamp: u64,
}

#[derive(CandidType, Serialize)]
struct CertifiedIdentity {
    principal_id: String,
    certificate: Certificate,
    issuer_signature: String,
    issuer_ecdsa_public_key_hex: String,
}

#[update]
async fn get_certified_identity() -> String {
    let caller = api::caller();

    // Check if the caller is anonymous and trap if so
    if caller == candid::types::principal::Principal::anonymous() {
        ic_cdk::trap("Anonymous principal not allowed to make calls");
    }

    let caller_str = caller.to_string();
    let current_time = api::time();
    
    let certificate = Certificate {
        principal: caller_str.clone(),
        timestamp: current_time,
    };
    
    // Serialize the certificate to sign it
    let certificate_bytes = serde_json::to_vec(&certificate).unwrap();
    
    // Create a hash of the certificate for signing
    let certificate_hash = sha256(&certificate_bytes);
    
    // Sign the certificate hash with ECDSA
    let signature = sign_certificate(certificate_hash).await;
    
    // Get the ECDSA public key in hex format
    let issuer_ecdsa_public_key_hex = ECDSA_PUBLIC_KEY.with(|pk| {
        hex::encode(pk.borrow().clone())
    });
    
    let identity = CertifiedIdentity {
        principal_id: caller_str,
        certificate,
        issuer_signature: hex::encode(signature),
        issuer_ecdsa_public_key_hex,
    };
    
    serde_json::to_string(&identity).unwrap()
}

#[query]
fn get_ecdsa_public_key_hex() -> String {
    ECDSA_PUBLIC_KEY.with(|pk| {
        hex::encode(pk.borrow().clone())
    })
}

async fn sign_certificate(message_hash: Vec<u8>) -> Vec<u8> {
    let key_name = get_key_name();
    
    let request = SignWithEcdsaArgument {
        message_hash,
        derivation_path: vec![],
        key_id: EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: key_name,
        },
    };
    
    match sign_with_ecdsa(request).await {
        Ok((response,)) => response.signature,
        Err((_, err)) => {
            ic_cdk::trap(&format!("Failed to sign with ECDSA: {}", err));
            #[allow(unreachable_code)]
            Vec::new()
        }
    }
}

#[query]
fn documentation() -> String {
  "".to_string()
}

// Helper function to compute SHA-256 hash
fn sha256(data: &[u8]) -> Vec<u8> {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

// Generate did files
ic_cdk::export_candid!();