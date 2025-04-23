use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use candid::{CandidType, Deserialize, Principal};
use ic_cdk::api;
use ic_cdk::api::management_canister::ecdsa::{
    ecdsa_public_key, sign_with_ecdsa, EcdsaCurve, EcdsaKeyId, EcdsaPublicKeyArgument,
    SignWithEcdsaArgument,
};
use ic_cdk_macros::{init, post_upgrade, pre_upgrade, query, update};
use serde::Serialize;
use std::cell::RefCell;

// Global state to store the encryption public key from init
thread_local! {
    static LOCAL_MODE: RefCell<bool> = RefCell::new(false);
    static AES_SYMMETRIC_ENCRYPTION_KEY_HEX: RefCell<String> = RefCell::new(String::new());
    static ECDSA_PUBLIC_KEY_HEX: RefCell<String> = RefCell::new(String::new());
    static CONTROLLER: RefCell<Principal> = RefCell::new(Principal::anonymous());
}

// Stable storage for the ECDSA public key and local mode
#[derive(CandidType, Deserialize)]
struct StableStorage {
    aes_symmetric_encryption_key_hex: String,
    ecdsa_public_key_hex: String,
    local_mode: bool,
    controller: Principal,
}

#[derive(CandidType, Deserialize)]
struct InitArgs {
    aes_symmetric_encryption_key_hex: String,
    local_mode: bool,
    controller_principal_id: String,
}

#[init]
fn init(args: InitArgs) {
    // set the controller
    CONTROLLER.with(|c| {
        *c.borrow_mut() = Principal::from_text(&args.controller_principal_id).unwrap();
    });

    // Validate hex format for encryption key
    if hex::decode(&args.aes_symmetric_encryption_key_hex).is_err() {
        ic_cdk::trap("Invalid hex format for encryption key");
    }

    // Store the encryption public key globally
    AES_SYMMETRIC_ENCRYPTION_KEY_HEX.with(|pk| {
        *pk.borrow_mut() = args.aes_symmetric_encryption_key_hex;
    });

    // Set local mode (default to false if not provided)
    let is_local_mode = args.local_mode;
    LOCAL_MODE.with(|mode| {
        *mode.borrow_mut() = is_local_mode;
    });
}

#[update]
async fn init_ecdsa_key() -> String {
    // validate that it is the controller
    let caller = api::msg_caller();
    if caller != CONTROLLER.with(|c| *c.borrow()) {
        ic_cdk::trap("Unauthorized");
    }

    // reject if the key is already set
    if ECDSA_PUBLIC_KEY_HEX.with(|pk| !pk.borrow().is_empty()) {
        ic_cdk::trap("ECDSA key already set");
    }

    // Get ECDSA public key and store it
    let ecdsa_key = get_ecdsa_key().await;
    ECDSA_PUBLIC_KEY_HEX.with(|pk| {
        *pk.borrow_mut() = hex::encode(ecdsa_key);
    });

    // return the public key hex
    get_ecdsa_public_key_hex()
}

#[pre_upgrade]
fn pre_upgrade() {
    let stable_data = StableStorage {
        aes_symmetric_encryption_key_hex: AES_SYMMETRIC_ENCRYPTION_KEY_HEX
            .with(|pk| pk.borrow().clone()),
        ecdsa_public_key_hex: ECDSA_PUBLIC_KEY_HEX.with(|pk| pk.borrow().clone()),
        local_mode: LOCAL_MODE.with(|mode| *mode.borrow()),
        controller: CONTROLLER.with(|c| *c.borrow()),
    };
    ic_cdk::storage::stable_save((stable_data,)).expect("Failed to save stable data");
}

#[post_upgrade]
fn post_upgrade() {
    let (stable_data,): (StableStorage,) =
        ic_cdk::storage::stable_restore().expect("Failed to restore stable data");

    AES_SYMMETRIC_ENCRYPTION_KEY_HEX.with(|pk| {
        *pk.borrow_mut() = stable_data.aes_symmetric_encryption_key_hex;
    });

    LOCAL_MODE.with(|mode| {
        *mode.borrow_mut() = stable_data.local_mode;
    });

    ECDSA_PUBLIC_KEY_HEX.with(|pk| {
        *pk.borrow_mut() = stable_data.ecdsa_public_key_hex;
    });

    // set the controller
    CONTROLLER.with(|c| {
        *c.borrow_mut() = stable_data.controller;
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
    // validate that it is the controller
    let caller = api::msg_caller();
    if caller != CONTROLLER.with(|c| *c.borrow()) {
        ic_cdk::trap("Unauthorized");
    }

    let key_name = get_key_name();

    let request = EcdsaPublicKeyArgument {
        canister_id: None,       // Use this canister's ID
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
}

#[update]
async fn get_certified_identity() -> String {
    let caller = api::msg_caller();

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

    let identity = CertifiedIdentity {
        principal_id: caller_str,
        certificate,
        issuer_signature: hex::encode(signature),
    };

    // Convert the identity to JSON string
    let identity_json = serde_json::to_string(&identity).unwrap();

    // Encrypt the JSON string using AES-GCM
    let encrypted_data = encrypt_data(identity_json.as_bytes())
        .await
        .unwrap_or_else(|e| ic_cdk::trap(&format!("Encryption failed: {}", e)));

    // Return the encrypted data as a hex string
    hex::encode(encrypted_data)
}

// Helper function to encrypt data using AES-GCM
async fn encrypt_data(data: &[u8]) -> Result<Vec<u8>, String> {
    // Get the encryption key from the global state
    let key_hex = AES_SYMMETRIC_ENCRYPTION_KEY_HEX.with(|k| k.borrow().clone());
    let key_bytes = hex::decode(&key_hex).map_err(|e| format!("Invalid key hex: {}", e))?;

    // Create a 32-byte key for AES-256-GCM
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    // Generate a deterministic nonce from timestamp and caller
    let timestamp = api::time();
    let caller = api::msg_caller();
    let mut nonce_bytes = [0u8; 12];

    // Use timestamp (8 bytes) and first 4 bytes of caller for nonce
    nonce_bytes[0..8].copy_from_slice(&timestamp.to_be_bytes());
    nonce_bytes[8..12].copy_from_slice(&caller.as_slice()[0..4]);

    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt the data
    let ciphertext = cipher
        .encrypt(nonce, data)
        .map_err(|e| format!("Encryption failed: {}", e))?;

    // Combine nonce and ciphertext
    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(nonce.as_slice());
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

#[query]
fn get_ecdsa_public_key_hex() -> String {
    // validate that it is the controller
    let caller = api::msg_caller();
    if caller != CONTROLLER.with(|c| *c.borrow()) {
        ic_cdk::trap("Unauthorized");
    }

    // Get the public key from storage
    let public_key = ECDSA_PUBLIC_KEY_HEX.with(|pk| pk.borrow().clone());

    // Convert from DER to raw format
    let raw_key = hex::decode(&public_key)
        .map_err(|e| format!("Invalid hex format: {}", e))
        .unwrap_or_else(|e| ic_cdk::trap(&e));

    // The public key is already in the correct format (33 bytes)
    // No need to extract from DER format
    hex::encode(raw_key)
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
    r#"# Asymmetric Identity Certifier

GitHub: https://github.com/ClainoLabs/asymmetric-identity-certifier

## Purpose
This canister provides a way to certify Internet Computer identities using asymmetric cryptography. While not bulletproof (as node providers could potentially access the asymmetric key), it provides a sufficient barrier to prevent random DApps from using your canister for identity validation without contributing to its cycles consumption.

## Flow
1. **Initialization**
   - The canister is initialized with an AES symmetric encryption key
   - The controller initializes the ECDSA key using `init_ecdsa_key`
   - The canister stores the ECDSA public key for future signature verification

2. **Certificate Generation**
   - When a user calls `get_certified_identity`, the canister:
     - Creates a certificate containing their principal ID and current timestamp
     - Signs this certificate using ECDSA (secp256k1)
     - Encrypts the entire certificate (including signature) using AES-GCM
     - Returns the encrypted data as a hex string

3. **Certificate Decryption**
   - The encrypted certificate can be decrypted using the AES key
   - The decrypted certificate contains:
     - The user's principal ID
     - A timestamp of when the certificate was issued
     - An ECDSA signature from the canister

4. **Signature Validation**
   - The signature can be verified using the canister's ECDSA public key
   - This ensures the certificate was actually issued by this canister

## Return Types

### get_certified_identity
Returns a hex string containing:
- First 12 bytes: AES-GCM nonce (derived from timestamp and caller)
- Remaining bytes: Encrypted certificate data
  - The encrypted data contains a JSON string with:
    - principal_id: The caller's principal ID
    - certificate: Object containing principal and timestamp
    - issuer_signature: ECDSA signature in hex format

### get_ecdsa_public_key_hex
Returns a hex string containing the raw ECDSA public key (33 bytes) used for signature verification.

### init_ecdsa_key
Returns the same as get_ecdsa_public_key_hex after initializing the key.

## Security Considerations
- The AES key is used for encryption only
- The ECDSA key is used for signing only
- Each certificate is encrypted with a unique nonce
- The nonce is derived from the timestamp and caller's principal
- Anonymous principals are not allowed to make calls
- Only the controller can initialize the ECDSA key"#.to_string()
}

// Helper function to compute SHA-256 hash
fn sha256(data: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::default();
    hasher.update(data);
    hasher.finalize().to_vec()
}

// Generate did files
ic_cdk::export_candid!();
