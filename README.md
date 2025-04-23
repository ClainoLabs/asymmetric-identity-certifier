# Asymmetric Identity Certifier

A canister that provides a way to certify Internet Computer identities using asymmetric cryptography. While not bulletproof (as node providers could potentially access the asymmetric key), it provides a sufficient barrier to prevent random DApps from using your canister for identity validation without contributing to its cycles consumption.

## Purpose

This canister serves as a middle ground between completely open identity validation and fully secure identity validation. It's designed to:

1. Make it difficult for unauthorized DApps to use your canister for identity validation
2. Provide a way to verify that a user has a certain identity in only 2 steps (1. get the certificate, 2. decrypt and validate the signature)

## How It Works

### Flow

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

### Return Types

#### get_certified_identity

Returns a hex string containing:

- First 12 bytes: AES-GCM nonce (derived from timestamp and caller)
- Remaining bytes: Encrypted certificate data
  - The encrypted data contains a JSON string with:
    - principal_id: The caller's principal ID
    - certificate: Object containing principal and timestamp
    - issuer_signature: ECDSA signature in hex format

#### get_ecdsa_public_key_hex

Returns a hex string containing the raw ECDSA public key (33 bytes) used for signature verification.

#### init_ecdsa_key

Returns the same as get_ecdsa_public_key_hex after initializing the key.

## Security Considerations

- The AES key is used for encryption only
- The ECDSA key is used for signing only
- Each certificate is encrypted with a unique nonce
- The nonce is derived from the timestamp and caller's principal
- Anonymous principals are not allowed to make calls
- Only the controller can initialize the ECDSA key

## Usage Examples

### Decrypting a Certificate

```typescript
import { decryptCertificate } from './scripts/utils/decrypt-certificate.js';

const encryptedCertificate = await canister.get_certified_identity();
const decryptedCertificate = decryptCertificate(encryptedCertificate, aesKey);
```

### Validating a Signature

```typescript
import { validateSignature } from './scripts/utils/validate-signature.js';

const isValid = validateSignature(decryptedCertificate, publicKey);
```

## Development

### Prerequisites

- Node.js
- DFX
- Rust

### Installation

```bash
npm install
```

### Available Scripts

- `npm run deploy` - Deploy the canister
- `npm run generate` - Generate Candid files
- `npm run test` - Run tests
- `npm run get-deploy-args` - Get deployment arguments

### Deployment

#### Using DFX

```bash
dfx deploy asymmetric_identity_certifier --mode reinstall --yes --argument '(record {
  aes_symmetric_encryption_key_hex="YOUR_AES_KEY_HEX";
  local_mode=true;
  controller_principal_id="YOUR_CONTROLLER_PRINCIPAL"
})'
```

#### Using NPM

```bash
# First, set your AES key in the environment
export AES_KEY="YOUR_AES_KEY"

# Then run the deploy script
npm run deploy
```

### Testing

```bash
npm test
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT
