import { buildArgument, deployCanister } from './utils/deploy-utils.js';
import { execSync } from 'child_process';
import { generateAesSymmetricEncryptionKeyHex } from './utils/get-aes-key-from-input.js';
import { decryptCertificate } from './utils/decrypt-certificate.js';
import { validateSignature } from './utils/validate-signature.js';
import assert from 'assert';

const cleanupStringResponse = (response: string) => {
  return response
    .replaceAll('"', '')
    .replaceAll('(', '')
    .replaceAll(')', '')
    .replaceAll(',', '')
    .trim();
};

const initialIdentity = execSync(`dfx identity whoami`, {
  encoding: 'utf-8',
});

const identityPrincipal = execSync(`dfx identity get-principal`, {
  encoding: 'utf-8',
}).trim();

console.log('Initial Identity:', initialIdentity);

const aesSymmetricEncryptionKeyHex =
  generateAesSymmetricEncryptionKeyHex('test');

deployCanister(
  buildArgument({
    aes_symmetric_encryption_key_hex: aesSymmetricEncryptionKeyHex,
    local_mode: true,
    controller_principal_id: identityPrincipal,
  }),
  true
);

const pubKeyResult = cleanupStringResponse(
  execSync(`dfx canister call asymmetric_identity_certifier init_ecdsa_key`, {
    encoding: 'utf-8',
  })
);

// call the get_ecdsa_public_key_hex method in the canister

const getPubKeyResult = cleanupStringResponse(
  execSync(
    `dfx canister call asymmetric_identity_certifier get_ecdsa_public_key_hex`,
    {
      encoding: 'utf-8',
    }
  )
);

assert(
  pubKeyResult === getPubKeyResult,
  'Get public key result does not match init public key result'
);

console.log('Public Key:', pubKeyResult);

// generate identity asymmetric_identity_certifier_test
execSync('dfx identity new asymmetric_identity_certifier_test', {
  stdio: 'inherit',
  encoding: 'utf-8',
});

// set the identity asymmetric_identity_certifier_test as the current identity
execSync('dfx identity use asymmetric_identity_certifier_test', {
  stdio: 'inherit',
  encoding: 'utf-8',
});

// call the get_certified_identity method in the canister
const certificateCommand = `dfx canister call asymmetric_identity_certifier get_certified_identity`;
const encryptedCertificate = cleanupStringResponse(
  execSync(certificateCommand, {
    encoding: 'utf-8',
  })
);

console.log('Encrypted Certificate:', encryptedCertificate);

// cleanup identities

execSync(`dfx identity use ${initialIdentity}`, {
  stdio: 'inherit',
  encoding: 'utf-8',
});

// delete the identity asymmetric_identity_certifier_test
execSync(`dfx identity remove asymmetric_identity_certifier_test`, {
  stdio: 'inherit',
  encoding: 'utf-8',
});

// Decrypt and log the certificate
const decryptedCertificate = decryptCertificate(
  encryptedCertificate,
  aesSymmetricEncryptionKeyHex
);

console.log(
  'Decrypted Certificate:',
  JSON.stringify(decryptedCertificate, null, 2)
);

// validate the signature
const isValid = validateSignature(decryptedCertificate, pubKeyResult);
console.log('Is Valid:', isValid);
assert(isValid, 'Signature is not valid');
