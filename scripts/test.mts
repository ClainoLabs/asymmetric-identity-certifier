import { generateKeyPair } from './utils/get-key-pair-from-input.js';
import { deployCanister } from './utils/deploy-utils.js';
import { execSync } from 'child_process';
import * as secp from '@noble/secp256k1';

const cleanupStringResponse = (response: string) => {
  return response.replaceAll('"', '').replaceAll('(', '').replaceAll(')', '');
};

const initialIdentity = execSync(`dfx identity whoami`, {
  encoding: 'utf-8',
});

console.log('Initial Identity:', initialIdentity);

const { privateKeyHex, publicKeyHex } = generateKeyPair('test');

deployCanister(
  `'(record {public_key_hex="${publicKeyHex}"; local_mode=true})'`,
  true
);

// call the init_ecdsa_key method in the canister
const command = `dfx canister call asymmetric_identity_certifier init_ecdsa_key`;
execSync(command, { stdio: 'inherit', encoding: 'utf-8' });

// call the get_ecdsa_public_key_hex method in the canister
const pubKeyCommand = `dfx canister call asymmetric_identity_certifier get_ecdsa_public_key_hex`;
const pubKeyResult = cleanupStringResponse(
  execSync(pubKeyCommand, {
    encoding: 'utf-8',
  })
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

// call the get_ecdsa_public_key_hex method in the canister
const certificateCommand = `dfx canister call asymmetric_identity_certifier get_ecdsa_public_key_hex`;
const certificateResult = cleanupStringResponse(
  execSync(certificateCommand, {
    encoding: 'utf-8',
  })
);

console.log('Certificate:', certificateResult);

// delete the identity asymmetric_identity_certifier_test
execSync(
  `dfx identity use ${initialIdentity} && dfx identity remove asymmetric_identity_certifier_test`,
  {
    stdio: 'inherit',
    encoding: 'utf-8',
  }
);

