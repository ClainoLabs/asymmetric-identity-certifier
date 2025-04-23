import inquirer from 'inquirer';
import { getAesSymmetricEncryptionKey } from './utils/get-aes-key-from-input.js';
import {
  getIdentityFromSeed,
  promptIdentitySeed,
} from './utils/identity-from-seed.js';

const aesSymmetricEncryptionKeyHex = await getAesSymmetricEncryptionKey();

console.log('aesSymmetricEncryptionKeyHex', aesSymmetricEncryptionKeyHex);

const identitySeed = await promptIdentitySeed();

console.log('identitySeed', identitySeed);

const identity = getIdentityFromSeed(identitySeed);

const principal = identity.getPrincipal();

console.log('principal', principal.toText());
