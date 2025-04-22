import inquirer from 'inquirer';
import clipboard from 'clipboardy';
import { getKeyPairFromInput } from './utils/get-key-pair-from-input.js';

const { privateKeyHex, publicKeyHex } = await getKeyPairFromInput();

// 4. Output results
console.log('\nPublic Key (hex):', publicKeyHex);
console.log('\nPrivate Key (hex):', privateKeyHex);

// 5. Ask to copy to clipboard
const { copy } = await inquirer.prompt<{
  copy: boolean;
}>([
  {
    type: 'confirm',
    name: 'copy',
    message: 'Do you want to copy the public key to your clipboard?',
    default: true,
  },
]);

if (copy) {
  clipboard.writeSync(publicKeyHex);
}

console.log('Public key copied to clipboard');
