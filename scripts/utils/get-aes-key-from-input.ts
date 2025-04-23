import inquirer from 'inquirer';
import { createHash } from 'crypto';
import { bytesToHex } from './bytes-to-hex.js';

export async function getAesSymmetricEncryptionKey() {
  // 1. Input string
  const { input } = await inquirer.prompt<{
    input: string;
  }>([
    {
      type: 'input',
      name: 'input',
      message:
        'Please provide an input string. This will be hashed and used as the AES symmetric encryption key.',
    },
  ]);

  if (!input) {
    console.error(
      'Please provide an input string: `npm run get-key-pair <input>`'
    );
    process.exit(1);
  }

  console.log('Input:', input);

  return generateAesSymmetricEncryptionKeyHex(input);
}

export const generateAesSymmetricEncryptionKeyHex = (input: string) => {
  // 1. Derive 32-byte private key from input
  const hash = createHash('sha256').update(input).digest(); // Node.js Buffer (also Uint8Array-compatible)

  const aesSymmetricEncryptionKeyHex = bytesToHex(hash);

  return aesSymmetricEncryptionKeyHex;
};
