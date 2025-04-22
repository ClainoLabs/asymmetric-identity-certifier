import inquirer from 'inquirer';
import { createHash } from 'crypto';
import { etc, getPublicKey } from '@noble/secp256k1';

export async function getKeyPairFromInput() {
  // 1. Input string
  const { input } = await inquirer.prompt<{
    input: string;
  }>([
    {
      type: 'input',
      name: 'input',
      message:
        'Please provide an input string. This will be hashed and used as the private key.',
    },
  ]);

  if (!input) {
    console.error(
      'Please provide an input string: `npm run get-key-pair <input>`'
    );
    process.exit(1);
  }

  console.log('Input:', input);

  return generateKeyPair(input);
}

export const generateKeyPair = (input: string) => {
  // 1. Derive 32-byte private key from input
  const hash = createHash('sha256').update(input).digest(); // Node.js Buffer (also Uint8Array-compatible)
  const privateKey = new Uint8Array(hash);

  // 2. Generate public key (uncompressed = 65 bytes)
  const publicKey = getPublicKey(privateKey, false); // false = uncompressed

  const privateKeyHex = etc.bytesToHex(privateKey);
  const publicKeyHex = etc.bytesToHex(publicKey);

  return { privateKeyHex, publicKeyHex };
};
