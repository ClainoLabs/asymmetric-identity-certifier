import { Ed25519KeyIdentity } from '@dfinity/identity';
import { createHash } from 'crypto';
import inquirer from 'inquirer';

export const promptIdentitySeed = async () => {
  const { identitySeed } = await inquirer.prompt<{
    identitySeed: string;
  }>([
    {
      type: 'input',
      name: 'identitySeed',
      message:
        'Please provide the identity seed (plain text). This will be hashed and used as the identity for the controller.',
    },
  ]);

  return identitySeed;
};

export const getIdentityFromSeed = (identitySeed: string) => {
  const identityHash = createHash('sha256').update(identitySeed).digest();

  const identityArrayBuffer = new Uint8Array(identityHash);

  return Ed25519KeyIdentity.generate(identityArrayBuffer);
};
