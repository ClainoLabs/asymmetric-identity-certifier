import { execSync } from 'child_process';
import inquirer from 'inquirer';
import { getAesSymmetricEncryptionKey } from './get-aes-key-from-input.js';
import { getIdentityFromSeed } from './identity-from-seed.js';
import { promptIdentitySeed } from './identity-from-seed.js';
import type { InitArgs } from '../../src/declarations/asymmetric_identity_certifier.did.js';

export const buildArgument = (input: InitArgs) => {
  return `'(record {aes_symmetric_encryption_key_hex="${input.aes_symmetric_encryption_key_hex}"; local_mode=${input.local_mode}; controller_principal_id="${input.controller_principal_id}"})'`;
};

export const captureDeployArgs = async () => {
  // 1. Ask for the key pair input
  const aesSymmetricEncryptionKeyHex = await getAesSymmetricEncryptionKey();

  // 2. Ask whether to deploy in local mode
  const { localMode } = await inquirer.prompt<{
    localMode: boolean;
  }>([
    {
      type: 'confirm',
      name: 'localMode',
      message: 'Do you want to deploy in local mode?',
      default: false,
    },
  ]);

  const identitySeed = await promptIdentitySeed();

  const identity = getIdentityFromSeed(identitySeed);

  const controller = identity.getPrincipal().toText();

  const argument = buildArgument({
    aes_symmetric_encryption_key_hex: aesSymmetricEncryptionKeyHex,
    local_mode: localMode,
    controller_principal_id: controller,
  });

  const { isReinstall } = await inquirer.prompt<{
    isReinstall: boolean;
  }>([
    {
      type: 'confirm',
      name: 'isReinstall',
      message:
        'Do you want to reinstall the canister? All existing data will be lost.',
      default: false,
    },
  ]);

  const network = localMode ? undefined : 'ic';

  return { argument, isReinstall, network };
};

export const deployCanister = (
  argument: string,
  isReinstall: boolean,
  network?: string
) => {
  // 3. Deploy the canister
  const command = [
    'dfx deploy asymmetric_identity_certifier ',
    isReinstall ? '--mode reinstall --yes ' : '',
    '--argument ',
    argument,
    network ? ` --network ${network} ` : '',
  ].join('');

  console.log('Deploying canister with command:\n', command, '\n');

  // 4. Execute the command
  execSync(command, { stdio: 'inherit', encoding: 'utf-8' });

  console.log('Canister deployed successfully');
};
