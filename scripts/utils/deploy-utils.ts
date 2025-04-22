import { execSync } from 'child_process';
import inquirer from 'inquirer';
import { getKeyPairFromInput } from '../utils/get-key-pair-from-input.js';

export const captureDeployArgs = async () => {
  // 1. Ask for the key pair input
  const { publicKeyHex } = await getKeyPairFromInput();

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

  const argument = `'(record {public_key_hex="${publicKeyHex}"; local_mode=${localMode}})'`;

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

  return { argument, isReinstall };
};

export const deployCanister = (argument: string, isReinstall: boolean) => {
  // 3. Deploy the canister
  const command = [
    'dfx deploy asymmetric_identity_certifier ',
    isReinstall ? '--mode reinstall --yes ' : '',
    '--argument ',
    argument,
  ].join('');

  console.log('Deploying canister with command:\n', command, '\n');

  // 4. Execute the command
  execSync(command, { stdio: 'inherit', encoding: 'utf-8' });

  console.log('Canister deployed successfully');
};
