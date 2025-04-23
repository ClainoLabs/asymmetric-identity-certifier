import { captureDeployArgs, deployCanister } from './utils/deploy-utils.js';

const { argument, isReinstall, network } = await captureDeployArgs();

deployCanister(argument, isReinstall, network);
