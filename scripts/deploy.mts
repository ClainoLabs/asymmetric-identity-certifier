import { captureDeployArgs, deployCanister } from './utils/deploy-utils.js';

const { argument, isReinstall } = await captureDeployArgs();

deployCanister(argument, isReinstall);
