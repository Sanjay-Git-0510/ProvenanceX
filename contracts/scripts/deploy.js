// Deploys ProvenanceEvidence to the local chain. The deploying account becomes the only anchorer.
const hre = require("hardhat");

const LOCAL_CHAIN_ID = 31337n;

async function main() {
  const { chainId } = await hre.ethers.provider.getNetwork();
  if (chainId !== LOCAL_CHAIN_ID) {
    throw new Error(`Refusing to deploy: chain id ${chainId} is not the local chain`);
  }
  const [deployer] = await hre.ethers.getSigners();
  if (!deployer) {
    throw new Error("BLOCKCHAIN_PRIVATE_KEY is not set. Add a local Hardhat dev key to .env");
  }
  const contract = await hre.ethers.deployContract("ProvenanceEvidence", deployer);
  await contract.waitForDeployment();
  console.log(
    JSON.stringify({
      contract_address: await contract.getAddress(),
      chain_id: Number(chainId),
      anchorer: deployer.address,
      deployment_tx: contract.deploymentTransaction().hash,
    }),
  );
}

main().catch((error) => {
  console.error(`Deployment failed: ${error.message}`);
  process.exitCode = 1;
});
