require("@nomicfoundation/hardhat-chai-matchers");
require("@nomicfoundation/hardhat-ethers");

const LOCAL_CHAIN_ID = 31337;
const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "hardhat"]);

// ProvenanceX anchors on a local chain only, so any other RPC host stops Hardhat from starting.
function localRpcUrl() {
  const url = new URL(process.env.BLOCKCHAIN_RPC_URL || "http://localhost:8545");
  if (url.protocol !== "http:" || !LOCAL_HOSTS.has(url.hostname)) {
    throw new Error("BLOCKCHAIN_RPC_URL must be a local http URL (localhost, 127.0.0.1 or hardhat)");
  }
  return url.toString();
}

// The key comes only from the environment. Without one, no deployment account exists.
const privateKey = process.env.BLOCKCHAIN_PRIVATE_KEY;

module.exports = {
  solidity: {
    version: "0.8.28",
    settings: { optimizer: { enabled: true, runs: 200 } },
  },
  networks: {
    hardhat: { chainId: LOCAL_CHAIN_ID },
    provenancex: {
      url: localRpcUrl(),
      chainId: LOCAL_CHAIN_ID,
      accounts: privateKey ? [privateKey] : [],
    },
  },
};
