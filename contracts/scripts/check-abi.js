// Fails unless the backend's abi.json matches the compiled contract. Usage: check-abi.js <path>
const fs = require("fs");
const path = require("path");

const ARTIFACT = path.join(
  __dirname,
  "../artifacts/contracts/ProvenanceEvidence.sol/ProvenanceEvidence.json",
);

const target = process.argv[2];
if (!target) {
  console.error("Usage: node scripts/check-abi.js <path to abi.json>");
  process.exit(1);
}
const compiled = JSON.parse(fs.readFileSync(ARTIFACT, "utf8")).abi;
const backend = JSON.parse(fs.readFileSync(target, "utf8"));
if (JSON.stringify(compiled) !== JSON.stringify(backend)) {
  console.error(`ABI mismatch: ${target} differs from the compiled contract`);
  process.exit(1);
}
console.log(`ABI matches the compiled contract (${compiled.length} entries)`);
