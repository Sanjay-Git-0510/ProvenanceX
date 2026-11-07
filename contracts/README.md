# contracts/

This directory will hold the Solidity evidence contract (`ProvenanceEvidence.sol`), the Hardhat config and the deploy scripts.
They arrive in **Phase 7**.

Only these fields go on-chain: `artifact_id, artifact_hash, bom_hash, provenance_hash, risk_score,
decision, scanner_version, timestamp`. Use local Hardhat dev keys only.
