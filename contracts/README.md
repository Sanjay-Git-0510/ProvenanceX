# contracts/

The `ProvenanceEvidence` Solidity contract and its Hardhat project (Hardhat 2.29.1, Node 22).
It is for a **local chain only**: Hardhat refuses a non-local `BLOCKCHAIN_RPC_URL`, and the deploy
script refuses any chain id other than 31337.

## What goes on-chain

Only these eight fields:

| Field | Type | Rule |
|---|---|---|
| `artifactId` | `bytes16` | The artifact UUID. Must be non-zero. |
| `artifactHash` | `bytes32` | Must be non-zero. A missing artifact hash is always refused. |
| `bomHash` | `bytes32` | `bytes32(0)` means absent. It does not mean clean. |
| `provenanceHash` | `bytes32` | `bytes32(0)` means absent. It does not mean clean. |
| `riskScore` | `uint32` | Score x 1,000,000, or `NO_SCORE`. |
| `decision` | enum | `ALLOW=1`, `REVIEW=2`, `BLOCK=3`. `NONE=0` is refused. |
| `scannerVersion` | `string` | 1 to 32 bytes. |
| `timestamp` | `uint64` | UTC seconds supplied by the anchoring service, not the block time. |

**A null score is never a 0.** `NO_SCORE` (`type(uint32).max`) means no score was computed, and 0
is a real score of 0. Values between 1,000,001 and `NO_SCORE - 1` are refused. A null score can sit
beside a REVIEW or BLOCK decision.

Anchors are append-only: `anchor` is the only state-changing function, and each call emits one
`EvidenceAnchored` event. Only the deploying account can anchor. Anyone can read.

An anchor shows that a record has not been rewritten. It does not show that the scanner was correct.

## Run the tests

From the repository root, in the pinned image:

```bash
docker compose build hardhat
docker compose run --rm --no-deps hardhat npx hardhat test --no-compile
```

## Start the chain and deploy

```bash
docker compose up -d --wait hardhat
docker compose logs hardhat | grep -m1 "Private Key"
```

Put that test key in your git-ignored `.env` as `BLOCKCHAIN_PRIVATE_KEY`, then deploy:

```bash
docker compose --profile chain-deploy run --rm hardhat-deploy
```

Copy `contract_address` from the output into `.env` as `BLOCKCHAIN_CONTRACT_ADDRESS`.

The keys printed by Hardhat are public test keys. Never use a real key, or one holding real funds.

**The chain runs in memory.** Restarting the `hardhat` service erases every anchor and the contract,
so you must deploy again.
