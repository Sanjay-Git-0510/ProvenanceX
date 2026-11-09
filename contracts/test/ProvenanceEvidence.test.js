const { expect } = require("chai");
const { ethers } = require("hardhat");

const ID = "0x11111111111111111111111111111111";
const OTHER_ID = "0x22222222222222222222222222222222";
const ZERO_ID = "0x00000000000000000000000000000000";
const hash = (byte) => `0x${byte.repeat(32)}`;
const ZERO_HASH = ethers.ZeroHash;

const NO_SCORE = 2n ** 32n - 1n;
const SCORE_SCALE = 1_000_000n;
const Decision = { NONE: 0, ALLOW: 1, REVIEW: 2, BLOCK: 3 };

describe("ProvenanceEvidence", () => {
  let contract;
  let deployer;
  let stranger;

  const fields = (overrides = {}) => {
    const merged = {
      artifactId: ID,
      artifactHash: hash("aa"),
      bomHash: hash("bb"),
      provenanceHash: hash("cc"),
      riskScore: 700_000,
      decision: Decision.REVIEW,
      scannerVersion: "0.1.0",
      timestamp: 1_790_000_000,
      ...overrides,
    };
    return [
      merged.artifactId,
      merged.artifactHash,
      merged.bomHash,
      merged.provenanceHash,
      merged.riskScore,
      merged.decision,
      merged.scannerVersion,
      merged.timestamp,
    ];
  };

  beforeEach(async () => {
    [deployer, stranger] = await ethers.getSigners();
    contract = await ethers.deployContract("ProvenanceEvidence");
    await contract.waitForDeployment();
  });

  describe("storing an anchor", () => {
    it("stores and returns all eight fields", async () => {
      await contract.anchor(...fields());
      const stored = await contract.getAnchor(ID, 0);
      expect(stored.artifactId).to.equal(ID);
      expect(stored.artifactHash).to.equal(hash("aa"));
      expect(stored.bomHash).to.equal(hash("bb"));
      expect(stored.provenanceHash).to.equal(hash("cc"));
      expect(stored.riskScore).to.equal(700_000n);
      expect(stored.decision).to.equal(BigInt(Decision.REVIEW));
      expect(stored.scannerVersion).to.equal("0.1.0");
      expect(stored.timestamp).to.equal(1_790_000_000n);
    });

    it("emits one event carrying every field", async () => {
      await expect(contract.anchor(...fields()))
        .to.emit(contract, "EvidenceAnchored")
        .withArgs(
          ID,
          0,
          hash("aa"),
          hash("bb"),
          hash("cc"),
          700_000,
          Decision.REVIEW,
          "0.1.0",
          1_790_000_000,
        );
    });

    it("stores the caller's timestamp, not the block time", async () => {
      await contract.anchor(...fields({ timestamp: 1 }));
      expect((await contract.getAnchor(ID, 0)).timestamp).to.equal(1n);
    });

    for (const name of ["ALLOW", "REVIEW", "BLOCK"]) {
      it(`accepts the ${name} decision`, async () => {
        await contract.anchor(...fields({ decision: Decision[name] }));
        expect((await contract.getAnchor(ID, 0)).decision).to.equal(BigInt(Decision[name]));
      });
    }
  });

  describe("null risk score", () => {
    it("exposes the sentinel and the scale", async () => {
      expect(await contract.NO_SCORE()).to.equal(NO_SCORE);
      expect(await contract.SCORE_SCALE()).to.equal(SCORE_SCALE);
    });

    it("keeps a null score distinct from a real 0", async () => {
      await contract.anchor(...fields({ riskScore: NO_SCORE }));
      await contract.anchor(...fields({ riskScore: 0 }));
      expect((await contract.getAnchor(ID, 0)).riskScore).to.equal(NO_SCORE);
      expect((await contract.getAnchor(ID, 1)).riskScore).to.equal(0n);
    });

    it("allows a null score beside a REVIEW or BLOCK decision", async () => {
      for (const decision of [Decision.REVIEW, Decision.BLOCK]) {
        await expect(contract.anchor(...fields({ riskScore: NO_SCORE, decision }))).to.emit(
          contract,
          "EvidenceAnchored",
        );
      }
    });

    it("accepts the top of the valid range", async () => {
      await contract.anchor(...fields({ riskScore: SCORE_SCALE }));
      expect((await contract.getAnchor(ID, 0)).riskScore).to.equal(SCORE_SCALE);
    });

    for (const value of [SCORE_SCALE + 1n, NO_SCORE - 1n]) {
      it(`rejects the out-of-range score ${value}`, async () => {
        await expect(contract.anchor(...fields({ riskScore: value })))
          .to.be.revertedWithCustomError(contract, "InvalidRiskScore")
          .withArgs(value);
      });
    }
  });

  describe("absent hashes", () => {
    it("stores the zero marker for a missing BOM hash", async () => {
      await contract.anchor(...fields({ bomHash: ZERO_HASH }));
      expect((await contract.getAnchor(ID, 0)).bomHash).to.equal(ZERO_HASH);
    });

    it("stores the zero marker for a missing provenance hash", async () => {
      await contract.anchor(...fields({ provenanceHash: ZERO_HASH }));
      expect((await contract.getAnchor(ID, 0)).provenanceHash).to.equal(ZERO_HASH);
    });

    it("always refuses a missing artifact hash", async () => {
      await expect(
        contract.anchor(...fields({ artifactHash: ZERO_HASH })),
      ).to.be.revertedWithCustomError(contract, "ZeroArtifactHash");
    });
  });

  describe("input validation", () => {
    it("refuses a zero artifact id", async () => {
      await expect(
        contract.anchor(...fields({ artifactId: ZERO_ID })),
      ).to.be.revertedWithCustomError(contract, "ZeroArtifactId");
    });

    it("refuses the NONE decision", async () => {
      await expect(
        contract.anchor(...fields({ decision: Decision.NONE })),
      ).to.be.revertedWithCustomError(contract, "InvalidDecision");
    });

    it("refuses a decision outside the enum", async () => {
      await expect(contract.anchor(...fields({ decision: 4 }))).to.be.reverted;
    });

    it("refuses an empty scanner version", async () => {
      await expect(
        contract.anchor(...fields({ scannerVersion: "" })),
      ).to.be.revertedWithCustomError(contract, "InvalidScannerVersion");
    });

    it("accepts a 32-byte scanner version and refuses 33 bytes", async () => {
      await contract.anchor(...fields({ scannerVersion: "v".repeat(32) }));
      await expect(
        contract.anchor(...fields({ scannerVersion: "v".repeat(33) })),
      ).to.be.revertedWithCustomError(contract, "InvalidScannerVersion");
    });

    it("refuses a zero timestamp", async () => {
      await expect(contract.anchor(...fields({ timestamp: 0 }))).to.be.revertedWithCustomError(
        contract,
        "ZeroTimestamp",
      );
    });

    it("stores nothing when a call is refused", async () => {
      await expect(contract.anchor(...fields({ timestamp: 0 }))).to.be.reverted;
      expect(await contract.anchorCount(ID)).to.equal(0n);
    });
  });

  describe("deployer-only anchoring", () => {
    it("records the deployer as the anchorer", async () => {
      expect(await contract.anchorer()).to.equal(deployer.address);
    });

    it("refuses any other account and stores nothing", async () => {
      await expect(contract.connect(stranger).anchor(...fields()))
        .to.be.revertedWithCustomError(contract, "NotAnchorer")
        .withArgs(stranger.address);
      expect(await contract.anchorCount(ID)).to.equal(0n);
    });

    it("lets anyone read an anchor", async () => {
      await contract.anchor(...fields());
      expect((await contract.connect(stranger).getAnchor(ID, 0)).artifactHash).to.equal(hash("aa"));
    });
  });

  describe("append-only history", () => {
    it("appends and leaves earlier anchors unchanged", async () => {
      await contract.anchor(...fields({ artifactHash: hash("01") }));
      await contract.anchor(...fields({ artifactHash: hash("02"), riskScore: NO_SCORE }));
      expect(await contract.anchorCount(ID)).to.equal(2n);
      const first = await contract.getAnchor(ID, 0);
      expect(first.artifactHash).to.equal(hash("01"));
      expect(first.riskScore).to.equal(700_000n);
      expect((await contract.getAnchor(ID, 1)).artifactHash).to.equal(hash("02"));
    });

    it("numbers each event by its position", async () => {
      await contract.anchor(...fields());
      await expect(contract.anchor(...fields()))
        .to.emit(contract, "EvidenceAnchored")
        .withArgs(
          ID,
          1,
          hash("aa"),
          hash("bb"),
          hash("cc"),
          700_000,
          Decision.REVIEW,
          "0.1.0",
          1_790_000_000,
        );
    });

    it("keeps artifacts separate", async () => {
      await contract.anchor(...fields());
      expect(await contract.anchorCount(OTHER_ID)).to.equal(0n);
    });

    it("reports an unknown index with a typed error", async () => {
      await expect(contract.getAnchor(ID, 0))
        .to.be.revertedWithCustomError(contract, "AnchorIndexOutOfRange")
        .withArgs(ID, 0);
    });
  });

  describe("interface", () => {
    const abiItems = (type) => contract.interface.fragments.filter((item) => item.type === type);

    it("has anchor as its only state-changing function", () => {
      const writers = abiItems("function").filter((item) => !item.constant);
      expect(writers.map((item) => item.name)).to.deep.equal(["anchor"]);
    });

    it("stores exactly the eight allowed fields", () => {
      const getter = abiItems("function").find((item) => item.name === "getAnchor");
      expect(getter.outputs[0].components.map((item) => item.name)).to.deep.equal([
        "artifactId",
        "artifactHash",
        "bomHash",
        "provenanceHash",
        "riskScore",
        "decision",
        "scannerVersion",
        "timestamp",
      ]);
    });

    it("emits only the eight fields plus the history position", () => {
      expect(abiItems("event")).to.have.length(1);
      expect(abiItems("event")[0].inputs.map((item) => item.name)).to.deep.equal([
        "artifactId",
        "anchorIndex",
        "artifactHash",
        "bomHash",
        "provenanceHash",
        "riskScore",
        "decision",
        "scannerVersion",
        "timestamp",
      ]);
    });
  });
});
