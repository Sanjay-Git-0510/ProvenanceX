// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @title ProvenanceEvidence
/// @notice Append-only record of compact ProvenanceX scan evidence, for a local Hardhat chain.
/// @dev Holds exactly eight fields per anchor. SBOMs, traces, source and model files stay
///      off-chain. An anchor shows that a record has not been rewritten. It does not show
///      that the scanner was correct.
contract ProvenanceEvidence {
    /// @dev NONE is the zero value, so an unset decision can never be stored as a verdict.
    enum Decision {
        NONE,
        ALLOW,
        REVIEW,
        BLOCK
    }

    struct Anchor {
        bytes16 artifactId;
        bytes32 artifactHash;
        // bytes32(0) means the hash is absent: the scan produced no BOM or provenance record.
        bytes32 bomHash;
        bytes32 provenanceHash;
        // Score multiplied by SCORE_SCALE, or NO_SCORE. A value of 0 is a real score of 0.
        uint32 riskScore;
        Decision decision;
        string scannerVersion;
        // UTC seconds supplied by the anchoring service, not the block time.
        uint64 timestamp;
    }

    uint32 public constant SCORE_SCALE = 1_000_000;
    /// @notice Means "no score was computed". It is outside the valid score range.
    uint32 public constant NO_SCORE = type(uint32).max;
    uint256 public constant MAX_SCANNER_VERSION_BYTES = 32;

    /// @notice The only address allowed to add anchors: the deployer.
    address public immutable anchorer;

    mapping(bytes16 => Anchor[]) private _anchors;

    event EvidenceAnchored(
        bytes16 indexed artifactId,
        uint256 indexed anchorIndex,
        bytes32 artifactHash,
        bytes32 bomHash,
        bytes32 provenanceHash,
        uint32 riskScore,
        Decision decision,
        string scannerVersion,
        uint64 timestamp
    );

    error NotAnchorer(address caller);
    error ZeroArtifactId();
    error ZeroArtifactHash();
    error InvalidRiskScore(uint32 riskScore);
    error InvalidDecision();
    error InvalidScannerVersion();
    error ZeroTimestamp();
    error AnchorIndexOutOfRange(bytes16 artifactId, uint256 index);

    constructor() {
        anchorer = msg.sender;
    }

    /// @notice Append one anchor. Nothing in this contract can change or remove it afterwards.
    /// @return anchorIndex The position of the new anchor in this artifact's history.
    function anchor(
        bytes16 artifactId,
        bytes32 artifactHash,
        bytes32 bomHash,
        bytes32 provenanceHash,
        uint32 riskScore,
        Decision decision,
        string calldata scannerVersion,
        uint64 timestamp
    ) external returns (uint256 anchorIndex) {
        if (msg.sender != anchorer) revert NotAnchorer(msg.sender);
        if (artifactId == bytes16(0)) revert ZeroArtifactId();
        if (artifactHash == bytes32(0)) revert ZeroArtifactHash();
        if (riskScore > SCORE_SCALE && riskScore != NO_SCORE) revert InvalidRiskScore(riskScore);
        if (decision == Decision.NONE) revert InvalidDecision();
        uint256 versionLength = bytes(scannerVersion).length;
        if (versionLength == 0 || versionLength > MAX_SCANNER_VERSION_BYTES) {
            revert InvalidScannerVersion();
        }
        if (timestamp == 0) revert ZeroTimestamp();

        anchorIndex = _anchors[artifactId].length;
        _anchors[artifactId].push(
            Anchor({
                artifactId: artifactId,
                artifactHash: artifactHash,
                bomHash: bomHash,
                provenanceHash: provenanceHash,
                riskScore: riskScore,
                decision: decision,
                scannerVersion: scannerVersion,
                timestamp: timestamp
            })
        );
        emit EvidenceAnchored(
            artifactId,
            anchorIndex,
            artifactHash,
            bomHash,
            provenanceHash,
            riskScore,
            decision,
            scannerVersion,
            timestamp
        );
    }

    function anchorCount(bytes16 artifactId) external view returns (uint256) {
        return _anchors[artifactId].length;
    }

    function getAnchor(bytes16 artifactId, uint256 index) external view returns (Anchor memory) {
        if (index >= _anchors[artifactId].length) revert AnchorIndexOutOfRange(artifactId, index);
        return _anchors[artifactId][index];
    }
}
