import { useCallback } from "react";
import useApi from "../../hooks/useApi.js";
import { NOT_RECORDED, formatDateTime, formatRiskScore, humanize } from "../../lib/format.js";
import { sanitizeDisplay } from "../../lib/sanitizeDisplay.js";
import { api } from "../../services/api.js";
import EmptyState from "../EmptyState.jsx";
import ErrorState from "../ui/ErrorState.jsx";
import HashValue from "../ui/HashValue.jsx";
import LoadingState from "../ui/LoadingState.jsx";
import MockLabel from "../ui/MockLabel.jsx";

function Row({ label, children }) {
  return (
    <div className="dl__row">
      <dt>{label}</dt>
      <dd>{children}</dd>
    </div>
  );
}

const plain = (value) => (value === null || value === undefined ? NOT_RECORDED : String(value));

function epochToIso(seconds) {
  return typeof seconds === "number" && Number.isFinite(seconds) ? new Date(seconds * 1000).toISOString() : null;
}

function Record({ record }) {
  const isMock = record.is_mock === true || record.source === "mock";
  const missing = Array.isArray(record.missing_evidence) ? record.missing_evidence : [];
  return (
    <dl className="dl">
      <Row label="Anchor status">
        {humanize(sanitizeDisplay(record.status))} <MockLabel isMock={isMock} />
      </Row>
      {record.error_code ? (
        <Row label="Error code">
          <code>{sanitizeDisplay(record.error_code)}</code>
        </Row>
      ) : null}
      <Row label="Source">{sanitizeDisplay(record.source)}</Row>
      <Row label="Transaction">
        <HashValue kind={isMock ? "mockTx" : "tx"} value={record.tx_hash} label="transaction" reason={NOT_RECORDED} />
      </Row>
      <Row label="Block number">{plain(record.block_number)}</Row>
      <Row label="Block hash">
        <HashValue kind="tx" value={record.block_hash} label="block hash" reason={NOT_RECORDED} />
      </Row>
      <Row label="Anchor index">{plain(record.anchor_index)}</Row>
      <Row label="Chain ID">{plain(record.chain_id)}</Row>
      <Row label="Contract">
        <HashValue kind="address" value={record.contract_address} label="contract address" reason={NOT_RECORDED} />
      </Row>
      <Row label="Anchored at">{formatDateTime(record.anchored_at)}</Row>
      <Row label="Artifact ID">
        <HashValue kind="uuid" value={record.artifact_id} label="artifact ID" reason={NOT_RECORDED} />
      </Row>
      <Row label="Artifact hash">
        <HashValue value={record.artifact_hash} label="artifact hash" reason={NOT_RECORDED} />
      </Row>
      <Row label="BOM hash">
        <HashValue value={record.bom_hash} label="BOM hash" reason="Absent when anchored" />
      </Row>
      <Row label="Provenance hash">
        <HashValue value={record.provenance_hash} label="provenance hash" reason="Absent when anchored" />
      </Row>
      <Row label="Record hash (off-chain)">
        <HashValue value={record.record_hash} label="record hash" reason={NOT_RECORDED} />
      </Row>
      <Row label="ProvenanceX risk when anchored">{formatRiskScore(record.risk_score)}</Row>
      <Row label="Decision when anchored">{sanitizeDisplay(record.decision)}</Row>
      <Row label="Scanner version">{sanitizeDisplay(record.scanner_version)}</Row>
      <Row label="Evidence time">{formatDateTime(epochToIso(record.evidence_timestamp))}</Row>
      {missing.length ? (
        <Row label="Absent evidence">{missing.map((name) => humanize(sanitizeDisplay(name))).join(", ")}</Row>
      ) : null}
    </dl>
  );
}

/** What is stored about the anchor. It says nothing about whether the record still holds. */
export default function AnchorRecord({ scanId }) {
  const fetcher = useCallback((options) => api.getBlockchain(scanId, options), [scanId]);
  const { status, data, error, reload } = useApi(fetcher);

  if (status === "error") return <ErrorState error={error} onRetry={reload} title="Could not load the anchor record" />;
  if (!data) return <LoadingState label="Loading the anchor record" />;
  if (!data.record) {
    return (
      <EmptyState
        title="No anchor recorded"
        message="Anchoring happens on the server when it is enabled. It cannot be started from the dashboard."
        headingLevel={3}
      />
    );
  }
  return (
    <>
      <Record record={data.record} />
      {data.note ? <p className="state__message panel__section">{sanitizeDisplay(data.note)}</p> : null}
    </>
  );
}
