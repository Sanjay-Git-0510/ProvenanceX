import { formatDateTime, humanize, isAllowedSourceUrl, NOT_AVAILABLE } from "../../lib/format.js";
import { sanitizeDisplay } from "../../lib/sanitizeDisplay.js";
import Badge from "../ui/Badge.jsx";
import HashValue from "../ui/HashValue.jsx";
import Panel from "../ui/Panel.jsx";

function integrity(provenance) {
  if (provenance?.hash_changed === true) return <Badge tone="block">HASH CHANGED since the prior scan</Badge>;
  if (provenance?.hash_changed === false) return <Badge tone="allow">Unchanged since the prior scan</Badge>;
  return <Badge tone="unknown">Not determined (no prior scan to compare)</Badge>;
}

function Row({ label, children }) {
  return (
    <div className="dl__row">
      <dt>{label}</dt>
      <dd>{children}</dd>
    </div>
  );
}

export default function ArtifactIdentity({ evidence, className }) {
  const { artifact, hashes, provenance, scanner_version: scannerVersion } = evidence;
  const url = artifact.source_url;
  return (
    <Panel title="Artifact identity and integrity" className={className}>
      <dl className="dl">
        <Row label="Artifact ID">
          <HashValue kind="uuid" value={artifact.artifact_id} label="artifact ID" truncate />
        </Row>
        <Row label="Scan ID">
          <HashValue kind="uuid" value={artifact.scan_id} label="scan ID" truncate />
        </Row>
        <Row label="Type">{humanize(artifact.artifact_type)}</Row>
        <Row label="Version or revision">{sanitizeDisplay(artifact.version) || NOT_AVAILABLE}</Row>
        <Row label="Source">
          {isAllowedSourceUrl(url) ? (
            <a href={url} target="_blank" rel="noopener noreferrer">
              {sanitizeDisplay(url)}
            </a>
          ) : (
            humanize(artifact.source)
          )}
        </Row>
        <Row label="Collected">{formatDateTime(artifact.collected_at)}</Row>
        <Row label="Scanner version">{sanitizeDisplay(scannerVersion) || NOT_AVAILABLE}</Row>
        <Row label="Integrity">{integrity(provenance)}</Row>
        <Row label="Artifact SHA-256">
          <HashValue value={hashes.artifact_sha256.value} reason={sanitizeDisplay(hashes.artifact_sha256.reason)} label="artifact hash" />
        </Row>
        <Row label="BOM SHA-256">
          <HashValue value={hashes.bom_sha256.value} reason={sanitizeDisplay(hashes.bom_sha256.reason)} label="BOM hash" />
        </Row>
        <Row label="Provenance record SHA-256">
          <HashValue
            value={hashes.provenance_record_sha256.value}
            reason={sanitizeDisplay(hashes.provenance_record_sha256.reason)}
            label="provenance hash"
          />
        </Row>
        <Row label="Sandbox trace SHA-256">
          <HashValue
            value={hashes.sandbox_trace_sha256.value}
            reason={sanitizeDisplay(hashes.sandbox_trace_sha256.reason)}
            label="sandbox trace hash"
          />
        </Row>
      </dl>
    </Panel>
  );
}
