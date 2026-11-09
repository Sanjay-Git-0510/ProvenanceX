import { formatProbability, humanize } from "../../lib/format.js";
import { sanitizeDisplay } from "../../lib/sanitizeDisplay.js";
import EmptyState from "../EmptyState.jsx";
import Badge from "../ui/Badge.jsx";
import DataTable from "../ui/DataTable.jsx";
import HashValue from "../ui/HashValue.jsx";
import MockLabel from "../ui/MockLabel.jsx";
import Panel from "../ui/Panel.jsx";

const CHECK_TONES = { pass: "allow", fail: "block", unknown: "unknown", info: "neutral" };

function triState(value) {
  if (value === null || value === undefined) return "Could not be determined";
  return value ? "Yes" : "No";
}

const columns = [
  { key: "name", header: "Check", render: (row) => humanize(sanitizeDisplay(row.name)) },
  {
    key: "status",
    header: "Status",
    render: (row) => <Badge tone={CHECK_TONES[row.status] || "unknown"}>{humanize(sanitizeDisplay(row.status))}</Badge>,
  },
  { key: "evidence", header: "Evidence", render: (row) => sanitizeDisplay(row.evidence) },
];

export default function ProvenancePanel({ provenance, className }) {
  if (!provenance) {
    return (
      <Panel title="Provenance" className={className}>
        <EmptyState
          title="No provenance record"
          message="This scan has no provenance record, which does not mean its provenance is sound."
          headingLevel={3}
        />
      </Panel>
    );
  }
  return (
    <Panel
      title="Provenance"
      className={className}
      actions={<MockLabel source={provenance.source} isMock={provenance.is_mock} />}
    >
      <dl className="dl">
        <div className="dl__row">
          <dt>Source known</dt>
          <dd>{triState(provenance.source_known)}</dd>
        </div>
        <div className="dl__row">
          <dt>Revision pinned</dt>
          <dd>{triState(provenance.revision_pinned)}</dd>
        </div>
        <div className="dl__row">
          <dt>Signature verified</dt>
          <dd>{triState(provenance.signed)}</dd>
        </div>
        <div className="dl__row">
          <dt>Signature files (by name, not verified)</dt>
          <dd>{triState(provenance.signature_files_present)}</dd>
        </div>
        <div className="dl__row">
          <dt>Attestation (by name, not verified)</dt>
          <dd>{triState(provenance.provenance_present)}</dd>
        </div>
        <div className="dl__row">
          <dt>Lineage completeness</dt>
          <dd>{formatProbability(provenance.lineage_completeness)}</dd>
        </div>
        <div className="dl__row">
          <dt>Resolved commit</dt>
          <dd>
            <HashValue kind="commit" value={provenance.resolved_commit} label="commit" truncate />
          </dd>
        </div>
      </dl>
      <div className="panel__section">
        <DataTable
          caption="Provenance checks"
          columns={columns}
          rows={provenance.checks}
          getRowKey={(row) => row.name}
          empty={<p className="state__message">No checks were recorded.</p>}
        />
        {provenance.checks_truncated ? (
          <p className="state__message preview-count">Only the first checks are shown.</p>
        ) : null}
      </div>
    </Panel>
  );
}
