import { humanize } from "../../lib/format.js";
import { sanitizeDisplay } from "../../lib/sanitizeDisplay.js";
import Badge from "../ui/Badge.jsx";
import DataTable from "../ui/DataTable.jsx";
import HashValue from "../ui/HashValue.jsx";

const NO_VALUE = "No value";
const HASH_FIELDS = new Set(["artifact_hash", "bom_hash", "provenance_hash", "record_hash"]);

// The label comes only from the status the API sent. This component never compares values.
const STATUS = {
  match: { tone: "allow", label: "Match" },
  mismatch: { tone: "block", label: "Mismatch" },
  absent: { tone: "neutral", label: "Absent" },
  unavailable: { tone: "unknown", label: "Unavailable" },
};

function FieldStatus({ status }) {
  const known = Object.hasOwn(STATUS, status) ? STATUS[status] : { tone: "unknown", label: "Unrecognized status" };
  return <Badge tone={known.tone}>{known.label}</Badge>;
}

function FieldValue({ field, value, where }) {
  const label = `${humanize(field)}, ${where}`;
  if (HASH_FIELDS.has(field)) return <HashValue value={value} label={label} reason={NO_VALUE} truncate />;
  if (field === "artifact_id") return <HashValue kind="uuid" value={value} label={label} reason={NO_VALUE} truncate />;
  if (value === null || value === undefined) return <span className="hash__missing">{NO_VALUE}</span>;
  if (typeof value === "number" || typeof value === "boolean") return <code>{String(value)}</code>;
  if (typeof value === "string") return <code>{sanitizeDisplay(value)}</code>;
  return <span className="hash__missing">Not shown</span>;
}

const valueColumn = (key, header, where) => ({
  key,
  header,
  render: (row) => <FieldValue field={row.field} value={row[key]} where={where} />,
});

const columns = [
  { key: "field", header: "Field", render: (row) => humanize(sanitizeDisplay(row.field)) },
  {
    key: "status",
    header: "Server result",
    render: (row) => (
      <>
        <FieldStatus status={row.status} />
        {row.detail ? <p className="comparison__detail">{sanitizeDisplay(row.detail)}</p> : null}
      </>
    ),
  },
  valueColumn("stored", "Stored", "stored"),
  valueColumn("recomputed", "Recomputed", "recomputed"),
  valueColumn("chain", "Chain", "chain"),
  valueColumn("source_table", "Source table", "source table"),
];

/** Each compared field as held in each place, with the server's verdict for that field. */
export default function FieldComparisonTable({ fields }) {
  return (
    <div className="comparison">
      <DataTable
        caption="Field by field comparison"
        captionHidden
        columns={columns}
        rows={fields}
        getRowKey={(row) => row.field}
        empty={<p className="state__message">The server returned no field comparison.</p>}
      />
      <p className="state__message panel__section">
        Values are shown as the API returned them. Source table values are raw, while stored, recomputed and chain values
        can be encoded (a scaled score, a timestamp in seconds), so compare using the server result.
      </p>
    </div>
  );
}
