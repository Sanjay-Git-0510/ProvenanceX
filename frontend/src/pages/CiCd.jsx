import { useCallback } from "react";
import EmptyState from "../components/EmptyState.jsx";
import DecisionDisplay from "../components/risk/DecisionDisplay.jsx";
import ScanPicker from "../components/scan/ScanPicker.jsx";
import Badge from "../components/ui/Badge.jsx";
import ErrorState from "../components/ui/ErrorState.jsx";
import LoadingState from "../components/ui/LoadingState.jsx";
import MockLabel from "../components/ui/MockLabel.jsx";
import Panel from "../components/ui/Panel.jsx";
import useApi from "../hooks/useApi.js";
import useScanSelection from "../hooks/useScanSelection.js";
import { formatRiskScore } from "../lib/format.js";
import { sanitizeDisplay } from "../lib/sanitizeDisplay.js";
import { api } from "../services/api.js";

const GATE = {
  BLOCK: { tone: "block", label: "Would fail the pipeline" },
  REVIEW: { tone: "review", label: "Would pass by default; fails only if the strict option is on" },
  ALLOW: { tone: "allow", label: "Would pass the pipeline" },
};

function GateOutcome({ decision }) {
  if (!Object.hasOwn(GATE, decision ?? "")) return <Badge tone="unknown">No gate outcome: no decision</Badge>;
  const { tone, label } = GATE[decision];
  return <Badge tone={tone}>{label}</Badge>;
}

function SelectedScan({ scanId }) {
  const fetcher = useCallback((options) => api.getRisk(scanId, options), [scanId]);
  const { status, data, error, reload } = useApi(fetcher);

  if (status === "error") return <ErrorState error={error} onRetry={reload} title="Could not load the decision" />;
  if (!data) return <LoadingState label="Loading the decision" lines={1} />;
  return (
    <>
      <DecisionDisplay
        decision={data.decision}
        confidence={data.confidence}
        confidenceLabel={data.confidence_label}
        notEvaluatedLayers={data.not_evaluated_layers}
      />
      {data.contains_mock_evidence ? (
        <p className="panel__section">
          <MockLabel isMock>Contains mock evidence</MockLabel>
        </p>
      ) : null}
      <dl className="dl panel__section">
        <div className="dl__row">
          <dt>ProvenanceX risk</dt>
          <dd>{formatRiskScore(data.risk_score)}</dd>
        </div>
        <div className="dl__row">
          <dt>Under the gate rule</dt>
          <dd>
            <GateOutcome decision={data.decision} />
          </dd>
        </div>
      </dl>
      {data.reason?.message ? <p className="state__message panel__section">{sanitizeDisplay(data.reason.message)}</p> : null}
    </>
  );
}

export default function CiCd() {
  const { scanId, invalid, selectScan } = useScanSelection();
  return (
    <>
      <header className="page-head">
        <div>
          <h1>CI/CD</h1>
          <p className="page-head__lede">
            How the decision of a scan maps to the pipeline gate. The GitHub Actions gate arrives in Phase 9, so this page shows
            the rule, not a pipeline result.
          </p>
        </div>
      </header>
      <div className="toolbar">
        <ScanPicker scanId={scanId} onSelect={selectScan} />
      </div>
      <div className="bento">
        <Panel title="Gate rule" className="span-5">
          <ul className="reason-list">
            <li>BLOCK fails the pipeline.</li>
            <li>REVIEW passes by default. An optional strict setting makes it fail.</li>
            <li>ALLOW passes.</li>
            <li>No decision gives no gate outcome.</li>
          </ul>
        </Panel>
        <Panel title="Selected scan" className="span-7">
          {invalid ? <p className="state__message">Not a valid scan ID. Choose a scan from the list.</p> : null}
          {!scanId && !invalid ? <p className="state__message">Choose a scan to see its decision.</p> : null}
          {scanId ? <SelectedScan key={scanId} scanId={scanId} /> : null}
        </Panel>
        <Panel title="Pipeline runs" className="span-12">
          <EmptyState
            title="No pipeline runs recorded"
            message="ProvenanceX does not record pipeline runs yet."
            headingLevel={3}
          />
        </Panel>
      </div>
    </>
  );
}
