import { useCallback } from "react";
import { ArrowUpRight } from "lucide-react";
import EmptyState from "../components/EmptyState.jsx";
import DecisionDisplay from "../components/risk/DecisionDisplay.jsx";
import EvidenceLinkList from "../components/risk/EvidenceLinkList.jsx";
import HardRules from "../components/risk/HardRules.jsx";
import LayerBreakdown from "../components/risk/LayerBreakdown.jsx";
import SeparateScores from "../components/risk/SeparateScores.jsx";
import ShapFactors from "../components/risk/ShapFactors.jsx";
import TrainingNotice from "../components/risk/TrainingNotice.jsx";
import ScanPicker from "../components/scan/ScanPicker.jsx";
import Button from "../components/ui/Button.jsx";
import DataTable from "../components/ui/DataTable.jsx";
import ErrorState from "../components/ui/ErrorState.jsx";
import LoadingState from "../components/ui/LoadingState.jsx";
import Panel from "../components/ui/Panel.jsx";
import useApi from "../hooks/useApi.js";
import useScanSelection from "../hooks/useScanSelection.js";
import { formatConfidence, humanize } from "../lib/format.js";
import { FLIP_NOTICE, layerLabel } from "../lib/policyDisplay.js";
import { sanitizeDisplay } from "../lib/sanitizeDisplay.js";
import { api } from "../services/api.js";

const notEvaluatedColumns = [
  { key: "feature", header: "Feature", render: (row) => humanize(sanitizeDisplay(row.feature)) },
  { key: "layer", header: "Layer", render: (row) => layerLabel(row.layer) },
  { key: "reason", header: "Why it has no value", render: (row) => humanize(sanitizeDisplay(row.null_reason)) },
];

function RiskResult({ scanId }) {
  const fetcher = useCallback((options) => api.getRisk(scanId, options), [scanId]);
  const { status, data, error, reload } = useApi(fetcher);
  // /risk has no artifact type, and graph links need it to pick the right page.
  const summaryFetcher = useCallback(
    (options) => api.getEvidence(scanId, { findingsLimit: 1, componentsLimit: 1, ...options }),
    [scanId],
  );
  const summary = useApi(summaryFetcher);
  const artifactType = summary.data?.artifact?.artifact_type;

  if (status === "error") return <ErrorState error={error} onRetry={reload} title="Could not load the risk result" />;
  if (!data) return <LoadingState label="Loading the risk result" />;

  const notEvaluated = data.explanation?.not_evaluated_features ?? [];
  return (
    <div className="bento">
      <Panel
        title="Decision"
        className="span-4"
        actions={
          <Button variant="ghost" size="small" icon={ArrowUpRight} to={`/scans/${scanId}`}>
            Scan details
          </Button>
        }
      >
        <DecisionDisplay
          decision={data.decision}
          confidence={data.confidence}
          confidenceLabel={data.confidence_label}
          notEvaluatedLayers={data.not_evaluated_layers}
        />
        {data.decision !== "ALLOW" ? (
          <p className="state__message panel__section">
            Confidence: {formatConfidence(data.confidence)}
            {data.confidence_label ? ` (${data.confidence_label})` : ""}. {FLIP_NOTICE}
          </p>
        ) : null}
        {data.reason?.message ? <p className="state__message panel__section">{sanitizeDisplay(data.reason.message)}</p> : null}
        {data.allow_reason ? <p className="state__message panel__section">{sanitizeDisplay(data.allow_reason)}</p> : null}
        {data.decision_reasons.length ? (
          <ul className="reason-list panel__section">
            {data.decision_reasons.map((reason, index) => (
              <li key={index}>{sanitizeDisplay(reason)}</li>
            ))}
          </ul>
        ) : null}
      </Panel>
      <Panel title="Separate measures" eyebrow="Never combined into one number" className="span-8">
        <SeparateScores scores={data.scores} />
        <div className="panel__section">
          <TrainingNotice trainingData={data.training_data} containsMock={data.contains_mock_evidence} />
        </div>
      </Panel>
      <Panel title="Evidence layers" className="span-12">
        <LayerBreakdown layers={data.layers} artifactType={artifactType} />
        <div className="panel__section">
          <EvidenceLinkList links={data.evidence_links} artifactType={artifactType} />
        </div>
      </Panel>
      <Panel title="Hard rules" className="span-4">
        <HardRules hardRules={data.hard_rules} artifactType={artifactType} />
      </Panel>
      <Panel title="ML factors (SHAP)" className="span-8">
        <ShapFactors explanation={data.explanation} artifactType={artifactType} />
      </Panel>
      <Panel title="Features with no value" eyebrow="Missing evidence, not a clean result" className="span-12">
        <DataTable
          caption="Table of features with no value"
          captionHidden
          columns={notEvaluatedColumns}
          rows={notEvaluated}
          getRowKey={(row) => row.feature}
          empty={<p className="state__message">Every feature had a value, or no explanation exists.</p>}
        />
      </Panel>
    </div>
  );
}

export default function RiskAnalysis() {
  const { scanId, invalid, selectScan } = useScanSelection();
  return (
    <>
      <header className="page-head">
        <div>
          <h1>Risk Analysis</h1>
          <p className="page-head__lede">
            How the evidence layers, hard rules and ML outputs led to this decision. Weights and thresholds are research
            parameters.
          </p>
        </div>
      </header>
      <div className="toolbar">
        <ScanPicker scanId={scanId} onSelect={selectScan} />
      </div>
      {invalid ? <EmptyState title="Not a valid scan ID" message="Choose a scan from the list." headingLevel={2} /> : null}
      {!scanId && !invalid ? (
        <EmptyState title="Choose a scan" message="Risk results are shown per scan." headingLevel={2} />
      ) : null}
      {scanId ? <RiskResult scanId={scanId} /> : null}
    </>
  );
}
