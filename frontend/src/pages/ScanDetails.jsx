import { useCallback } from "react";
import { useParams } from "react-router-dom";
import { ArrowUpRight, Blocks, GitFork, Network } from "lucide-react";
import EmptyState from "../components/EmptyState.jsx";
import FindingsPreview from "../components/findings/FindingsPreview.jsx";
import SeparateScores from "../components/risk/SeparateScores.jsx";
import ShapFactors from "../components/risk/ShapFactors.jsx";
import TrainingNotice from "../components/risk/TrainingNotice.jsx";
import ArtifactIdentity from "../components/scan/ArtifactIdentity.jsx";
import EvidenceSummary from "../components/scan/EvidenceSummary.jsx";
import ProvenancePanel from "../components/scan/ProvenancePanel.jsx";
import ScanHero from "../components/scan/ScanHero.jsx";
import Timeline from "../components/scan/Timeline.jsx";
import Button from "../components/ui/Button.jsx";
import ErrorState from "../components/ui/ErrorState.jsx";
import LoadingState from "../components/ui/LoadingState.jsx";
import Panel from "../components/ui/Panel.jsx";
import useApi from "../hooks/useApi.js";
import useScan, { isTerminal } from "../hooks/useScan.js";
import { isScanId } from "../hooks/useScanSelection.js";
import { sanitizeDisplay } from "../lib/sanitizeDisplay.js";
import { api } from "../services/api.js";

const SOFTWARE_TYPES = new Set(["software", "container"]);

function riskNote(risk, finished) {
  if (!finished) return "The scan is still running.";
  if (risk.status === "error") return "The risk result could not be loaded.";
  if (risk.status === "loading" && !risk.data) return "Loading the risk result.";
  return null;
}

function ScanBody({ scanId, evidence }) {
  const finished = isTerminal(evidence.scan_status);
  // /risk is only requested once the scan has finished.
  const fetcher = useCallback((options) => api.getRisk(scanId, options), [scanId]);
  const risk = useApi(finished ? fetcher : null);
  const artifactType = evidence.artifact.artifact_type;
  const isSoftware = SOFTWARE_TYPES.has(artifactType);

  return (
    <div className="bento">
      <div className="span-12">
        <ScanHero evidence={evidence} risk={risk.data} riskNote={riskNote(risk, finished)} />
      </div>
      {evidence.scan_error?.message ? (
        <div className="span-12">
          <ErrorState
            error={{ code: evidence.scan_error.code, message: evidence.scan_error.message, status: 400 }}
            title="The scan failed"
          />
        </div>
      ) : null}
      {risk.status === "error" ? (
        <div className="span-12">
          <ErrorState error={risk.error} onRetry={risk.reload} title="Could not load the risk result" />
        </div>
      ) : null}
      <ArtifactIdentity evidence={evidence} className="span-7" />
      <EvidenceSummary evidence={evidence} className="span-5" />
      {finished ? (
        <>
          <FindingsPreview scanId={scanId} category="vulnerability" className="span-12" />
          <FindingsPreview scanId={scanId} category="static" className="span-6" />
          <FindingsPreview scanId={scanId} category="behavioral" className="span-6" />
        </>
      ) : null}
      <ProvenancePanel provenance={evidence.provenance} className="span-7" />
      <Timeline stages={evidence.stages} className="span-5" />
      {risk.data ? (
        <Panel
          title="Why this score?"
          className="span-12"
          actions={
            <Button variant="ghost" size="small" icon={ArrowUpRight} to={`/risk?scan=${scanId}`}>
              Full risk analysis
            </Button>
          }
        >
          <SeparateScores scores={risk.data.scores} />
          <div className="panel__section">
            <TrainingNotice trainingData={risk.data.training_data} containsMock={risk.data.contains_mock_evidence} />
          </div>
          {risk.data.decision_reasons.length ? (
            <ul className="reason-list panel__section">
              {risk.data.decision_reasons.map((reason, index) => (
                <li key={index}>{sanitizeDisplay(reason)}</li>
              ))}
            </ul>
          ) : null}
          <div className="panel__section">
            <h3>Top ML factors (SHAP)</h3>
            <ShapFactors explanation={risk.data.explanation} limit={5} artifactType={artifactType} />
          </div>
        </Panel>
      ) : null}
      <Panel title={isSoftware ? "Dependency graph" : "Model lineage"} className="span-6">
        <p className="state__message">Inspect nodes, relationships and the limits of this graph.</p>
        <div className="state__action">
          <Button
            variant="secondary"
            icon={isSoftware ? Network : GitFork}
            to={`${isSoftware ? "/graph" : "/lineage"}?scan=${scanId}`}
          >
            {isSoftware ? "Open dependency graph" : "Open model lineage"}
          </Button>
        </div>
      </Panel>
      <Panel title="Blockchain verification" className="span-6">
        <p className="state__message">
          Verification runs only when you ask for it. VERIFIED means the record is unchanged, not that the scanner was
          correct.
        </p>
        <div className="state__action">
          <Button variant="secondary" icon={Blocks} to={`/blockchain?scan=${scanId}`}>
            Open blockchain evidence
          </Button>
        </div>
      </Panel>
    </div>
  );
}

export default function ScanDetails() {
  const { scanId } = useParams();
  const valid = isScanId(scanId);
  const { status, data, error, reload } = useScan(valid ? scanId : null);

  return (
    <>
      <header className="page-head">
        <h1>Scan Details</h1>
      </header>
      {!valid ? <EmptyState title="Not a valid scan ID" message="Open a scan from the Dashboard." headingLevel={2} /> : null}
      {status === "loading" ? <LoadingState label="Loading scan evidence" /> : null}
      {status === "error" ? <ErrorState error={error} onRetry={reload} title="Could not load this scan" /> : null}
      {data ? <ScanBody scanId={scanId} evidence={data} /> : null}
    </>
  );
}
