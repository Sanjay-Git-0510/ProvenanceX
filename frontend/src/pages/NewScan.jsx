import { useCallback, useRef, useState } from "react";
import { ArrowRight } from "lucide-react";
import ScanProgressModal from "../components/scan/ScanProgressModal.jsx";
import ScanTypePicker from "../components/scan/ScanTypePicker.jsx";
import Button from "../components/ui/Button.jsx";
import ErrorState from "../components/ui/ErrorState.jsx";
import Panel from "../components/ui/Panel.jsx";
import useApi from "../hooks/useApi.js";
import { isScanId } from "../hooks/useScanSelection.js";
import { formatCount } from "../lib/format.js";
import { WORKFLOWS, validateScanInput } from "../lib/scanValidation.js";
import { workflowKind } from "../lib/scanStages.js";
import { api } from "../services/api.js";

function Choice({ legend, name, value, options, onChange }) {
  return (
    <fieldset className="choice">
      <legend className="field__label">{legend}</legend>
      <div className="choice__options">
        {options.map(([optionValue, label]) => (
          <label key={optionValue} className="choice__option">
            <input
              type="radio"
              name={name}
              value={optionValue}
              checked={value === optionValue}
              onChange={() => onChange(optionValue)}
            />
            <span>{label}</span>
          </label>
        ))}
      </div>
    </fieldset>
  );
}

function FieldError({ id, message }) {
  if (!message) return null;
  return (
    <p className="field__error" id={id} role="alert">
      {message}
    </p>
  );
}

const PROVIDER_TEXT = {
  disabled: "off",
  docker: "on (Docker)",
  mock: "mock (results labelled MOCK)",
  web3: "on (local chain)",
};

/** Server limits as reported by GET /limits. Unknown values say so instead of guessing. */
function LimitsNote({ limits }) {
  if (limits.status === "error") {
    return (
      <p className="field__hint" role="status">
        Server limits could not be loaded, so the upload size is checked only by the server.
      </p>
    );
  }
  if (!limits.data) return <p className="field__hint">Loading server limits.</p>;
  const { max_upload_mb: upload, max_artifact_files: files, sandbox_provider: sandbox, blockchain_provider: chain } =
    limits.data;
  return (
    <p className="field__hint">
      Uploads up to {typeof upload === "number" ? `${upload} MB` : "an unknown size"} and {formatCount(files)} files.
      Sandbox:{" "}
      {PROVIDER_TEXT[sandbox] || "unknown"}. Blockchain: {PROVIDER_TEXT[chain] || "unknown"}
      {chain !== "disabled" && !limits.data.blockchain_anchor_on_scan ? " (anchoring on request only)" : ""}.
    </p>
  );
}

export default function NewScan() {
  const [active, setActive] = useState(null);
  const lastRun = useRef(null);
  const [workflow, setWorkflow] = useState("software");
  const [mode, setMode] = useState("url");
  const [url, setUrl] = useState("");
  const [file, setFile] = useState(null);
  const [revision, setRevision] = useState("");
  const [name, setName] = useState("");
  const [invalid, setInvalid] = useState(null);
  const [error, setError] = useState(null);
  const [submitting, setSubmitting] = useState(false);
  const limitsFetcher = useCallback((options) => api.getLimits(options), []);
  const limits = useApi(limitsFetcher);

  /** Create the scan, then hand it to the progress overlay. The form stays locked meanwhile. */
  async function start(run) {
    setError(null);
    setSubmitting(true);
    try {
      const spec = WORKFLOWS[run.workflow];
      const created =
        spec.endpoint === "software"
          ? await api.createSoftwareScan(run.input)
          : await api.createModelScan({ ...run.input, artifactType: spec.artifactType });
      if (!isScanId(created?.scan_id)) throw new Error("The API returned an invalid scan ID.");
      setActive({ scanId: created.scan_id, artifact: run.artifact, kind: workflowKind(spec.artifactType) });
    } catch (err) {
      setError(err);
      setSubmitting(false);
    }
  }

  function submit(event) {
    event.preventDefault();
    const problem = validateScanInput({ workflow, mode, url, file, revision }, limits.data);
    setInvalid(problem);
    setError(null);
    if (problem || submitting) return;

    const input = {
      sourceUrl: mode === "url" ? url.trim() : undefined,
      file: mode === "upload" ? file : undefined,
      revision: revision.trim(),
      name: name.trim(),
    };
    const source = mode === "url" ? url.trim().replace(/^https:\/\//, "") : file.name;
    lastRun.current = { workflow, input, artifact: { name: input.name || source, type: WORKFLOWS[workflow].label } };
    start(lastRun.current);
  }

  function changeWorkflow(next) {
    setWorkflow(next);
    setInvalid(null);
  }

  function closeProgress() {
    setActive(null);
    setSubmitting(false);
  }

  function retry() {
    setActive(null);
    start(lastRun.current);
  }

  const spec = WORKFLOWS[workflow];
  const errorFor = (field) => (invalid?.field === field ? invalid.message : null);
  return (
    <>
      <header className="page-head">
        <div>
          <h1>New Scan</h1>
          <p className="page-head__lede">
            Artifacts are treated as untrusted. They are parsed and hashed, and never run on the host.
          </p>
        </div>
      </header>
      <Panel className="form-panel">
        <form className="form" onSubmit={submit} noValidate>
          <ScanTypePicker value={workflow} onChange={changeWorkflow} />
          <p className="field__hint">{spec.hint}</p>
          <Choice
            legend="Source"
            name="mode"
            value={mode}
            options={[
              ["url", `${spec.hostName} URL`],
              ["upload", "Upload ZIP"],
            ]}
            onChange={(next) => {
              setMode(next);
              setInvalid(null);
            }}
          />
          {mode === "url" ? (
            <label className="field" key="url">
              <span className="field__label">Repository URL (https)</span>
              <input
                className="field__control"
                type="url"
                inputMode="url"
                autoComplete="off"
                placeholder={spec.placeholder}
                value={url}
                aria-invalid={Boolean(errorFor("url"))}
                aria-describedby={errorFor("url") ? "url-error" : undefined}
                onChange={(e) => setUrl(e.target.value)}
              />
            </label>
          ) : (
            <label className="field" key="file">
              <span className="field__label">ZIP file</span>
              <input
                className="field__control"
                type="file"
                accept=".zip,application/zip"
                aria-invalid={Boolean(errorFor("file"))}
                aria-describedby={errorFor("file") ? "file-error" : undefined}
                onChange={(e) => setFile(e.target.files?.[0] ?? null)}
              />
            </label>
          )}
          <FieldError id="url-error" message={mode === "url" ? errorFor("url") : null} />
          <FieldError id="file-error" message={mode === "upload" ? errorFor("file") : null} />
          <LimitsNote limits={limits} />
          <label className="field">
            <span className="field__label">Revision (optional: branch, tag or commit)</span>
            <input
              className="field__control"
              maxLength={255}
              value={revision}
              aria-invalid={Boolean(errorFor("revision"))}
              aria-describedby={errorFor("revision") ? "revision-error" : undefined}
              onChange={(e) => setRevision(e.target.value)}
            />
          </label>
          <FieldError id="revision-error" message={errorFor("revision")} />
          <label className="field">
            <span className="field__label">Display name (optional)</span>
            <input className="field__control" maxLength={255} value={name} onChange={(e) => setName(e.target.value)} />
          </label>
          <p className="field__hint">These checks run in your browser; the server checks everything again.</p>
          {error ? <ErrorState error={error} title="The scan was not started" /> : null}
          <div>
            <Button type="submit" icon={ArrowRight} loading={submitting}>
              {submitting ? "Starting scan" : "Start scan"}
            </Button>
          </div>
        </form>
      </Panel>
      {active ? (
        <ScanProgressModal
          scanId={active.scanId}
          artifact={active.artifact}
          kind={active.kind}
          onRetry={retry}
          onClose={closeProgress}
        />
      ) : null}
    </>
  );
}
