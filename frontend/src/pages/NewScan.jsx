import { useRef, useState } from "react";
import { ArrowRight } from "lucide-react";
import ScanProgressModal from "../components/scan/ScanProgressModal.jsx";
import Button from "../components/ui/Button.jsx";
import ErrorState from "../components/ui/ErrorState.jsx";
import Panel from "../components/ui/Panel.jsx";
import { isScanId } from "../hooks/useScanSelection.js";
import { isAllowedSourceUrl } from "../lib/format.js";
import { api } from "../services/api.js";

const KINDS = {
  software: { label: "Software", host: "github.com", hostName: "GitHub", placeholder: "github.com/owner/repository" },
  model: { label: "AI / ML", host: "huggingface.co", hostName: "Hugging Face", placeholder: "huggingface.co/owner/model" },
};

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

function validate({ kind, mode, url, file }) {
  if (mode === "url") {
    const { host, hostName } = KINDS[kind];
    return isAllowedSourceUrl(url.trim(), host) ? null : `Enter a full https address on ${hostName} (${host}).`;
  }
  if (!file) return "Choose a ZIP file to upload.";
  return file.name.toLowerCase().endsWith(".zip") ? null : "Only .zip uploads are supported.";
}

export default function NewScan() {
  const [active, setActive] = useState(null);
  const lastRun = useRef(null);
  const [kind, setKind] = useState("software");
  const [mode, setMode] = useState("url");
  const [url, setUrl] = useState("");
  const [file, setFile] = useState(null);
  const [revision, setRevision] = useState("");
  const [name, setName] = useState("");
  const [artifactType, setArtifactType] = useState("model");
  const [invalid, setInvalid] = useState(null);
  const [error, setError] = useState(null);
  const [submitting, setSubmitting] = useState(false);

  /** Create the scan, then hand it to the progress overlay. The form stays locked meanwhile. */
  async function start(run) {
    setError(null);
    setSubmitting(true);
    try {
      const created =
        run.kind === "software"
          ? await api.createSoftwareScan(run.input)
          : await api.createModelScan({ ...run.input, artifactType: run.artifactType });
      if (!isScanId(created?.scan_id)) throw new Error("The API returned an invalid scan ID.");
      setActive({ scanId: created.scan_id, artifact: run.artifact });
    } catch (err) {
      setError(err);
      setSubmitting(false);
    }
  }

  function submit(event) {
    event.preventDefault();
    const problem = validate({ kind, mode, url, file });
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
    const typeLabel = kind === "software" ? "Software" : { model: "Model", lora: "LoRA adapter", dataset: "Dataset" }[artifactType];
    lastRun.current = { kind, input, artifactType, artifact: { name: input.name || source, type: typeLabel } };
    start(lastRun.current);
  }

  function closeProgress() {
    setActive(null);
    setSubmitting(false);
  }

  function retry() {
    setActive(null);
    start(lastRun.current);
  }

  const { placeholder } = KINDS[kind];
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
          <Choice
            legend="Artifact"
            name="kind"
            value={kind}
            options={Object.entries(KINDS).map(([key, entry]) => [key, entry.label])}
            onChange={setKind}
          />
          <Choice
            legend="Source"
            name="mode"
            value={mode}
            options={[
              ["url", "Repository URL"],
              ["upload", "Upload ZIP"],
            ]}
            onChange={setMode}
          />
          {kind === "model" ? (
            <label className="field">
              <span className="field__label">Model artifact type</span>
              <select className="field__control" value={artifactType} onChange={(e) => setArtifactType(e.target.value)}>
                <option value="model">Model</option>
                <option value="lora">LoRA adapter</option>
                <option value="dataset">Dataset</option>
              </select>
            </label>
          ) : null}
          {mode === "url" ? (
            <label className="field" key="url">
              <span className="field__label">Repository URL (https)</span>
              <input
                className="field__control"
                type="url"
                inputMode="url"
                autoComplete="off"
                placeholder={placeholder}
                value={url}
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
                onChange={(e) => setFile(e.target.files?.[0] ?? null)}
              />
            </label>
          )}
          <label className="field">
            <span className="field__label">Revision (optional: branch, tag or commit)</span>
            <input className="field__control" maxLength={255} value={revision} onChange={(e) => setRevision(e.target.value)} />
          </label>
          <label className="field">
            <span className="field__label">Display name (optional)</span>
            <input className="field__control" maxLength={255} value={name} onChange={(e) => setName(e.target.value)} />
          </label>
          {invalid ? (
            <p className="field__error" role="alert">
              {invalid}
            </p>
          ) : null}
          {error ? <ErrorState error={error} title="The scan was not started" /> : null}
          <div>
            <Button type="submit" icon={ArrowRight} loading={submitting}>
              {submitting ? "Starting scan" : "Start scan"}
            </Button>
          </div>
        </form>
      </Panel>
      {active ? (
        <ScanProgressModal scanId={active.scanId} artifact={active.artifact} onRetry={retry} onClose={closeProgress} />
      ) : null}
    </>
  );
}
