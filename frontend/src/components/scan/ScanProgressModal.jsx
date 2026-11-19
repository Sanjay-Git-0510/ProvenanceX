import { useEffect, useRef, useState } from "react";
import { Check, CircleCheck, CircleX, Clock, LoaderCircle, Play } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { COMPLETE_HOLD_MS, POLL_MS, STEPS, activeStep, formatElapsed } from "../../lib/scanProgress.js";
import { sanitizeDisplay } from "../../lib/sanitizeDisplay.js";
import { api } from "../../services/api.js";
import Badge from "../ui/Badge.jsx";
import Button from "../ui/Button.jsx";
import Modal from "../ui/Modal.jsx";

const STATUS_BADGE = {
  queued: { tone: "neutral", icon: Clock, label: "Queued" },
  running: { tone: "accent", icon: Play, label: "Running" },
  completed: { tone: "allow", icon: CircleCheck, label: "Completed" },
  failed: { tone: "block", icon: CircleX, label: "Failed" },
};

function Stepper({ active, failed }) {
  return (
    <ol className="stepper">
      {STEPS.map((label, index) => {
        const state = index < active ? "done" : index === active ? (failed ? "failed" : "active") : "pending";
        const Icon = state === "done" ? Check : state === "failed" ? CircleX : state === "active" ? LoaderCircle : null;
        return (
          <li key={label} className={`stepper__item stepper__item--${state}`} aria-current={state === "active" ? "step" : undefined}>
            <span className="stepper__marker" aria-hidden="true">
              {Icon ? <Icon size={14} className={state === "active" ? "stepper__spin" : undefined} /> : index + 1}
            </span>
            <span>{label}</span>
            <span className="sr-only">
              {state === "done" ? " (done)" : state === "active" ? " (in progress)" : state === "failed" ? " (failed)" : " (waiting)"}
            </span>
          </li>
        );
      })}
    </ol>
  );
}

/**
 * Blocks the page while one scan runs. Polls the scan, shows an elapsed timer and the stages,
 * then opens the result. A failed scan keeps the dialog open with Retry and Close.
 */
export default function ScanProgressModal({ scanId, artifact, onRetry, onClose }) {
  const navigate = useNavigate();
  const [scan, setScan] = useState(null);
  const [pollError, setPollError] = useState(null);
  const [elapsed, setElapsed] = useState(0);
  const status = scan?.status ?? "queued";
  const finished = status === "completed" || status === "failed";

  useEffect(() => {
    if (!scanId || finished) return undefined;
    const controller = new AbortController();
    let timer;
    async function poll() {
      try {
        const next = await api.getScan(scanId, { signal: controller.signal });
        setScan(next);
        setPollError(null);
        if (next.status === "completed" || next.status === "failed") return;
      } catch (error) {
        if (controller.signal.aborted) return;
        setPollError(error);
      }
      timer = setTimeout(poll, POLL_MS);
    }
    poll();
    return () => {
      controller.abort();
      clearTimeout(timer);
    };
  }, [scanId, finished]);

  useEffect(() => {
    if (finished) return undefined;
    const started = Date.now();
    const timer = setInterval(() => setElapsed((Date.now() - started) / 1000), 1000);
    return () => clearInterval(timer);
  }, [scanId, finished]);

  const openedRef = useRef(false);
  useEffect(() => {
    if (status !== "completed" || openedRef.current) return undefined;
    const timer = setTimeout(() => {
      openedRef.current = true;
      navigate(`/scans/${scanId}`);
    }, COMPLETE_HOLD_MS);
    return () => clearTimeout(timer);
  }, [status, scanId, navigate]);

  const badge = STATUS_BADGE[status] ?? STATUS_BADGE.queued;
  const background = () => {
    onClose();
    navigate(`/scans/${scanId}`);
  };
  const failed = status === "failed";

  return (
    <Modal
      open
      title="Scan in progress"
      onClose={failed ? onClose : background}
      dismissOnBackdrop={false}
      hideClose
      footer={
        failed ? (
          <>
            <Button variant="secondary" onClick={onClose}>
              Close
            </Button>
            <Button onClick={onRetry}>Retry</Button>
          </>
        ) : status === "completed" ? null : (
          <Button variant="secondary" onClick={background}>
            Run in background
          </Button>
        )
      }
    >
      <div className="scan-progress">
        <div className="scan-progress__head">
          <div className="scan-progress__artifact">
            <p className="scan-progress__name" title={artifact.name}>
              {sanitizeDisplay(artifact.name)}
            </p>
            <p className="scan-progress__type">{artifact.type}</p>
          </div>
          <div role="status" aria-live="polite">
            <Badge tone={badge.tone} icon={badge.icon}>
              {badge.label}
            </Badge>
          </div>
        </div>
        <p className="scan-progress__timer" aria-label={`Elapsed time ${formatElapsed(elapsed)}`}>
          {formatElapsed(elapsed)}
        </p>
        <Stepper active={activeStep(scan)} failed={failed} />
        {failed ? (
          <p className="scan-progress__error" role="alert">
            {sanitizeDisplay(scan.error?.message || "The scan failed.")}
          </p>
        ) : null}
        {pollError && !finished ? (
          <p className="scan-progress__note" role="status">
            Could not read the scan status. Retrying.
          </p>
        ) : null}
      </div>
    </Modal>
  );
}
