import { useEffect, useRef, useState } from "react";
import {
  Check,
  CircleCheck,
  CircleDashed,
  CircleMinus,
  CircleQuestionMark,
  CircleX,
  Clock,
  LoaderCircle,
  Play,
  SkipForward,
} from "lucide-react";
import { useNavigate } from "react-router-dom";
import {
  COMPLETE_HOLD_MS,
  POLL_MS,
  STAGE_STATES,
  formatElapsed,
  stageStatuses,
  workflowKind,
} from "../../lib/scanStages.js";
import { sanitizeDisplay } from "../../lib/sanitizeDisplay.js";
import { api } from "../../services/api.js";
import Badge from "../ui/Badge.jsx";
import Button from "../ui/Button.jsx";
import MockLabel from "../ui/MockLabel.jsx";
import Modal from "../ui/Modal.jsx";

const STATUS_BADGE = {
  queued: { tone: "neutral", icon: Clock, label: "Queued" },
  running: { tone: "accent", icon: Play, label: "Running" },
  completed: { tone: "allow", icon: CircleCheck, label: "Completed" },
  failed: { tone: "block", icon: CircleX, label: "Failed" },
};

const STAGE_ICONS = {
  done: Check,
  partial: CircleMinus,
  skipped: SkipForward,
  unavailable: CircleQuestionMark,
  error: CircleX,
  active: LoaderCircle,
  pending: null,
  not_run: CircleDashed,
  not_reported: CircleQuestionMark,
};

const STEPPER_CLASS = {
  done: "done",
  partial: "partial",
  error: "failed",
  active: "active",
};

/** One row per backend stage, with its recorded status in words and an icon. */
function StageList({ stages }) {
  return (
    <ol className="stepper" aria-label="Scan stages">
      {stages.map((stage, index) => {
        const Icon = STAGE_ICONS[stage.state];
        const variant = STEPPER_CLASS[stage.state] || "pending";
        return (
          <li
            key={stage.key}
            className={`stepper__item stepper__item--${variant}`}
            aria-current={stage.state === "active" ? "step" : undefined}
          >
            <span className="stepper__marker" aria-hidden="true">
              {Icon ? <Icon size={14} className={stage.state === "active" ? "stepper__spin" : undefined} /> : index + 1}
            </span>
            <span className="stepper__label">
              {stage.label}
              {stage.reason ? <span className="stepper__reason">{sanitizeDisplay(stage.reason)}</span> : null}
            </span>
            {stage.provider === "mock" ? <MockLabel isMock>MOCK</MockLabel> : null}
            <span className="stepper__state">{STAGE_STATES[stage.state].label}</span>
          </li>
        );
      })}
    </ol>
  );
}

/**
 * Blocks the page while one scan runs. Polls the scan, shows an elapsed timer and each stage
 * as the backend records it, then opens the result. A failed scan keeps the dialog open with Retry and Close.
 */
export default function ScanProgressModal({ scanId, artifact, kind, onRetry, onClose }) {
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
        <StageList stages={stageStatuses(scan, kind || workflowKind(scan?.artifact?.artifact_type))} />
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
