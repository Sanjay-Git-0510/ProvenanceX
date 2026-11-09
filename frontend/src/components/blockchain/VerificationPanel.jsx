import { ShieldQuestion } from "lucide-react";
import useVerification from "../../hooks/useVerification.js";
import { formatDateTime, humanize } from "../../lib/format.js";
import { sanitizeDisplay } from "../../lib/sanitizeDisplay.js";
import Button from "../ui/Button.jsx";
import ErrorState from "../ui/ErrorState.jsx";
import MockLabel from "../ui/MockLabel.jsx";
import VerificationBadge from "../ui/VerificationBadge.jsx";
import FieldComparisonTable from "./FieldComparisonTable.jsx";

function Result({ result }) {
  const missing = Array.isArray(result.missing_evidence) ? result.missing_evidence : [];
  return (
    <>
      <div className="panel__section">
        <p className="verify__reason">
          {result.reason?.code ? <code className="state__code">{sanitizeDisplay(result.reason.code)}</code> : null}
          {sanitizeDisplay(result.reason?.message)}
        </p>
        {missing.length ? (
          <p className="state__message">
            Absent when anchored, which does not mean clean: {missing.map((name) => humanize(sanitizeDisplay(name))).join(", ")}
          </p>
        ) : null}
        <p className="state__message">Checked {formatDateTime(result.verified_at)}.</p>
        {result.note ? <p className="state__message">{sanitizeDisplay(result.note)}</p> : null}
      </div>
      <div className="panel__section">
        <FieldComparisonTable fields={Array.isArray(result.fields) ? result.fields : []} />
      </div>
    </>
  );
}

/** The only place that calls /verify, and only from the button. Failed requests are not UNKNOWN. */
export default function VerificationPanel({ scanId }) {
  const { status, result, error, verify } = useVerification(scanId);
  const checking = status === "checking";
  return (
    <>
      <div className="verify__head" aria-live="polite">
        <VerificationBadge state={status === "done" ? result.state : null} />
        {status === "done" ? <MockLabel source={result.source} isMock={result.is_mock} /> : null}
        <Button variant="secondary" icon={ShieldQuestion} loading={checking} onClick={verify}>
          {checking ? "Verifying" : "Verify"}
        </Button>
      </div>
      {status === "failed" ? (
        <div className="panel__section">
          <ErrorState
            error={error}
            onRetry={verify}
            headingLevel={3}
            title="The verification request failed"
          />
          <p className="state__message panel__section">
            No comparison was made, so this is not an UNKNOWN verification result.
          </p>
        </div>
      ) : null}
      {status === "done" ? <Result result={result} /> : null}
    </>
  );
}
