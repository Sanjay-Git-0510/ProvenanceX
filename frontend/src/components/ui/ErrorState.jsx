import { CircleX, RotateCw } from "lucide-react";
import { sanitizeDisplay } from "../../lib/sanitizeDisplay.js";
import Button from "./Button.jsx";

function canRetry(error) {
  const status = error?.status ?? 0;
  return status === 0 || status === 408 || status === 429 || status >= 500;
}

/** Says what failed and whether retrying can help. `error.details` is never displayed. */
export default function ErrorState({ error, title = "Could not load this data", headingLevel = 2, onRetry }) {
  const Heading = `h${headingLevel}`;
  const retryable = canRetry(error);
  return (
    <div className="state state--error" role="alert">
      <CircleX className="state__icon" size={20} aria-hidden="true" />
      <Heading>{title}</Heading>
      <p className="state__message">{sanitizeDisplay(error?.message) || "An unexpected error occurred."}</p>
      {error?.code ? <code className="state__code">{sanitizeDisplay(error.code)}</code> : null}
      <p className="state__message">
        {retryable ? "This may be temporary. You can retry." : "Retrying will not help until the request changes."}
      </p>
      {onRetry && retryable ? (
        <div className="state__action">
          <Button variant="secondary" size="small" icon={RotateCw} onClick={onRetry}>
            Retry
          </Button>
        </div>
      ) : null}
    </div>
  );
}
