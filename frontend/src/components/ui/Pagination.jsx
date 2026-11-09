import { ArrowLeft, ArrowRight } from "lucide-react";
import { formatCount } from "../../lib/format.js";
import Button from "./Button.jsx";

function summary(total, limit, offset) {
  if (total === 0) return "No results";
  if (offset >= total) return `No rows at this page of ${formatCount(total)}`;
  return `Showing ${formatCount(offset + 1)} to ${formatCount(Math.min(offset + limit, total))} of ${formatCount(total)}`;
}

/** Works with /scans and /evidence (`has_more`) and with /findings (total only). */
export default function Pagination({ total, limit, offset, hasMore, onChange, label = "Pagination" }) {
  const more = hasMore ?? offset + limit < total;
  return (
    <nav className="pagination" aria-label={label}>
      <p>{summary(total, limit, offset)}</p>
      <div className="pagination__actions">
        <Button
          variant="secondary"
          size="small"
          icon={ArrowLeft}
          disabled={offset <= 0}
          onClick={() => onChange(Math.max(0, offset - limit))}
        >
          Previous
        </Button>
        <Button
          variant="secondary"
          size="small"
          icon={ArrowRight}
          disabled={!more}
          onClick={() => onChange(offset + limit)}
        >
          Next
        </Button>
      </div>
    </nav>
  );
}
