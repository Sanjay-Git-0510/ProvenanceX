import { ArrowUpRight } from "lucide-react";
import useFindings from "../../hooks/useFindings.js";
import { formatCount } from "../../lib/format.js";
import Button from "../ui/Button.jsx";
import ErrorState from "../ui/ErrorState.jsx";
import LoadingState from "../ui/LoadingState.jsx";
import Panel from "../ui/Panel.jsx";
import FindingsTable, { FindingsEmpty } from "./FindingsTable.jsx";
import { categoryLabel } from "./FindingCategoryBadge.jsx";

const PREVIEW = 5;

/** The first findings of one kind, with a link to the full, paginated list. */
export default function FindingsPreview({ scanId, category, title, className }) {
  const { status, data, error, reload } = useFindings(scanId, { category, limit: PREVIEW });
  const label = title || `${categoryLabel(category)} findings`;
  return (
    <Panel
      title={label}
      className={className}
      actions={
        <Button variant="ghost" size="small" icon={ArrowUpRight} to={`/findings?scan=${scanId}&category=${category}`}>
          View all
        </Button>
      }
    >
      {status === "loading" && !data ? <LoadingState label={`Loading ${label.toLowerCase()}`} lines={2} /> : null}
      {status === "error" ? <ErrorState error={error} onRetry={reload} headingLevel={3} /> : null}
      {data ? (
        <>
          <FindingsTable
            caption={`Table of ${label.toLowerCase()}`}
            findings={data.items ?? []}
            empty={<FindingsEmpty stages={data.stages} category={category} />}
          />
          {data.total > 0 ? (
            <p className="state__message preview-count">
              Showing {formatCount(Math.min(PREVIEW, data.items?.length ?? 0))} of {formatCount(data.total)}
            </p>
          ) : null}
        </>
      ) : null}
    </Panel>
  );
}
