import { useState } from "react";
import { Check, Copy, TriangleAlert } from "lucide-react";
import { NOT_AVAILABLE, shortenMiddle } from "../../lib/format.js";
import Button from "./Button.jsx";

export const HASH_FORMATS = {
  sha256: /^[0-9a-f]{64}$/i,
  commit: /^[0-9a-f]{40}$/i,
  tx: /^0x[0-9a-f]{64}$/i,
  address: /^0x[0-9a-f]{40}$/i,
  uuid: /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
};

/**
 * Shows a hash or ID as plain text, only after it matches the expected format.
 * A value that fails the check is not displayed at all. `reason` explains a missing value.
 */
export default function HashValue({ value, kind = "sha256", label = "value", reason, truncate = false }) {
  const [copyState, setCopyState] = useState("idle");

  if (value === null || value === undefined || value === "") {
    return <span className="hash__missing">{reason || NOT_AVAILABLE}</span>;
  }
  const format = HASH_FORMATS[kind];
  if (!format || typeof value !== "string" || !format.test(value)) {
    return (
      <span className="hash__invalid">
        <TriangleAlert size={14} aria-hidden="true" />
        Invalid format
      </span>
    );
  }

  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      setCopyState("copied");
    } catch {
      setCopyState("failed");
    }
  }

  const copyLabel = { idle: "Copy", copied: "Copied", failed: "Copy failed" }[copyState];
  return (
    <span className="hash">
      <code className="hash__value" title={truncate ? value : undefined}>
        {truncate ? shortenMiddle(value) : value}
      </code>
      <Button
        variant="ghost"
        size="small"
        icon={copyState === "copied" ? Check : Copy}
        aria-label={`${copyLabel} ${label}`}
        onClick={copy}
      >
        {copyLabel}
      </Button>
    </span>
  );
}
