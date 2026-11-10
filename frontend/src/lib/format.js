// Display formatting. Missing values get words, so null can never read as 0.
export const NOT_COMPUTED = "Not computed yet";
export const NOT_AVAILABLE = "Not available";
export const NOT_RECORDED = "Not recorded";

const isNumber = (value) => typeof value === "number" && Number.isFinite(value);

const dateFormat = new Intl.DateTimeFormat("en-GB", {
  dateStyle: "medium",
  timeStyle: "short",
  timeZone: "UTC",
});

/** The ProvenanceX risk score (0 to 1). A real 0 stays "0.000". */
export function formatRiskScore(value) {
  return isNumber(value) ? value.toFixed(3) : NOT_COMPUTED;
}

export function formatConfidence(value) {
  return isNumber(value) ? value.toFixed(2) : NOT_COMPUTED;
}

/** Advisory CVSS base score (0 to 10). Separate from the ProvenanceX risk score. */
export function formatCvss(value) {
  return isNumber(value) ? value.toFixed(1) : "No CVSS score";
}

/** ML probability or anomaly score. Separate from the ProvenanceX risk score. */
export function formatProbability(value) {
  return isNumber(value) ? value.toFixed(3) : NOT_AVAILABLE;
}

export function formatCount(value) {
  return isNumber(value) ? value.toLocaleString("en-US") : NOT_AVAILABLE;
}

export function formatDateTime(value) {
  if (value === null || value === undefined || value === "") return NOT_RECORDED;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "Invalid date" : `${dateFormat.format(date)} UTC`;
}

/** Compact age such as "2m ago". Older than a week falls back to "Nov 9, 14:05". The full UTC time goes in a title. */
export function formatRelativeTime(value, now = Date.now()) {
  if (value === null || value === undefined || value === "") return NOT_RECORDED;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Invalid date";
  const seconds = Math.max(0, Math.round((now - date.getTime()) / 1000));
  if (seconds < 60) return "just now";
  const units = [[60, 60, "m"], [3600, 24, "h"], [86400, 7, "d"]];
  for (const [size, limit, suffix] of units) {
    const amount = Math.floor(seconds / size);
    if (amount < limit) return `${amount}${suffix} ago`;
  }
  return date.toLocaleString("en-US", { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", hour12: false, timeZone: "UTC" });
}

/** Turn an API code such as "ai_specific" into "Ai specific". */
export function humanize(value) {
  if (typeof value !== "string" || !value) return NOT_AVAILABLE;
  const words = value.replace(/[_-]+/g, " ").trim();
  return words.charAt(0).toUpperCase() + words.slice(1);
}

/** Shorten a long identifier while keeping both ends comparable. */
export function shortenMiddle(value, start = 10, end = 8) {
  if (value.length <= start + end + 1) return value;
  return `${value.slice(0, start)}…${value.slice(-end)}`;
}

/** A feature value from the risk engine. Null means no evidence, so it never reads as 0 or false. */
export function formatFeatureValue(value) {
  if (value === null || value === undefined) return "No value";
  if (typeof value === "boolean") return value ? "Yes" : "No";
  return String(value);
}

const SOURCE_HOSTS = new Set(["github.com", "huggingface.co"]);

/** True only for an https URL on an allowlisted host. `host` narrows it to one of them. */
export function isAllowedSourceUrl(value, host) {
  try {
    const url = new URL(value);
    return (
      url.protocol === "https:" &&
      !url.username &&
      !url.password &&
      !url.port &&
      SOURCE_HOSTS.has(url.hostname) &&
      (!host || url.hostname === host)
    );
  } catch {
    return false;
  }
}
