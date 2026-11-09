// Display guard for artifact-derived text from endpoints the backend does not sanitize
// (/findings, /graph). It mirrors `sanitize` in backend/app/schemas/evidence.py. It is pattern
// based, so it reduces leakage and cannot recognize every secret. Never apply it to hashes:
// the 0x pattern below would redact real transaction hashes.
export const REDACTED = "[redacted]";
export const TRUNCATED = "...[truncated]";
export const MAX_TEXT = 1024;

const HOST_ROOTS =
  "home|root|app|tmp|var|etc|mnt|workspace|workspaces|usr|opt|srv|proc|run|dev|sys|bin|lib|Users";

const SENSITIVE = [
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/g,
  /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}/g,
  /\bgithub_pat_[A-Za-z0-9_]{20,}/g,
  /\bhf_[A-Za-z0-9]{20,}/g,
  /\bsk-[A-Za-z0-9_-]{20,}/g,
  /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g,
  /\b0x[0-9a-fA-F]{64}\b/g,
  /\bbearer\s+[A-Za-z0-9._~+/=-]{8,}/gi,
  /\b(?:password|passwd|secret|token|api[_-]?key|private[_-]?key)\s*[=:]\s*\S+/gi,
  /[a-z][a-z0-9+.-]*:\/\/[^/\s:@]+:[^/\s@]+@\S*/g,
  /\bfile:\/+\S*/gi,
  /\b[A-Za-z]:\\[^\s'"]*/g,
  /\\\\[^\s\\'"]+\\[^\s'"]*/g,
  new RegExp(`(?<![\\w:.\\-/])/(?:${HOST_ROOTS})(?:/[^\\s'"]*)?(?![\\w-])`, "g"),
];

/** Returns display-safe plain text. Anything that is not a string becomes an empty string. */
export function sanitizeDisplay(value) {
  if (typeof value !== "string") return "";
  const cleaned = SENSITIVE.reduce((text, pattern) => text.replace(pattern, REDACTED), value);
  return cleaned.length > MAX_TEXT ? cleaned.slice(0, MAX_TEXT) + TRUNCATED : cleaned;
}
