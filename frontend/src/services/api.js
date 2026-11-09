// API service layer. All backend calls go through here so error handling stays consistent.
const API_BASE = import.meta.env.VITE_API_BASE || "/api/v1";

export class ApiError extends Error {
  constructor({ code, message, details = null, status = 0 }) {
    super(message);
    this.name = "ApiError";
    this.code = code;
    this.details = details;
    this.status = status;
  }
}

/** Fetch JSON from the API; throws ApiError with the backend's structured error envelope. */
export async function request(path, options = {}) {
  let resp;
  try {
    resp = await fetch(`${API_BASE}${path}`, {
      ...options,
      headers: { Accept: "application/json", ...(options.headers || {}) },
    });
  } catch (err) {
    if (err.name === "AbortError") {
      throw new ApiError({ code: "aborted", message: "Request was cancelled" });
    }
    throw new ApiError({ code: "network_error", message: `API unreachable: ${err.message}` });
  }

  let body = null;
  try {
    body = await resp.json();
  } catch {
    body = null;
  }

  if (!resp.ok) {
    const e = body && body.error;
    throw new ApiError({
      code: (e && e.code) || `http_${resp.status}`,
      message: (e && e.message) || `Request failed with status ${resp.status}`,
      details: (e && e.details) || null,
      status: resp.status,
    });
  }
  return body;
}

/** Build a query string, leaving out empty values. A value of 0 is kept. */
function query(params) {
  const search = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== "") search.set(key, String(value));
  });
  const text = search.toString();
  return text ? `?${text}` : "";
}

function scanPath(scanId, suffix = "") {
  return `/scans/${encodeURIComponent(scanId)}${suffix}`;
}

/** The scan endpoints take a multipart form. The browser sets its Content-Type boundary. */
function scanForm(fields, file) {
  const form = new FormData();
  Object.entries(fields).forEach(([key, value]) => {
    if (value) form.set(key, value);
  });
  if (file) form.set("file", file);
  return form;
}

export const api = {
  health: () => request("/health"),
  ready: () => request("/health/ready"),

  listScans: ({ limit, offset, status, signal } = {}) =>
    request(`/scans${query({ limit, offset, status })}`, { signal }),

  createSoftwareScan: ({ sourceUrl, revision, name, file, signal } = {}) =>
    request("/scans/software", {
      method: "POST",
      body: scanForm({ source_url: sourceUrl, revision, name }, file),
      signal,
    }),

  createModelScan: ({ sourceUrl, revision, name, artifactType, file, signal } = {}) =>
    request("/scans/model", {
      method: "POST",
      body: scanForm({ source_url: sourceUrl, revision, name, artifact_type: artifactType }, file),
      signal,
    }),

  getScan: (scanId, { signal } = {}) => request(scanPath(scanId), { signal }),

  getFindings: (scanId, { category, severity, source, limit, offset, signal } = {}) =>
    request(scanPath(scanId, `/findings${query({ category, severity, source, limit, offset })}`), {
      signal,
    }),

  getGraph: (scanId, { signal } = {}) => request(scanPath(scanId, "/graph"), { signal }),

  getRisk: (scanId, { signal } = {}) => request(scanPath(scanId, "/risk"), { signal }),

  getEvidence: (
    scanId,
    { findingsLimit, findingsOffset, componentsLimit, componentsOffset, signal } = {},
  ) =>
    request(
      scanPath(
        scanId,
        `/evidence${query({
          findings_limit: findingsLimit,
          findings_offset: findingsOffset,
          components_limit: componentsLimit,
          components_offset: componentsOffset,
        })}`,
      ),
      { signal },
    ),

  getBlockchain: (scanId, { signal } = {}) => request(scanPath(scanId, "/blockchain"), { signal }),

  verifyScan: (scanId, { signal } = {}) =>
    request(scanPath(scanId, "/verify"), { method: "POST", signal }),
};
