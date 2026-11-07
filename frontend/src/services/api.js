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
      headers: { Accept: "application/json", ...(options.headers || {}) },
      ...options,
    });
  } catch (err) {
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

export const api = {
  health: () => request("/health"),
  ready: () => request("/health/ready"),
};
