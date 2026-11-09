// Shared page-test helpers. Fixture values are test inputs, never shown by the application.
import { render } from "@testing-library/react";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";

export const SCAN_ID = "11111111-2222-4333-8444-555555555555";
export const SCAN_B = "66666666-7777-4888-8999-aaaaaaaaaaaa";
export const SHA = "a".repeat(64);
export const CANARY = "PX_DETAILS_CANARY_71c";
export const HOST_PATH = "/home/victim/app.py";

const future = { v7_startTransition: true, v7_relativeSplatPath: true };

function json(status, body) {
  return Promise.resolve({ ok: status < 400, status, json: () => Promise.resolve(body) });
}

/** Stub fetch. `routes` is a list of [regex, body or function, status]; the first match wins. */
export function mockApi(routes) {
  const fetchMock = vi.fn((url, options) => {
    for (const [pattern, body, status = 200] of routes) {
      if (pattern.test(url)) return json(status, typeof body === "function" ? body(url, options) : body);
    }
    return json(404, { error: { code: "unexpected_call", message: `No stub for ${url}` } });
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

export const calledUrls = (fetchMock) => fetchMock.mock.calls.map(([url]) => url);

function LocationProbe() {
  const { pathname, search } = useLocation();
  return <output data-testid="location">{`${pathname}${search}`}</output>;
}

export function renderPage(element, { path = "/", route = "/" } = {}) {
  return render(
    <MemoryRouter initialEntries={[path]} future={future}>
      <Routes>
        <Route path={route} element={element} />
        <Route path="*" element={null} />
      </Routes>
      <LocationProbe />
    </MemoryRouter>,
  );
}

/** Fails if any rendered ALLOW is missing its not-evaluated layers and confidence. */
export function expectEveryAllowHasCaveat(container, { minimum = 1 } = {}) {
  const allows = [...container.querySelectorAll(".badge--allow")].filter((badge) =>
    badge.textContent.trim().startsWith("ALLOW"),
  );
  expect(allows.length).toBeGreaterThanOrEqual(minimum);
  allows.forEach((badge) => {
    const holder = badge.closest('[data-allow="true"]');
    if (!holder) throw new Error("ALLOW rendered without its caveat container");
    const caveat = holder.querySelector(".allow-caveat");
    if (!caveat) throw new Error("ALLOW rendered without AllowCaveat");
    if (!/Confidence:\s*\S/.test(caveat.textContent)) throw new Error("ALLOW rendered without confidence");
    if (!/Not evaluated:\s*\S/.test(caveat.textContent)) throw new Error("ALLOW rendered without not-evaluated layers");
    if (!/can flip/.test(caveat.textContent)) throw new Error("ALLOW rendered without the flip notice");
  });
}

export function scanRow(overrides = {}) {
  return {
    scan_id: SCAN_ID,
    status: "completed",
    created_at: "2026-11-09T07:05:00Z",
    finished_at: "2026-11-09T07:06:00Z",
    artifact: { name: "demo-app", artifact_type: "software", source: "upload" },
    decision: null,
    risk_score: null,
    confidence: null,
    ...overrides,
  };
}

export function scanList(items, page = {}) {
  return { page: { total: items.length, limit: 20, offset: 0, has_more: false, ...page }, items };
}

export function finding(overrides = {}) {
  return {
    finding_id: "f1",
    category: "vulnerability",
    kind: "known_vulnerability",
    identifier: "GHSA-aaaa-bbbb-cccc",
    aliases: ["CVE-2026-0001"],
    title: "A title",
    severity: "HIGH",
    severity_source: "osv",
    cvss: { score: 8.8, vector: "CVSS:3.1/AV:N", version: "3.1", source: "osv" },
    source: "osv",
    is_mock: false,
    component: { component_id: null, name: "requests", version: "2.32.3", purl: "pkg:pypi/requests@2.32.3", ecosystem: "pypi" },
    details: { secret_detail: CANARY },
    ...overrides,
  };
}

export function findingsPage(items, overrides = {}) {
  return {
    scan_id: SCAN_ID,
    total: items.length,
    limit: 50,
    offset: 0,
    items,
    contains_mock: false,
    stage: null,
    stages: { vulnerability: { status: "completed", raw_blob: CANARY } },
    ...overrides,
  };
}

const emptyScore = (label) => ({ label, value: null, reason: `${label} has no value` });

export function riskResult(overrides = {}) {
  return {
    scan_id: SCAN_ID,
    scan_status: "completed",
    status: "computed",
    reason: null,
    risk_score: 0.3,
    decision: "ALLOW",
    decision_basis: "rules",
    decision_reasons: ["A reason"],
    allow_reason: "Enough evidence was clean",
    confidence: 0.61,
    confidence_label: "MEDIUM",
    layers: [
      { layer: "vulnerability", status: "not_evaluated", score: null, coverage: 0, weight: 0.3, contribution: null, evidence_links: [] },
      { layer: "static", status: "evaluated", score: 0.2, coverage: 1, weight: 0.2, contribution: 0.04, evidence_links: [{ rel: "static_findings", href: `/api/v1/scans/${SCAN_ID}/findings?category=static` }] },
    ],
    not_evaluated_layers: ["vulnerability", "behavioral"],
    partial_layers: [],
    hard_rules: { fired: [], not_evaluated: [] },
    scores: {
      provenancex_risk: { label: "ProvenanceX risk (0 to 1)", value: 0.3, reason: null },
      cvss_max: { label: "Highest CVSS base score", value: 7.5, reason: null },
      ml_probability: { label: "Random Forest probability", value: 0.465, reason: null },
      anomaly_score: { label: "Isolation Forest anomaly score", value: 0.51, reason: null },
    },
    ml: { status: "available" },
    explanation: {
      status: "available",
      top_factors: [
        { feature: "script_presence", layer: "static", value: true, evaluated: true, null_reason: null, shap_contribution: 0.2, direction: "raises_model_probability", evidence_links: [] },
        { feature: "commit_age", layer: "provenance_integrity", value: null, evaluated: false, null_reason: "not_determinable", shap_contribution: -0.1, direction: "lowers_model_probability", evidence_links: [] },
      ],
      not_evaluated_features: [{ feature: "network_count", layer: "behavioral", null_reason: "stage_not_run" }],
    },
    training_data: { label: "synthetic", models_used: true, notice: "Models were trained on synthetic data." },
    evidence_links: [],
    contains_mock_evidence: false,
    policy_version: "p1",
    computed_at: "2026-11-09T07:06:00Z",
    ...overrides,
  };
}

export function noRisk(status, code, message) {
  return riskResult({
    status,
    reason: { code, message },
    risk_score: null,
    decision: null,
    decision_reasons: [],
    allow_reason: null,
    confidence: null,
    confidence_label: null,
    layers: [],
    not_evaluated_layers: [],
    explanation: null,
    scores: {
      provenancex_risk: emptyScore("ProvenanceX risk"),
      cvss_max: emptyScore("CVSS"),
      ml_probability: emptyScore("ML probability"),
      anomaly_score: emptyScore("Anomaly score"),
    },
  });
}

const hash = (value, reason = null) => ({ value, reason });

export function evidence(overrides = {}) {
  return {
    scan_id: SCAN_ID,
    scan_status: "completed",
    scan_error: null,
    scanner_version: "0.1.0",
    artifact: {
      artifact_id: SCAN_B,
      name: "demo-app",
      artifact_type: "software",
      version: "main",
      source: "github",
      source_url: "https://github.com/a/b",
      sha256: SHA,
      collected_at: "2026-11-09T07:05:00Z",
      scan_id: SCAN_ID,
    },
    stages: [{ name: "sbom", status: "completed", source: "syft", is_mock: false, finished_at: "2026-11-09T07:05:30Z", incomplete_reasons: [], limitations: [], warnings: [] }],
    feature_vector: { status: "available", features: [] },
    findings: { page: { total: 2, limit: 1, offset: 0, has_more: true }, by_category: { vulnerability: 2 }, by_severity: {}, by_source: {}, items: [] },
    components: { page: { total: 7, limit: 1, offset: 0, has_more: true }, by_source: {}, items: [] },
    provenance: {
      source_known: true,
      revision_pinned: false,
      resolved_commit: "b".repeat(40),
      signed: null,
      signature_files_present: false,
      provenance_present: false,
      hash_changed: false,
      previous_scan_id: null,
      lineage_completeness: null,
      source: "provenancex",
      is_mock: false,
      checks: [{ name: "download_integrity", status: "pass", evidence: "Hashes matched", severity: null, identifier: null }],
      checks_truncated: false,
      created_at: "2026-11-09T07:05:00Z",
    },
    hashes: {
      artifact_sha256: hash(SHA),
      bom_sha256: hash(null, "No SBOM was produced"),
      provenance_record_sha256: hash("c".repeat(64)),
      sandbox_trace_sha256: hash(null, "Sandbox was not run"),
    },
    model: { model_version: null, ml_status: "available" },
    mock: { contains_mock_evidence: false, mock_stages: [], mock_findings: 0, mock_components: 0, provenance_is_mock: false },
    training_data: { label: "synthetic", models_used: true, notice: "Models were trained on synthetic data." },
    sanitized: { redacted_values: 0, truncated_values: 0 },
    ...overrides,
  };
}
