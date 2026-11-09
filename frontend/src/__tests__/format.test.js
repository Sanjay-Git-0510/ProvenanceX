import { evidenceLabel, evidenceRoute } from "../lib/evidenceLinks.js";
import {
  NOT_AVAILABLE,
  NOT_COMPUTED,
  NOT_RECORDED,
  formatConfidence,
  formatCount,
  formatCvss,
  formatDateTime,
  formatProbability,
  formatRiskScore,
  humanize,
  shortenMiddle,
} from "../lib/format.js";

describe("score formatting", () => {
  it.each([null, undefined, NaN, Infinity, "0.5"])("%s risk score is not computed, never 0", (value) => {
    expect(formatRiskScore(value)).toBe(NOT_COMPUTED);
    expect(formatConfidence(value)).toBe(NOT_COMPUTED);
  });

  it("keeps a real 0 as a number", () => {
    expect(formatRiskScore(0)).toBe("0.000");
    expect(formatConfidence(0)).toBe("0.00");
    expect(formatCvss(0)).toBe("0.0");
    expect(formatProbability(0)).toBe("0.000");
  });

  it("formats real values", () => {
    expect(formatRiskScore(0.483452)).toBe("0.483");
    expect(formatConfidence(0.606)).toBe("0.61");
    expect(formatCvss(8.8)).toBe("8.8");
  });

  it("names missing CVSS and ML values separately from risk", () => {
    expect(formatCvss(null)).toBe("No CVSS score");
    expect(formatProbability(null)).toBe(NOT_AVAILABLE);
  });
});

describe("other formatting", () => {
  it("formats counts, keeping 0", () => {
    expect(formatCount(1234)).toBe("1,234");
    expect(formatCount(0)).toBe("0");
    expect(formatCount(null)).toBe(NOT_AVAILABLE);
  });

  it("formats dates in UTC", () => {
    expect(formatDateTime("2026-11-09T07:05:00Z")).toBe("9 Nov 2026, 07:05 UTC");
  });

  it.each([null, undefined, ""])("%s date is not recorded", (value) => {
    expect(formatDateTime(value)).toBe(NOT_RECORDED);
  });

  it("flags a bad date", () => {
    expect(formatDateTime("nope")).toBe("Invalid date");
  });

  it("humanizes codes", () => {
    expect(humanize("no_rule_layer_scored")).toBe("No rule layer scored");
    expect(humanize(null)).toBe(NOT_AVAILABLE);
  });

  it("shortens only long values", () => {
    expect(shortenMiddle("a".repeat(64))).toBe(`${"a".repeat(10)}…${"a".repeat(8)}`);
    expect(shortenMiddle("short")).toBe("short");
  });
});

describe("evidence links", () => {
  const id = "11111111-2222-4333-8444-555555555555";
  const api = `/api/v1/scans/${id}`;

  it.each([
    [api, `/scans/${id}`],
    [`${api}/evidence`, `/scans/${id}`],
    [`${api}/findings`, `/findings?scan=${id}`],
    [`${api}/findings?category=static`, `/findings?scan=${id}&category=static`],
    [`${api}/risk`, `/risk?scan=${id}`],
    [`${api}/blockchain`, `/blockchain?scan=${id}`],
  ])("maps %s", (href, route) => {
    expect(evidenceRoute(href)).toBe(route);
  });

  it("sends software to the dependency graph and models to lineage", () => {
    expect(evidenceRoute(`${api}/graph`, { artifactType: "software" })).toBe(`/graph?scan=${id}`);
    expect(evidenceRoute(`${api}/graph`, { artifactType: "lora" })).toBe(`/lineage?scan=${id}`);
  });

  it.each([
    null,
    "https://evil.test/api/v1/scans/x",
    "javascript:alert(1)",
    "/api/v1/scans/not-a-uuid/risk",
    `${api}/unknown`,
    `${api}/findings?category=evil`,
    `${api}/risk?category=static`,
  ])("refuses %s", (href) => {
    expect(evidenceRoute(href)).toBeNull();
  });

  it("labels links", () => {
    expect(evidenceLabel("static_findings")).toBe("Static findings");
    expect(evidenceLabel("other")).toBe("Evidence");
  });
});
