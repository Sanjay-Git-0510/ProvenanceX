import { STAGE_STATES, formatElapsed, stageStatuses, workflowKind } from "../lib/scanStages.js";

const entry = (status, extra = {}) => ({ status, ...extra });
const states = (scan, kind) => Object.fromEntries(stageStatuses(scan, kind).map((s) => [s.key, s.state]));

describe("stageStatuses", () => {
  it("lists software and model stages in pipeline order", () => {
    expect(stageStatuses(null, "software").map((s) => s.key)).toEqual([
      "fetch", "sbom", "graph", "vulnerabilities", "provenance", "static", "sandbox", "risk", "anchor",
    ]);
    expect(stageStatuses(null, "model")[1].key).toBe("aibom");
  });

  it("shows every stage waiting while queued", () => {
    expect(new Set(Object.values(states({ status: "queued" }, "software")))).toEqual(new Set(["pending"]));
  });

  it("marks only the first unrecorded stage in progress while running", () => {
    const scan = { status: "running", artifact: { sha256: "a".repeat(64) }, stages: { sbom: entry("completed") } };
    const s = states(scan, "software");
    expect(s.fetch).toBe("done");
    expect(s.sbom).toBe("done");
    expect(s.graph).toBe("active");
    expect(s.vulnerabilities).toBe("pending");
    expect(Object.values(s).filter((v) => v === "active")).toHaveLength(1);
  });

  it("maps every recorded backend status and never invents done", () => {
    const scan = {
      status: "running",
      stages: {
        aibom: entry("partial"),
        graph: entry("error"),
        vulnerabilities: entry("unavailable"),
        provenance: entry("skipped", { reason: "no source" }),
        static: entry("weird"),
      },
    };
    const list = stageStatuses(scan, "model");
    const s = Object.fromEntries(list.map((x) => [x.key, x.state]));
    expect(s).toMatchObject({
      fetch: "done",
      aibom: "partial",
      graph: "error",
      vulnerabilities: "unavailable",
      provenance: "skipped",
      static: "not_reported",
      sandbox: "active",
      risk: "pending",
    });
    expect(list.find((x) => x.key === "provenance").reason).toBe("no source");
  });

  it("does not mark fetch done before the backend reports anything", () => {
    expect(states({ status: "running", stages: null }, "software").fetch).toBe("active");
  });

  it("marks unrecorded stages not run after a failure and not reported after completion", () => {
    expect(states({ status: "failed", stages: null }, "software").sbom).toBe("not_run");
    const done = states({ status: "completed", stages: { sbom: entry("completed") } }, "software");
    expect(done.sbom).toBe("done");
    expect(done.anchor).toBe("not_reported");
  });

  it("keeps the provider so mock stages can be labelled", () => {
    const list = stageStatuses({ status: "running", stages: { sbom: entry("completed", { provider: "mock" }) } });
    expect(list.find((x) => x.key === "sbom").provider).toBe("mock");
  });

  it("has words for every state", () => {
    Object.values(STAGE_STATES).forEach((meta) => expect(meta.label).toBeTruthy());
  });
});

describe("workflowKind", () => {
  it("groups artifact types", () => {
    expect(workflowKind("software")).toBe("software");
    expect(workflowKind("container")).toBe("software");
    expect(workflowKind("lora")).toBe("model");
    expect(workflowKind("dataset")).toBe("model");
  });
});

describe("formatElapsed", () => {
  it("formats mm:ss and hours", () => {
    expect(formatElapsed(0)).toBe("00:00");
    expect(formatElapsed(7.9)).toBe("00:07");
    expect(formatElapsed(125)).toBe("02:05");
    expect(formatElapsed(3723)).toBe("1:02:03");
    expect(formatElapsed(-4)).toBe("00:00");
  });
});
