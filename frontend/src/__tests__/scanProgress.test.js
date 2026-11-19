import { STEPS, activeStep, formatElapsed } from "../lib/scanProgress.js";

const done = { status: "completed" };
const stages = (...names) => Object.fromEntries(names.map((name) => [name, { status: "completed" }]));

describe("activeStep", () => {
  it("starts at the first step while queued or unknown", () => {
    expect(activeStep(null)).toBe(0);
    expect(activeStep({ status: "queued" })).toBe(0);
  });
  it("follows the recorded evidence stages while running", () => {
    expect(activeStep({ status: "running", stages: null })).toBe(1);
    expect(activeStep({ status: "running", stages: stages("sbom", "graph") })).toBe(1);
    expect(activeStep({ status: "running", stages: stages("sbom", "graph", "vulnerabilities", "provenance") })).toBe(2);
    expect(activeStep({ status: "running", stages: stages("aibom", "graph", "vulnerabilities", "provenance") })).toBe(2);
  });
  it("marks every step done only when the scan completes", () => {
    expect(activeStep(done)).toBe(STEPS.length);
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
