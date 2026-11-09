import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { ALLOW_MIN_CONFIDENCE, FLIP_NOTICE, layerLabel } from "../lib/policyDisplay.js";

describe("policy display values", () => {
  it("matches min_allow_confidence in the backend policy", () => {
    const policy = readFileSync(resolve(process.cwd(), "../backend/app/risk/policy_config.py"), "utf8");
    const match = /min_allow_confidence:\s*float\s*=\s*([\d.]+)/.exec(policy);
    expect(match).not.toBeNull();
    expect(ALLOW_MIN_CONFIDENCE).toBe(Number.parseFloat(match[1]));
  });

  it("states the flip threshold", () => {
    expect(FLIP_NOTICE).toContain("0.60");
    expect(FLIP_NOTICE).toContain("flip");
  });

  it("names layers", () => {
    expect(layerLabel("ai_specific")).toBe("AI-specific");
    expect(layerLabel("new_layer")).toBe("New layer");
  });
});
