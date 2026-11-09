import { readdirSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";

const root = process.cwd();
const tokensCss = readFileSync(resolve(root, "src/styles/tokens.css"), "utf8");
const tokens = Object.fromEntries(
  [...tokensCss.matchAll(/--([\w-]+):\s*([^;]+);/g)].map(([, name, value]) => [name, value.trim()]),
);

function parseColor(value) {
  const hex = /^#([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})$/i.exec(value);
  if (hex) return { rgb: hex.slice(1).map((part) => parseInt(part, 16)), alpha: 1 };
  const rgba = /^rgba\((\d+),\s*(\d+),\s*(\d+),\s*([\d.]+)\)$/.exec(value);
  if (rgba) return { rgb: rgba.slice(1, 4).map(Number), alpha: Number(rgba[4]) };
  throw new Error(`Unparseable colour: ${value}`);
}

const token = (name) => {
  if (!(name in tokens)) throw new Error(`Missing token: ${name}`);
  return parseColor(tokens[name]);
};

function composite(top, bottom) {
  return top.rgb.map((channel, i) => channel * top.alpha + bottom.rgb[i] * (1 - top.alpha));
}

function luminance(rgb) {
  const [r, g, b] = rgb.map((channel) => {
    const c = channel / 255;
    return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

function contrast(a, b) {
  const [high, low] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (high + 0.05) / (low + 0.05);
}

const SURFACES = ["surface-0", "surface-1", "surface-2", "surface-3"];
const TEXT = ["text-primary", "text-secondary", "text-tertiary"];
const COLOURED = ["accent", "status-allow", "status-review", "status-block", "status-unknown"];

const textPairs = [
  ...[...TEXT, ...COLOURED].flatMap((fg) => SURFACES.map((bg) => [fg, bg])),
  ["status-allow", "status-allow-tint"],
  ["status-review", "status-review-tint"],
  ["status-block", "status-block-tint"],
  ["status-unknown", "status-unknown-tint"],
  ["accent", "accent-tint"],
  ["on-accent", "accent"],
  ["on-accent", "accent-hover"],
];

describe("WCAG AA contrast on actual backgrounds", () => {
  it.each(textPairs)("text %s on %s is at least 4.5:1", (fg, bg) => {
    expect(contrast(token(fg).rgb, token(bg).rgb)).toBeGreaterThanOrEqual(4.5);
  });

  it.each(SURFACES)("control line and focus ring on %s are at least 3:1", (bg) => {
    expect(contrast(token("line-control").rgb, token(bg).rgb)).toBeGreaterThanOrEqual(3);
    expect(contrast(token("accent").rgb, token(bg).rgb)).toBeGreaterThanOrEqual(3);
  });

  // The worst case for glass is the lightest page content scrolling behind it.
  it.each(["text-primary", "text-secondary", "status-allow", "status-review", "status-block"])(
    "%s stays readable on glass over the lightest backdrop",
    (fg) => {
      const glass = composite(token("glass-fill"), token("text-primary"));
      expect(contrast(token(fg).rgb, glass)).toBeGreaterThanOrEqual(4.5);
    },
  );

  it("surfaces get steadily lighter", () => {
    const levels = SURFACES.map((name) => luminance(token(name).rgb));
    expect(levels).toEqual([...levels].sort((a, b) => a - b));
    expect(new Set(levels).size).toBe(SURFACES.length);
  });
});

describe("design tokens", () => {
  const rem = (name) => Number.parseFloat(tokens[name]) * 16;

  it("uses the approved type scale", () => {
    const sizes = [12, 14, 16, 20, 24, 30, 36, 48];
    expect(sizes.map((size) => rem(`text-${size}`))).toEqual(sizes);
  });

  it("keeps spacing on the 8px grid with one 4px half-step", () => {
    const steps = Object.keys(tokens).filter((name) => name.startsWith("space-"));
    expect(rem("space-half")).toBe(4);
    steps.filter((name) => name !== "space-half").forEach((name) => {
      expect(rem(name) % 8).toBe(0);
    });
  });

  it("keeps motion between 150 and 250 ms", () => {
    ["motion-fast", "motion-base", "motion-slow"].forEach((name) => {
      const ms = Number.parseInt(tokens[name], 10);
      expect(ms).toBeGreaterThanOrEqual(150);
      expect(ms).toBeLessThanOrEqual(250);
    });
  });
});

function sourceFiles(dir) {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) return entry.name === "__tests__" || entry.name === "test" ? [] : sourceFiles(path);
    return /\.(js|jsx|css)$/.test(entry.name) ? [path] : [];
  });
}

describe("source rules", () => {
  const files = [...sourceFiles(resolve(root, "src")), resolve(root, "index.html")].map((path) => ({
    path,
    text: readFileSync(path, "utf8"),
  }));
  const offenders = (pattern) => files.filter(({ text }) => pattern.test(text)).map(({ path }) => path);

  it("scans the real source tree", () => {
    expect(files.length).toBeGreaterThan(30);
  });

  it("never injects raw HTML", () => {
    expect(offenders(/dangerouslySetInnerHTML|\.innerHTML|insertAdjacentHTML/)).toEqual([]);
  });

  it("loads nothing from an external host", () => {
    expect(offenders(/https?:\/\/|\/\/fonts\.g|@import\s+url/)).toEqual([]);
  });

  it("uses no gradients", () => {
    expect(offenders(/gradient\(/)).toEqual([]);
  });

  it("uses glass only through the approved classes", () => {
    const blurred = offenders(/backdrop-filter/).map((path) => path.split("/").pop());
    expect(blurred.sort()).toEqual(["components.css", "layout.css"]);
    const components = files.find(({ path }) => path.endsWith("components.css")).text;
    const selectors = [...components.matchAll(/^\s*\.([\w-]+) \{\n(?:[^}]*?)backdrop-filter/gm)].map((m) => m[1]);
    expect(new Set(selectors)).toEqual(new Set(["modal-backdrop"]));
  });

  it("applies the glass class only to the header and its controls", () => {
    const users = offenders(/className=[^>]*\bglass\b/).map((path) => path.split("/").pop());
    expect(users.sort()).toEqual(["Layout.jsx", "StatusBadge.jsx"]);
  });

  it("gives every glass rule a solid fallback", () => {
    ["layout.css", "components.css"].forEach((name) => {
      const { text } = files.find(({ path }) => path.endsWith(name));
      expect(text).toContain("@supports (backdrop-filter");
      expect(text).toContain("prefers-reduced-transparency: reduce");
    });
  });

  it("imports only the Latin 400 and 500 weights of Plex Mono", () => {
    const main = files.find(({ path }) => path.endsWith("main.jsx")).text;
    const imports = [...main.matchAll(/@fontsource\/ibm-plex-mono\/([\w-]+\.css)/g)].map((m) => m[1]);
    expect(imports).toEqual(["latin-400.css", "latin-500.css"]);
  });

  it("honours reduced motion", () => {
    expect(files.find(({ path }) => path.endsWith("base.css")).text).toContain("prefers-reduced-motion: reduce");
  });
});
