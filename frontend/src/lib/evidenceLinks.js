// Maps the backend's evidence links to dashboard routes. Unknown links return null, so the UI
// shows no link rather than navigating to a value it did not recognize.
const UUID = "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}";
const SCAN_LINK = new RegExp(`^/api/v1/scans/(${UUID})(/[a-z]+)?(?:\\?category=([a-z]+))?$`);
const CATEGORIES = new Set(["vulnerability", "static", "behavioral", "provenance"]);
const SOFTWARE_TYPES = new Set(["software", "container"]);

const LABELS = {
  vulnerability_findings: "Vulnerability findings",
  provenance_findings: "Provenance findings",
  static_findings: "Static findings",
  behavioral_findings: "Behavioral findings",
  scan_stages: "Scan stages",
  graph: "Graph",
};

/** artifactType picks the graph page. Without it a graph link is left out rather than guessed. */
export function evidenceRoute(href, { artifactType } = {}) {
  if (typeof href !== "string") return null;
  const match = SCAN_LINK.exec(href);
  if (!match) return null;
  const [, scanId, section, category] = match;
  const scan = `scan=${scanId}`;

  if (category && (section !== "/findings" || !CATEGORIES.has(category))) return null;
  switch (section) {
    case undefined:
    case "/evidence":
      return `/scans/${scanId}`;
    case "/findings":
      return category ? `/findings?${scan}&category=${category}` : `/findings?${scan}`;
    case "/graph":
      if (!artifactType) return null;
      return `${SOFTWARE_TYPES.has(artifactType) ? "/graph" : "/lineage"}?${scan}`;
    case "/risk":
      return `/risk?${scan}`;
    case "/blockchain":
      return `/blockchain?${scan}`;
    default:
      return null;
  }
}

export function evidenceLabel(rel) {
  return LABELS[rel] || "Evidence";
}
