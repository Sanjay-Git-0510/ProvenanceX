function LineSample({ inferred }) {
  return (
    <svg width="32" height="8" aria-hidden="true">
      <line className={`graph-edge${inferred ? " graph-edge--inferred" : ""}`} x1="0" y1="4" x2="32" y2="4" />
    </svg>
  );
}

function BoxSample({ variant }) {
  return (
    <svg className={`graph-node graph-node--${variant}`} width="24" height="16" aria-hidden="true">
      <rect x="1" y="1" width="22" height="14" rx="4" />
    </svg>
  );
}

/** Keys the outline and line styles. Node type is written on each node, never colour-coded. */
export default function GraphLegend() {
  return (
    <ul className="graph-legend" aria-label="Graph legend">
      <li>
        <BoxSample variant="root" /> Root artifact, marked “Root”
      </li>
      <li>
        <BoxSample variant="selected" /> Selected node
      </li>
      <li>
        <LineSample /> Recorded relation
      </li>
      <li>
        <LineSample inferred /> Inferred relation
      </li>
    </ul>
  );
}
