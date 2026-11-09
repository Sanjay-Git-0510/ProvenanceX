import { humanize } from "../../lib/format.js";

const MAX_CONNECTIONS = 25;

function Connections({ title, connections }) {
  if (connections.length === 0) return null;
  const hidden = connections.length - MAX_CONNECTIONS;
  return (
    <div className="panel__section">
      <h3 className="graph-inspector__heading">
        {title} ({connections.length})
      </h3>
      <ul className="graph-inspector__list">
        {connections.slice(0, MAX_CONNECTIONS).map(({ id, label, relation, origin }) => (
          <li key={id}>
            {label} <span className="graph-inspector__meta">· {humanize(relation)} · {humanize(origin)}</span>
          </li>
        ))}
      </ul>
      {hidden > 0 ? <p className="state__message">{hidden} more in the edges table.</p> : null}
    </div>
  );
}

/** Named fields of the selected node. Its text was sanitized by normalizeGraph. */
export default function NodeInspector({ graph, selectedKey, rootKey }) {
  const node = graph.nodes.find((candidate) => candidate.key === selectedKey);
  if (!node) {
    return <p className="state__message">Select a node in the drawing or the nodes table to see its details.</p>;
  }

  const labels = new Map(graph.nodes.map((candidate) => [candidate.key, candidate.label]));
  const connection = (edge, otherKey) => ({ ...edge, label: labels.get(otherKey) });
  const outgoing = graph.edges.filter((edge) => edge.source === node.key).map((edge) => connection(edge, edge.target));
  const incoming = graph.edges.filter((edge) => edge.target === node.key).map((edge) => connection(edge, edge.source));

  return (
    <>
      <dl className="dl">
        <div className="dl__row">
          <dt>Label</dt>
          <dd>{node.label}</dd>
        </div>
        <div className="dl__row">
          <dt>Type</dt>
          <dd>
            {humanize(node.type)}
            {node.key === rootKey ? " (root)" : ""}
          </dd>
        </div>
        <div className="dl__row">
          <dt>Node key</dt>
          <dd className="is-mono">{node.displayKey}</dd>
        </div>
        {node.details.map(({ field, label, value }) => (
          <div className="dl__row" key={field}>
            <dt>{label}</dt>
            <dd>{value}</dd>
          </div>
        ))}
      </dl>
      <Connections title="Points to" connections={outgoing} />
      <Connections title="Pointed to by" connections={incoming} />
    </>
  );
}
