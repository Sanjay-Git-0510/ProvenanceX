import { Link } from "react-router-dom";
import { evidenceLabel, evidenceRoute } from "../../lib/evidenceLinks.js";

/** Links a risk result back to its evidence. Unrecognized links are left out. */
export default function EvidenceLinkList({ links, artifactType }) {
  const items = (links || [])
    .map((link) => ({ label: evidenceLabel(link.rel), to: evidenceRoute(link.href, { artifactType }) }))
    .filter((item) => item.to);
  if (items.length === 0) return null;
  return (
    <ul className="link-list">
      {items.map((item) => (
        <li key={item.to}>
          <Link to={item.to}>{item.label}</Link>
        </li>
      ))}
    </ul>
  );
}
