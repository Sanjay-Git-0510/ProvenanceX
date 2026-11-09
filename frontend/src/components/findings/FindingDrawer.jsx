import { formatCvss, NOT_AVAILABLE } from "../../lib/format.js";
import { sanitizeDisplay } from "../../lib/sanitizeDisplay.js";
import MockLabel from "../ui/MockLabel.jsx";
import Modal from "../ui/Modal.jsx";
import FindingCategoryBadge, { SeverityBadge } from "./FindingCategoryBadge.jsx";

const clean = (value) => sanitizeDisplay(value) || NOT_AVAILABLE;

function Row({ label, children }) {
  return (
    <div className="dl__row">
      <dt>{label}</dt>
      <dd>{children}</dd>
    </div>
  );
}

/** Opens over the page, so the scan context is kept. Named fields only, never `details`. */
export default function FindingDrawer({ finding, onClose }) {
  if (!finding) return null;
  const { component, cvss } = finding;
  return (
    <Modal open onClose={onClose} title={clean(finding.identifier)}>
      <dl className="dl">
        <Row label="Kind">
          <FindingCategoryBadge category={finding.category} />
        </Row>
        <Row label="Title">{clean(finding.title)}</Row>
        <Row label="Severity">
          <SeverityBadge severity={finding.severity} />
        </Row>
        <Row label="Severity source">{clean(finding.severity_source)}</Row>
        <Row label="CVSS (advisory, not ProvenanceX risk)">{formatCvss(cvss?.score)}</Row>
        <Row label="CVSS vector">{clean(cvss?.vector)}</Row>
        <Row label="CVSS version and source">
          {clean(cvss?.version)} · {clean(cvss?.source)}
        </Row>
        <Row label="Aliases">
          {finding.aliases?.length ? finding.aliases.map(sanitizeDisplay).join(", ") : "None"}
        </Row>
        <Row label="Component">
          {component
            ? `${clean(component.name)} ${sanitizeDisplay(component.version)}`.trim()
            : "No linked component"}
        </Row>
        <Row label="Package URL">{clean(component?.purl)}</Row>
        <Row label="Source">
          {clean(finding.source)} <MockLabel source={finding.source} isMock={finding.is_mock} />
        </Row>
      </dl>
    </Modal>
  );
}
