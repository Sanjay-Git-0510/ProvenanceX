import DecisionBadge from "../ui/DecisionBadge.jsx";
import AllowCaveat from "./AllowCaveat.jsx";

/** The only place a decision badge is rendered, so an ALLOW always carries its caveat. */
export default function DecisionDisplay({ decision, ...caveat }) {
  if (decision !== "ALLOW") return <DecisionBadge decision={decision} />;
  return (
    <div className="decision-display" data-allow="true">
      <DecisionBadge decision="ALLOW" />
      <AllowCaveat {...caveat} />
    </div>
  );
}
