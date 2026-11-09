import { Info } from "lucide-react";
import { sanitizeDisplay } from "../../lib/sanitizeDisplay.js";
import Badge from "../ui/Badge.jsx";
import MockLabel from "../ui/MockLabel.jsx";

/** Shown wherever ML output appears. Training data is synthetic. */
export default function TrainingNotice({ trainingData, containsMock = false }) {
  return (
    <div className="notice">
      <Info size={16} aria-hidden="true" />
      <div>
        <p className="notice__badges">
          <Badge tone="accent">{sanitizeDisplay(trainingData?.label).toUpperCase() || "UNKNOWN"} TRAINING DATA</Badge>
          <MockLabel isMock={containsMock}>CONTAINS MOCK EVIDENCE</MockLabel>
        </p>
        {trainingData?.notice ? <p>{sanitizeDisplay(trainingData.notice)}</p> : null}
      </div>
    </div>
  );
}
