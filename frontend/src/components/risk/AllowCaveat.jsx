import { formatConfidence } from "../../lib/format.js";
import { FLIP_NOTICE, layerLabel } from "../../lib/policyDisplay.js";

function layersText(layers, note) {
  if (!Array.isArray(layers)) return note || "could not be loaded";
  return layers.length ? layers.map(layerLabel).join(", ") : "none";
}

/**
 * What an ALLOW does not cover. Rendered beside every ALLOW through DecisionDisplay.
 * layersNote replaces the list while it loads or when one list cannot apply.
 */
export default function AllowCaveat({ confidence, confidenceLabel, confidenceText, notEvaluatedLayers, layersNote }) {
  const value = confidenceText || formatConfidence(confidence);
  return (
    <div className="allow-caveat">
      <p>
        <strong>Confidence:</strong> {value}
        {confidenceLabel ? ` (${confidenceLabel})` : ""}
      </p>
      <p>
        <strong>Not evaluated:</strong> {layersText(notEvaluatedLayers, layersNote)}
      </p>
      <p>{FLIP_NOTICE}</p>
    </div>
  );
}
