import { Brain, Database, Layers, Package } from "lucide-react";
import { WORKFLOWS } from "../../lib/scanValidation.js";

const ICONS = { software: Package, model: Brain, dataset: Database, lora: Layers };

/** The four scan workflows as one labelled radio group. Icons are decorative. */
export default function ScanTypePicker({ value, onChange }) {
  return (
    <fieldset className="choice">
      <legend className="field__label">What are you scanning?</legend>
      <div className="type-picker">
        {Object.entries(WORKFLOWS).map(([key, spec]) => {
          const Icon = ICONS[key];
          return (
            <label key={key} className="type-picker__option">
              <input
                type="radio"
                name="workflow"
                value={key}
                checked={value === key}
                onChange={() => onChange(key)}
              />
              <Icon size={18} aria-hidden="true" />
              <span className="type-picker__label">{spec.label}</span>
              <span className="type-picker__host">{spec.hostName} or ZIP</span>
            </label>
          );
        })}
      </div>
    </fieldset>
  );
}
