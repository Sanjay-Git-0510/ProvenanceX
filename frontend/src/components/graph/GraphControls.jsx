import { Minus, Plus } from "lucide-react";
import { humanize } from "../../lib/format.js";
import Button from "../ui/Button.jsx";

export const ZOOM = { min: 0.5, max: 2, step: 0.25 };

function FilterSelect({ label, value, options, allLabel, onChange }) {
  return (
    <label className="field">
      <span className="field__label">{label}</span>
      <select className="field__control" value={value} onChange={(event) => onChange(event.target.value)}>
        <option value="">{allLabel}</option>
        {options.map((option) => (
          <option key={option} value={option}>
            {humanize(option)}
          </option>
        ))}
      </select>
    </label>
  );
}

/** Filters for the drawing and tables, plus zoom for the drawing. */
export default function GraphControls({ filters, options, onChange, zoom, onZoom, showZoom }) {
  return (
    <div className="toolbar">
      <div className="filter-row">
        <label className="field">
          <span className="field__label">Search nodes</span>
          <input
            className="field__control"
            type="search"
            value={filters.search}
            onChange={(event) => onChange({ search: event.target.value })}
          />
        </label>
        <FilterSelect
          label="Node type"
          value={filters.nodeType}
          options={options.nodeTypes}
          allLabel="All types"
          onChange={(nodeType) => onChange({ nodeType })}
        />
        <FilterSelect
          label="Relation"
          value={filters.relation}
          options={options.relations}
          allLabel="All relations"
          onChange={(relation) => onChange({ relation })}
        />
      </div>
      {showZoom ? (
        <div className="graph-zoom">
          <Button
            variant="secondary"
            size="small"
            icon={Minus}
            aria-label="Zoom out"
            disabled={zoom <= ZOOM.min}
            onClick={() => onZoom(zoom - ZOOM.step)}
          />
          <output aria-label="Zoom level">{Math.round(zoom * 100)}%</output>
          <Button
            variant="secondary"
            size="small"
            icon={Plus}
            aria-label="Zoom in"
            disabled={zoom >= ZOOM.max}
            onClick={() => onZoom(zoom + ZOOM.step)}
          />
        </div>
      ) : null}
    </div>
  );
}
