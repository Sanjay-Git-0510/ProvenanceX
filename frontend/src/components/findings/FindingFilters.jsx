import { categoryLabel, CATEGORY_NAMES } from "./FindingCategoryBadge.jsx";

export const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"];
export const SOURCES = ["osv", "provenancex", "sandbox", "mock"];

function Filter({ label, name, value, options, onChange }) {
  return (
    <label className="field">
      <span className="field__label">{label}</span>
      <select className="field__control" value={value || ""} onChange={(event) => onChange(name, event.target.value)}>
        <option value="">All</option>
        {options.map(([optionValue, optionLabel]) => (
          <option key={optionValue} value={optionValue}>
            {optionLabel}
          </option>
        ))}
      </select>
    </label>
  );
}

export default function FindingFilters({ filters, onChange }) {
  return (
    <form className="filter-row" aria-label="Finding filters" onSubmit={(event) => event.preventDefault()}>
      <Filter
        label="Kind"
        name="category"
        value={filters.category}
        options={CATEGORY_NAMES.map((name) => [name, categoryLabel(name)])}
        onChange={onChange}
      />
      <Filter
        label="Severity"
        name="severity"
        value={filters.severity}
        options={SEVERITIES.map((name) => [name, name])}
        onChange={onChange}
      />
      <Filter
        label="Source"
        name="source"
        value={filters.source}
        options={SOURCES.map((name) => [name, name])}
        onChange={onChange}
      />
    </form>
  );
}
