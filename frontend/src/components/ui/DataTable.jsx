import { NOT_AVAILABLE } from "../../lib/format.js";
import EmptyState from "../EmptyState.jsx";

function cellValue(column, row) {
  const value = column.render ? column.render(row) : row[column.key];
  return value === null || value === undefined ? NOT_AVAILABLE : value;
}

/**
 * A semantic table on a solid surface.
 * columns: [{ key, header, render?, align?: "end", mono?: true }]. `empty` replaces the default
 * empty message, which matters when an empty list does not mean "nothing found".
 */
export default function DataTable({ caption, columns, rows, getRowKey, empty, captionHidden = false }) {
  if (!rows || rows.length === 0) {
    return empty || <EmptyState title="No rows" message={`${caption}: nothing to show.`} headingLevel={3} />;
  }
  return (
    <div className="table-region" role="region" aria-label={caption} tabIndex={0}>
      <table className="table">
        <caption className={captionHidden ? "sr-only" : undefined}>{caption}</caption>
        <thead>
          <tr>
            {columns.map((column) => (
              <th key={column.key} scope="col" className={column.align === "end" ? "is-end" : undefined}>
                {column.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={getRowKey(row)}>
              {columns.map((column) => {
                const classes = [column.align === "end" && "is-end", column.mono && "is-mono"]
                  .filter(Boolean)
                  .join(" ");
                return (
                  <td key={column.key} className={classes || undefined}>
                    {cellValue(column, row)}
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
