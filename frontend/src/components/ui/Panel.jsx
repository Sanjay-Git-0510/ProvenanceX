import { useId } from "react";

/** A solid evidence surface. `level` (1 to 3) picks the elevation. */
export default function Panel({
  title,
  eyebrow,
  actions,
  level = 1,
  headingLevel = 2,
  className = "",
  children,
}) {
  const titleId = useId();
  const Heading = `h${headingLevel}`;
  const hasHead = title || eyebrow || actions;
  return (
    <section
      className={`panel panel--level-${level} ${className}`.trim()}
      aria-labelledby={title ? titleId : undefined}
    >
      {hasHead ? (
        <div className="panel__head">
          <div>
            {eyebrow ? <p className="panel__eyebrow">{eyebrow}</p> : null}
            {title ? <Heading id={titleId}>{title}</Heading> : null}
          </div>
          {actions ? <div>{actions}</div> : null}
        </div>
      ) : null}
      {children}
    </section>
  );
}
