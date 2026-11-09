import { Inbox } from "lucide-react";

/** Shown where there is no real data to display. Never renders fake data. */
export default function EmptyState({ title, message, headingLevel = 1, icon: Icon = Inbox, action }) {
  const Heading = `h${headingLevel}`;
  return (
    <section className="state" aria-label={title}>
      <Icon className="state__icon" size={20} aria-hidden="true" />
      <Heading>{title}</Heading>
      {message ? <p className="state__message">{message}</p> : null}
      {action ? <div className="state__action">{action}</div> : null}
    </section>
  );
}
