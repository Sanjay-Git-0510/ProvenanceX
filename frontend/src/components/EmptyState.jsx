/** Placeholder shown where real data is not available yet. Never renders fake data. */
export default function EmptyState({ title, message }) {
  return (
    <section className="empty-state" aria-label={title}>
      <h1>{title}</h1>
      <p>{message}</p>
    </section>
  );
}
