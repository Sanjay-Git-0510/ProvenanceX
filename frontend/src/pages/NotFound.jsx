import { Link } from "react-router-dom";

export default function NotFound() {
  return (
    <section className="empty-state">
      <h1>Page not found</h1>
      <p>
        <Link to="/">Back to Dashboard</Link>
      </p>
    </section>
  );
}
