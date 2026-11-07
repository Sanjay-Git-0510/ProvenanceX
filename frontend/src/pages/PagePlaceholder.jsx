import EmptyState from "../components/EmptyState.jsx";

export default function PagePlaceholder({ title, phase }) {
  return <EmptyState title={title} message={`Not implemented yet. Real data arrives in Phase ${phase}.`} />;
}
