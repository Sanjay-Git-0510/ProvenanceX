import { useParams } from "react-router-dom";
import EmptyState from "../components/EmptyState.jsx";

export default function ScanDetails() {
  const { scanId } = useParams();
  return (
    <EmptyState
      title="Scan Details"
      message={`Scan ${scanId}: scan records are not available yet. Real data arrives in Phase 8.`}
    />
  );
}
