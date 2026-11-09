import { CircleQuestionMark } from "lucide-react";
import EmptyState from "../components/EmptyState.jsx";
import Button from "../components/ui/Button.jsx";

export default function NotFound() {
  return (
    <EmptyState
      title="Page not found"
      icon={CircleQuestionMark}
      action={
        <Button to="/" variant="secondary">
          Back to Dashboard
        </Button>
      }
    />
  );
}
