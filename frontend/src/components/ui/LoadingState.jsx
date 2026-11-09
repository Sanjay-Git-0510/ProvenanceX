import { Clock } from "lucide-react";

/** Static on purpose: the design allows no decorative looping animation. */
export default function LoadingState({ label = "Loading", lines = 3 }) {
  return (
    <div className="state" role="status">
      <Clock className="state__icon" size={20} aria-hidden="true" />
      <p className="state__message">{label}</p>
      <div className="skeleton" aria-hidden="true">
        {Array.from({ length: lines }, (_, index) => (
          <span className="skeleton__line" key={index} />
        ))}
      </div>
    </div>
  );
}
