import {
  CircleCheck,
  CircleDot,
  CircleQuestionMark,
  FlaskConical,
  Info,
  OctagonX,
  TriangleAlert,
} from "lucide-react";

const TONE_ICONS = {
  neutral: CircleDot,
  accent: Info,
  allow: CircleCheck,
  review: TriangleAlert,
  block: OctagonX,
  unknown: CircleQuestionMark,
  mock: FlaskConical,
};

/** A label with an icon. Every tone has a default icon, so status never relies on colour. */
export default function Badge({ tone = "neutral", icon, title, children }) {
  const Icon = icon || TONE_ICONS[tone] || TONE_ICONS.neutral;
  return (
    <span className={`badge badge--${tone}`} title={title}>
      <Icon size={14} aria-hidden="true" />
      {children}
    </span>
  );
}
