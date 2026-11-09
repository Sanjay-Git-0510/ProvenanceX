import Badge from "./Badge.jsx";

/** Labels mock evidence. Renders nothing for real data. */
export default function MockLabel({ source, isMock = false, children = "MOCK DATA" }) {
  if (source !== "mock" && isMock !== true) return null;
  return <Badge tone="mock">{children}</Badge>;
}
