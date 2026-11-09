import GraphPage from "../components/graph/GraphView.jsx";

export default function DependencyGraph() {
  return (
    <GraphPage
      kind="dependency"
      title="Dependency Graph"
      lede="Packages found in a software scan and how they depend on each other. Every node and edge is also listed in the tables."
    />
  );
}
