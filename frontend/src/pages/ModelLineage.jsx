import GraphPage from "../components/graph/GraphView.jsx";

export default function ModelLineage() {
  return (
    <GraphPage
      kind="lineage"
      title="Model Lineage"
      lede="Base models, adapters, datasets and files declared by a model scan. Declared relations come from the artifact itself and are not independently confirmed."
    />
  );
}
