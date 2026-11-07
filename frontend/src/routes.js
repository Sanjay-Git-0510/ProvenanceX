// Single source of truth for navigation + routing. `phase` = CLAUDE.md phase that delivers the page's data.
import Dashboard from "./pages/Dashboard.jsx";
import NewScan from "./pages/NewScan.jsx";
import ScanDetails from "./pages/ScanDetails.jsx";
import Findings from "./pages/Findings.jsx";
import DependencyGraph from "./pages/DependencyGraph.jsx";
import ModelLineage from "./pages/ModelLineage.jsx";
import RiskAnalysis from "./pages/RiskAnalysis.jsx";
import BlockchainEvidence from "./pages/BlockchainEvidence.jsx";
import CiCd from "./pages/CiCd.jsx";
import Settings from "./pages/Settings.jsx";

export const routes = [
  { path: "/", label: "Dashboard", element: Dashboard, nav: true },
  { path: "/scans/new", label: "New Scan", element: NewScan, nav: true },
  { path: "/scans/:scanId", label: "Scan Details", element: ScanDetails, nav: false },
  { path: "/findings", label: "Findings", element: Findings, nav: true },
  { path: "/graph", label: "Dependency Graph", element: DependencyGraph, nav: true },
  { path: "/lineage", label: "Model Lineage", element: ModelLineage, nav: true },
  { path: "/risk", label: "Risk Analysis", element: RiskAnalysis, nav: true },
  { path: "/blockchain", label: "Blockchain Evidence", element: BlockchainEvidence, nav: true },
  { path: "/cicd", label: "CI/CD", element: CiCd, nav: true },
  { path: "/settings", label: "Settings", element: Settings, nav: true },
];
