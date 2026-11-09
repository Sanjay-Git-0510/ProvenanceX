// Single source of truth for navigation and routing.
import {
  Blocks,
  Gauge,
  GitFork,
  LayoutDashboard,
  ListChecks,
  Network,
  ScanSearch,
  Settings as SettingsIcon,
  Workflow,
} from "lucide-react";
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

const OVERVIEW = "Overview";
const EVIDENCE = "Evidence";
const OPERATIONS = "Operations";

export const routes = [
  { path: "/", label: "Dashboard", element: Dashboard, nav: true, group: OVERVIEW, icon: LayoutDashboard },
  { path: "/scans/new", label: "New Scan", element: NewScan, nav: true, group: OVERVIEW, icon: ScanSearch },
  { path: "/scans/:scanId", label: "Scan Details", element: ScanDetails, nav: false },
  { path: "/findings", label: "Findings", element: Findings, nav: true, group: EVIDENCE, icon: ListChecks },
  { path: "/graph", label: "Dependency Graph", element: DependencyGraph, nav: true, group: EVIDENCE, icon: Network },
  { path: "/lineage", label: "Model Lineage", element: ModelLineage, nav: true, group: EVIDENCE, icon: GitFork },
  { path: "/risk", label: "Risk Analysis", element: RiskAnalysis, nav: true, group: EVIDENCE, icon: Gauge },
  { path: "/blockchain", label: "Blockchain Evidence", element: BlockchainEvidence, nav: true, group: EVIDENCE, icon: Blocks },
  { path: "/cicd", label: "CI/CD", element: CiCd, nav: true, group: OPERATIONS, icon: Workflow },
  { path: "/settings", label: "Settings", element: Settings, nav: true, group: OPERATIONS, icon: SettingsIcon },
];

export const navGroups = [OVERVIEW, EVIDENCE, OPERATIONS].map((name) => ({
  name,
  items: routes.filter((route) => route.nav && route.group === name),
}));
