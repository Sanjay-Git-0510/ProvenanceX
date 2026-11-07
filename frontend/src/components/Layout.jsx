import { Outlet } from "react-router-dom";
import Nav from "./Nav.jsx";
import StatusBadge from "./StatusBadge.jsx";

export default function Layout() {
  return (
    <div className="layout">
      <header className="topbar">
        <span className="brand">ProvenanceX</span>
        <StatusBadge />
      </header>
      <Nav />
      <main className="content">
        <Outlet />
      </main>
    </div>
  );
}
