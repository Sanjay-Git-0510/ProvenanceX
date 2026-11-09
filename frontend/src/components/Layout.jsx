import { useEffect, useState } from "react";
import { Link, Outlet, useLocation } from "react-router-dom";
import { FingerprintPattern, Menu, ScanSearch, X } from "lucide-react";
import Nav from "./Nav.jsx";
import StatusBadge from "./StatusBadge.jsx";
import Button from "./ui/Button.jsx";

const NAV_ID = "main-navigation";

export default function Layout() {
  const [menuOpen, setMenuOpen] = useState(false);
  const { pathname } = useLocation();

  useEffect(() => {
    setMenuOpen(false);
  }, [pathname]);

  useEffect(() => {
    if (!menuOpen) return undefined;
    function onKeyDown(event) {
      if (event.key === "Escape") setMenuOpen(false);
    }
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [menuOpen]);

  const MenuIcon = menuOpen ? X : Menu;

  return (
    <div className="app">
      <a className="skip-link" href="#main">
        Skip to content
      </a>
      <header className="app-header glass">
        <button
          type="button"
          className="chip glass app-header__menu"
          aria-expanded={menuOpen}
          aria-controls={NAV_ID}
          onClick={() => setMenuOpen((open) => !open)}
        >
          <MenuIcon size={16} aria-hidden="true" />
          <span className="hide-below-sm">{menuOpen ? "Close" : "Menu"}</span>
        </button>
        <Link className="app-header__brand" to="/">
          <FingerprintPattern className="app-header__mark" size={20} aria-hidden="true" />
          <span className="hide-below-xs">ProvenanceX</span>
        </Link>
        <div className="app-header__end">
          <StatusBadge />
          <Button className="app-header__action" to="/scans/new" icon={ScanSearch}>
            Start scan
          </Button>
        </div>
      </header>
      <div className="app-body">
        <Nav id={NAV_ID} open={menuOpen} />
        <main className="app-main" id="main" tabIndex={-1}>
          <Outlet />
        </main>
      </div>
    </div>
  );
}
