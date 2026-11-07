import { NavLink } from "react-router-dom";
import { routes } from "../routes.js";

export default function Nav() {
  return (
    <nav className="nav" aria-label="Main">
      <ul>
        {routes
          .filter((r) => r.nav)
          .map((r) => (
            <li key={r.path}>
              <NavLink to={r.path} end={r.path === "/"}>
                {r.label}
              </NavLink>
            </li>
          ))}
      </ul>
    </nav>
  );
}
