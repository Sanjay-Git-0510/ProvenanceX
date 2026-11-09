import { NavLink } from "react-router-dom";
import { navGroups } from "../routes.js";

export default function Nav({ id, open = false }) {
  return (
    <nav id={id} className={`rail${open ? " rail--open" : ""}`} aria-label="Main">
      {navGroups.map((group) => (
        <div className="rail__group" key={group.name}>
          <p className="rail__heading">{group.name}</p>
          <ul>
            {group.items.map(({ path, label, icon: Icon }) => (
              <li key={path}>
                <NavLink className="rail__link" to={path} end={path === "/"}>
                  <Icon size={16} aria-hidden="true" />
                  {label}
                </NavLink>
              </li>
            ))}
          </ul>
        </div>
      ))}
    </nav>
  );
}
