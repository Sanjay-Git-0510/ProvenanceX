import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import App from "../App.jsx";
import { routes } from "../routes.js";

function jsonResponse(status, body) {
  return Promise.resolve({ ok: status < 400, status, json: () => Promise.resolve(body) });
}

const future = { v7_startTransition: true, v7_relativeSplatPath: true };

function renderAt(path) {
  return render(
    <MemoryRouter initialEntries={[path]} future={future}>
      <App />
    </MemoryRouter>,
  );
}

afterEach(() => {
  vi.unstubAllGlobals();
});

// Health calls answer with status; the list endpoint answers with an empty page.
function emptyApi(url) {
  if (url.includes("/scans")) {
    return jsonResponse(200, { page: { total: 0, limit: 20, offset: 0, has_more: false }, items: [] });
  }
  return jsonResponse(200, { status: "ok", version: "0.1.0" });
}

describe("routing", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn(emptyApi));
  });

  // Each test awaits the health badge so async state updates settle inside act().
  it.each(routes.map((r) => [r.path, r.label]))("renders %s", async (path, label) => {
    renderAt(path.replace(":scanId", "abc123"));
    expect(screen.getByRole("heading", { level: 1, name: label })).toBeInTheDocument();
    await screen.findByText(/API OK/);
  });

  it("renders NotFound for unknown paths", async () => {
    renderAt("/nope");
    expect(screen.getByRole("heading", { name: "Page not found" })).toBeInTheDocument();
    await screen.findByText(/API OK/);
  });

  it("shows nav links for every navigable page", async () => {
    renderAt("/");
    await screen.findByText(/API OK/);
    const nav = screen.getByRole("navigation", { name: "Main" });
    routes.filter((r) => r.nav).forEach((r) => {
      expect(nav).toHaveTextContent(r.label);
    });
  });
});

describe("health badge", () => {
  it("shows OK when API and DB are healthy", async () => {
    vi.stubGlobal("fetch", vi.fn(emptyApi));
    renderAt("/");
    expect(await screen.findByText(/API OK · DB OK/)).toBeInTheDocument();
  });

  it("shows DB UNAVAILABLE when readiness fails", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn((url) =>
        url.endsWith("/health/ready")
          ? jsonResponse(503, { error: { code: "database_unavailable", message: "Database is not reachable" } })
          : jsonResponse(200, { status: "ok", version: "0.1.0" }),
      ),
    );
    renderAt("/");
    expect(await screen.findByText(/DB UNAVAILABLE/)).toBeInTheDocument();
  });

  it("shows API UNREACHABLE when fetch fails", async () => {
    vi.stubGlobal("fetch", vi.fn(() => Promise.reject(new TypeError("Failed to fetch"))));
    renderAt("/");
    expect(await screen.findByText("API UNREACHABLE")).toBeInTheDocument();
  });
});

describe("application shell", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn(emptyApi));
  });

  it("offers a skip link to the main region", async () => {
    renderAt("/");
    await screen.findByText(/API OK/);
    expect(screen.getByRole("link", { name: "Skip to content" })).toHaveAttribute("href", "#main");
    expect(screen.getByRole("main")).toHaveAttribute("id", "main");
  });

  it("toggles the navigation menu and closes it on Escape", async () => {
    renderAt("/");
    await screen.findByText(/API OK/);
    const menu = screen.getByRole("button", { name: "Menu" });
    expect(menu).toHaveAttribute("aria-expanded", "false");
    fireEvent.click(menu);
    expect(screen.getByRole("button", { name: "Close" })).toHaveAttribute("aria-expanded", "true");
    expect(screen.getByRole("navigation", { name: "Main" })).toHaveClass("rail--open");
    fireEvent.keyDown(document, { key: "Escape" });
    expect(screen.getByRole("button", { name: "Menu" })).toHaveAttribute("aria-expanded", "false");
  });

  it("closes the navigation menu after moving to another page", async () => {
    renderAt("/");
    await screen.findByText(/API OK/);
    fireEvent.click(screen.getByRole("button", { name: "Menu" }));
    fireEvent.click(screen.getByRole("link", { name: "Findings" }));
    expect(screen.getByRole("heading", { level: 1, name: "Findings" })).toBeInTheDocument();
    await screen.findByLabelText(/^Scan/);
    expect(screen.getByRole("navigation", { name: "Main" })).not.toHaveClass("rail--open");
  });

  it("marks the current page in the navigation", async () => {
    renderAt("/findings");
    await screen.findByText(/API OK/);
    expect(screen.getByRole("link", { name: "Findings" })).toHaveAttribute("aria-current", "page");
  });

  it("shows the version in lowercase text", async () => {
    renderAt("/");
    await screen.findByText(/API OK/);
    expect(screen.getByRole("status", { name: "" })).toHaveTextContent("v0.1.0");
  });

  it("gives every health state an icon as well as text", async () => {
    renderAt("/");
    const label = await screen.findByText(/API OK/);
    expect(label.parentElement.querySelector('svg[aria-hidden="true"]')).not.toBeNull();
  });

  it("redacts a host path from the health error title", async () => {
    vi.stubGlobal("fetch", vi.fn(() => Promise.reject(new TypeError("failed at /home/victim/x"))));
    renderAt("/");
    const label = await screen.findByText("API UNREACHABLE");
    expect(label.parentElement.getAttribute("title")).not.toContain("/home/victim");
  });
});
