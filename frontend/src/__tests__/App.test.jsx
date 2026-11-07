import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import App from "../App.jsx";
import { routes } from "../routes.js";
import { ApiError, request } from "../services/api.js";

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

describe("routing", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn(() => jsonResponse(200, { status: "ok", version: "0.1.0" })));
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
    vi.stubGlobal("fetch", vi.fn(() => jsonResponse(200, { status: "ok", version: "0.1.0" })));
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

describe("api service", () => {
  it("parses the structured error envelope", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(() => jsonResponse(422, { error: { code: "validation_error", message: "bad", details: [1] } })),
    );
    const err = await request("/x").catch((e) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(err).toMatchObject({ code: "validation_error", message: "bad", status: 422, details: [1] });
  });
});
