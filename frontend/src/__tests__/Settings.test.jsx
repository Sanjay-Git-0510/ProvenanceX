import { screen } from "@testing-library/react";
import Settings from "../pages/Settings.jsx";
import { calledUrls, mockApi, renderPage } from "../test/helpers.jsx";

afterEach(() => vi.unstubAllGlobals());

const live = [/\/health$/, { status: "ok", version: "0.1.0" }];
const open = () => renderPage(<Settings />, { path: "/settings", route: "/settings" });

describe("Settings", () => {
  it("shows health and version only", async () => {
    const fetchMock = mockApi([live, [/\/health\/ready$/, { status: "ready", db: "ok", version: "0.1.0" }]]);
    const { container } = open();
    expect(await screen.findByText("Ready")).toBeInTheDocument();
    expect(screen.getByText("0.1.0")).toBeInTheDocument();
    expect(container).not.toHaveTextContent(/weight|threshold/i);
    expect(container.querySelector("input, select, textarea")).toBeNull();
    expect(screen.queryByRole("button")).toBeNull();
    expect(calledUrls(fetchMock).every((url) => url.includes("/health"))).toBe(true);
  });

  it("reports a database that is not ready", async () => {
    mockApi([live, [/\/health\/ready$/, { error: { code: "database_unavailable", message: "Database is not reachable" } }, 503]]);
    open();
    expect(await screen.findByText("Not ready")).toBeInTheDocument();
    expect(screen.getByText("Reachable")).toBeInTheDocument();
  });

  it("does not claim a database state when the API is down", async () => {
    mockApi([[/\/health$/, { error: { code: "down", message: "API down" } }, 500]]);
    open();
    expect(await screen.findByText("Unreachable")).toBeInTheDocument();
    expect(screen.getByText(/Unknown: the API did not answer/)).toBeInTheDocument();
    expect(screen.getByText("Not available")).toBeInTheDocument();
  });
});
