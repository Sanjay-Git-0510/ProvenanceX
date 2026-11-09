import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import Findings from "../pages/Findings.jsx";
import {
  CANARY,
  HOST_PATH,
  SCAN_ID,
  calledUrls,
  finding,
  findingsPage,
  mockApi,
  renderPage,
  scanList,
  scanRow,
} from "../test/helpers.jsx";

afterEach(() => vi.unstubAllGlobals());

const LIST = [/\/scans\?limit=100/, scanList([scanRow()])];
const open = (query = `?scan=${SCAN_ID}`) => renderPage(<Findings />, { path: `/findings${query}`, route: "/findings" });
const location = () => screen.getByTestId("location").textContent;

describe("Findings", () => {
  it("asks for a scan when none is selected and requests no findings", async () => {
    const fetchMock = mockApi([LIST]);
    open("");
    expect(await screen.findByRole("heading", { name: "Choose a scan" })).toBeInTheDocument();
    expect(calledUrls(fetchMock).some((url) => url.includes("/findings"))).toBe(false);
  });

  it("selects a scan through the picker", async () => {
    mockApi([LIST, [/\/findings/, findingsPage([finding()])]]);
    open("");
    fireEvent.change(await screen.findByLabelText(/^Scan/), { target: { value: SCAN_ID } });
    await waitFor(() => expect(location()).toBe(`/findings?scan=${SCAN_ID}`));
    expect(await screen.findByText("GHSA-aaaa-bbbb-cccc")).toBeInTheDocument();
  });

  it("rejects a malformed scan id", async () => {
    const fetchMock = mockApi([LIST]);
    open("?scan=../x");
    expect(await screen.findByRole("heading", { name: "Not a valid scan ID" })).toBeInTheDocument();
    expect(calledUrls(fetchMock).some((url) => url.includes("/findings"))).toBe(false);
  });

  it("sends filters to the API and keeps them in the URL", async () => {
    const fetchMock = mockApi([LIST, [/\/findings/, findingsPage([finding()])]]);
    open();
    fireEvent.change(await screen.findByLabelText("Severity"), { target: { value: "HIGH" } });
    await waitFor(() =>
      expect(calledUrls(fetchMock)).toContain(`/api/v1/scans/${SCAN_ID}/findings?severity=HIGH&limit=50&offset=0`),
    );
    expect(location()).toContain("severity=HIGH");
  });

  it("resets to the first page when a filter changes", async () => {
    mockApi([LIST, [/\/findings/, findingsPage([finding()], { total: 200, offset: 50 })]]);
    open(`?scan=${SCAN_ID}&offset=50`);
    fireEvent.change(await screen.findByLabelText("Kind"), { target: { value: "static" } });
    await waitFor(() => expect(location()).toContain("category=static"));
    expect(location()).not.toContain("offset");
  });

  it("ignores unrecognized filters from the URL", async () => {
    const fetchMock = mockApi([LIST, [/\/findings/, findingsPage([])]]);
    open(`?scan=${SCAN_ID}&category=evil&severity=x&source=y&offset=-5`);
    await waitFor(() =>
      expect(calledUrls(fetchMock)).toContain(`/api/v1/scans/${SCAN_ID}/findings?limit=50&offset=0`),
    );
  });

  it("pages through findings", async () => {
    const fetchMock = mockApi([LIST, [/\/findings/, findingsPage([finding()], { total: 120 })]]);
    open();
    fireEvent.click(await screen.findByRole("button", { name: "Next" }));
    await waitFor(() => expect(calledUrls(fetchMock)).toContain(`/api/v1/scans/${SCAN_ID}/findings?limit=50&offset=50`));
    expect(await screen.findByText("Showing 1 to 50 of 120")).toBeInTheDocument();
  });

  it("shows known vulnerabilities and suspicious signals differently", async () => {
    mockApi([
      LIST,
      [/\/findings/, findingsPage([finding(), finding({ finding_id: "f2", category: "behavioral", identifier: "BEHAV-1", cvss: { score: null } })])],
    ]);
    open();
    const known = await screen.findByText("Known vulnerability", { selector: ".badge" });
    const suspicious = screen.getByText("Suspicious: behavioral", { selector: ".badge" });
    expect(known.className).not.toBe(suspicious.className);
  });

  it("keeps CVSS labeled as advisory and null CVSS as words", async () => {
    mockApi([LIST, [/\/findings/, findingsPage([finding({ cvss: { score: null } })])]]);
    open();
    expect(await screen.findByRole("columnheader", { name: "CVSS (advisory)" })).toBeInTheDocument();
    expect(screen.getByText("No CVSS score")).toBeInTheDocument();
  });

  it("labels mock findings", async () => {
    mockApi([LIST, [/\/findings/, findingsPage([finding({ source: "mock", is_mock: true })], { contains_mock: true })]]);
    open();
    expect(await screen.findByText("THIS SCAN CONTAINS MOCK FINDINGS")).toBeInTheDocument();
    expect(screen.getByText("MOCK DATA")).toBeInTheDocument();
  });

  it("shows named fields in the drawer, never details", async () => {
    mockApi([LIST, [/\/findings/, findingsPage([finding()])]]);
    open();
    fireEvent.click(await screen.findByRole("button", { name: /Open details/ }));
    const dialog = screen.getByRole("dialog", { name: "GHSA-aaaa-bbbb-cccc" });
    expect(dialog).toHaveTextContent("CVE-2026-0001");
    expect(dialog).toHaveTextContent("pkg:pypi/requests@2.32.3");
    expect(dialog).toHaveTextContent("CVSS (advisory, not ProvenanceX risk)");
    expect(dialog).not.toHaveTextContent(CANARY);
    expect(document.body).not.toHaveTextContent(CANARY);
  });

  it("redacts artifact text everywhere in the row and drawer", async () => {
    mockApi([
      LIST,
      [/\/findings/, findingsPage([finding({ identifier: HOST_PATH, title: HOST_PATH, aliases: [HOST_PATH], component: { name: HOST_PATH, purl: HOST_PATH } })])],
    ]);
    open();
    fireEvent.click(await screen.findByRole("button", { name: /Open details/ }));
    expect(document.body).not.toHaveTextContent(HOST_PATH);
  });

  it("renders artifact markup as text", async () => {
    mockApi([LIST, [/\/findings/, findingsPage([finding({ title: "<img src=x onerror=alert(1)>" })])]]);
    const { container } = open();
    await screen.findByText("<img src=x onerror=alert(1)>");
    expect(container.querySelector("img")).toBeNull();
  });

  it("separates no findings from filters and from incomplete stages", async () => {
    mockApi([LIST, [/\/findings/, findingsPage([], { stages: { vulnerability: { status: "completed" } } })]]);
    const first = open(`?scan=${SCAN_ID}&severity=LOW`);
    expect(await screen.findByText("No findings match these filters.")).toBeInTheDocument();
    first.unmount();
    mockApi([LIST, [/\/findings/, findingsPage([], { stages: { vulnerability: { status: "error" } } })]]);
    open();
    expect(await screen.findByRole("heading", { name: /evidence is incomplete/ })).toBeInTheDocument();
  });

  it("does not show raw stage fields", async () => {
    mockApi([LIST, [/\/findings/, findingsPage([], { stages: { vulnerability: { status: "error", raw_blob: CANARY } } })]]);
    const { container } = open();
    await screen.findByRole("heading", { name: /evidence is incomplete/ });
    expect(container).not.toHaveTextContent(CANARY);
  });

  it("shows loading, then an error with retry", async () => {
    let fail = true;
    mockApi([LIST]);
    vi.stubGlobal(
      "fetch",
      vi.fn((url) => {
        if (url.includes("limit=100")) return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(scanList([scanRow()])) });
        return Promise.resolve(
          fail
            ? { ok: false, status: 503, json: () => Promise.resolve({ error: { code: "down", message: "Findings down" } }) }
            : { ok: true, status: 200, json: () => Promise.resolve(findingsPage([finding()])) },
        );
      }),
    );
    open();
    expect(screen.getByText("Loading findings")).toBeInTheDocument();
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Findings down");
    fail = false;
    fireEvent.click(within(alert).getByRole("button", { name: "Retry" }));
    expect(await screen.findByText("GHSA-aaaa-bbbb-cccc")).toBeInTheDocument();
  });

  it("reports a picker failure", async () => {
    mockApi([[/\/scans\?limit=100/, { error: { code: "down", message: "List down" } }, 503]]);
    open("");
    expect(await screen.findByText("List down")).toBeInTheDocument();
  });

  it("shows an empty picker", async () => {
    mockApi([[/\/scans\?limit=100/, scanList([])]]);
    open("");
    const select = await screen.findByLabelText(/^Scan/);
    expect(within(select).getAllByRole("option")).toHaveLength(1);
  });
});
