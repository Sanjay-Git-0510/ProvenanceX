import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import NewScan from "../pages/NewScan.jsx";
import { SCAN_ID, mockApi, renderPage } from "../test/helpers.jsx";

const CREATED = { scan_id: SCAN_ID, artifact_id: SCAN_ID, status: "queued" };
const DONE = [new RegExp(`/scans/${SCAN_ID}$`), { scan_id: SCAN_ID, status: "completed", stages: null, error: null }];
const GITHUB = "https://github.com/pallets/flask";

afterEach(() => vi.unstubAllGlobals());

const render = () => renderPage(<NewScan />, { path: "/scans/new", route: "/scans/new" });
const urlField = () => screen.getByLabelText("Repository URL (https)");
const submit = () => fireEvent.click(screen.getByRole("button", { name: "Start scan" }));
const location = () => screen.getByTestId("location").textContent;

describe("New Scan", () => {
  it("starts a software scan and opens it", async () => {
    const fetchMock = mockApi([[/\/scans\/software/, CREATED], DONE]);
    render();
    fireEvent.change(urlField(), { target: { value: GITHUB } });
    fireEvent.change(screen.getByLabelText(/^Revision/), { target: { value: "main" } });
    submit();
    await waitFor(() => expect(location()).toBe(`/scans/${SCAN_ID}`));
    const [url, options] = fetchMock.mock.calls[0];
    expect(url).toBe("/api/v1/scans/software");
    expect(Object.fromEntries(options.body)).toEqual({ source_url: GITHUB, revision: "main" });
  });

  it("starts a model scan with its artifact type", async () => {
    const fetchMock = mockApi([[/\/scans\/model/, CREATED], DONE]);
    render();
    fireEvent.click(screen.getByLabelText("AI / ML"));
    fireEvent.change(screen.getByLabelText("Model artifact type"), { target: { value: "lora" } });
    fireEvent.change(urlField(), { target: { value: "https://huggingface.co/a/b" } });
    submit();
    await waitFor(() => expect(location()).toBe(`/scans/${SCAN_ID}`));
    expect(fetchMock.mock.calls[0][1].body.get("artifact_type")).toBe("lora");
  });

  it("uploads a ZIP", async () => {
    const fetchMock = mockApi([[/\/scans\/software/, CREATED], DONE]);
    render();
    fireEvent.click(screen.getByLabelText("Upload ZIP"));
    const file = new File(["zip"], "project.ZIP");
    fireEvent.change(screen.getByLabelText("ZIP file"), { target: { files: [file] } });
    submit();
    await waitFor(() => expect(location()).toBe(`/scans/${SCAN_ID}`));
    expect(fetchMock.mock.calls[0][1].body.get("file").name).toBe("project.ZIP");
  });

  it.each([
    "http://github.com/a/b",
    "https://evil.test/a/b",
    "https://huggingface.co/a/b",
    "https://user:pw@github.com/a/b",
    "https://github.com:8443/a/b",
    "file:///etc/passwd",
    "not a url",
    "",
  ])("refuses %s for a software scan without calling the API", (value) => {
    const fetchMock = mockApi([]);
    render();
    fireEvent.change(urlField(), { target: { value } });
    submit();
    expect(screen.getByRole("alert")).toHaveTextContent("GitHub");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("refuses a non-ZIP upload and a missing file", () => {
    const fetchMock = mockApi([]);
    render();
    fireEvent.click(screen.getByLabelText("Upload ZIP"));
    submit();
    expect(screen.getByRole("alert")).toHaveTextContent("Choose a ZIP");
    fireEvent.change(screen.getByLabelText("ZIP file"), { target: { files: [new File(["x"], "a.tar")] } });
    submit();
    expect(screen.getByRole("alert")).toHaveTextContent("Only .zip");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("shows a structured API error, redacted, and allows another try", async () => {
    mockApi([[/\/scans\/software/, { error: { code: "url_rejected", message: "Rejected at /home/victim/x", details: { x: "PX_SECRET" } } }, 400]]);
    render();
    fireEvent.change(urlField(), { target: { value: GITHUB } });
    submit();
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("The scan was not started");
    expect(alert).toHaveTextContent("url_rejected");
    expect(alert).not.toHaveTextContent("/home/victim");
    expect(alert).not.toHaveTextContent("PX_SECRET");
    expect(screen.getByRole("button", { name: "Start scan" })).toBeEnabled();
    expect(location()).toBe("/scans/new");
  });

  it("does not navigate on an invalid scan id", async () => {
    mockApi([[/\/scans\/software/, { scan_id: "../evil" }]]);
    render();
    fireEvent.change(urlField(), { target: { value: GITHUB } });
    submit();
    expect(await screen.findByRole("alert")).toHaveTextContent("invalid scan ID");
    expect(location()).toBe("/scans/new");
  });

  it("locks the page with a progress dialog, then opens the result when the scan completes", async () => {
    mockApi([[/\/scans\/software/, CREATED], [new RegExp(`/scans/${SCAN_ID}$`), { scan_id: SCAN_ID, status: "running", stages: null, error: null }]]);
    render();
    fireEvent.change(urlField(), { target: { value: GITHUB } });
    submit();
    const dialog = await screen.findByRole("dialog");
    expect(dialog).toHaveTextContent("github.com/pallets/flask");
    expect(dialog).toHaveTextContent("Software");
    expect(await within(dialog).findByText("Running")).toBeInTheDocument();
    expect(within(dialog).getByText(/^00:0\d$/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Starting scan", hidden: true })).toBeDisabled();
    expect(location()).toBe("/scans/new");
  });

  it("keeps the dialog open on a failed scan and retries with a new scan", async () => {
    let created = 0;
    const fetchMock = mockApi([
      [/\/scans\/software/, () => { created += 1; return CREATED; }],
      [new RegExp(`/scans/${SCAN_ID}$`), { scan_id: SCAN_ID, status: "failed", error: { code: "x", message: "Clone failed" } }],
    ]);
    render();
    fireEvent.change(urlField(), { target: { value: GITHUB } });
    submit();
    const dialog = await screen.findByRole("dialog");
    expect(await within(dialog).findByRole("alert")).toHaveTextContent("Clone failed");
    expect(within(dialog).getByText("Failed")).toBeInTheDocument();
    fireEvent.click(within(dialog).getByRole("button", { name: "Retry" }));
    await waitFor(() => expect(created).toBe(2));
    expect(fetchMock.mock.calls.filter(([, o]) => o?.method === "POST")).toHaveLength(2);
    fireEvent.click(await within(await screen.findByRole("dialog")).findByRole("button", { name: "Close" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(screen.getByRole("button", { name: "Start scan" })).toBeEnabled();
  });

  it("lets a long scan run in the background", async () => {
    mockApi([[/\/scans\/software/, CREATED], [new RegExp(`/scans/${SCAN_ID}$`), { scan_id: SCAN_ID, status: "running" }]]);
    render();
    fireEvent.change(urlField(), { target: { value: GITHUB } });
    submit();
    fireEvent.click(await screen.findByRole("button", { name: "Run in background" }));
    await waitFor(() => expect(location()).toBe(`/scans/${SCAN_ID}`));
  });

  it("shows progress while starting", () => {
    vi.stubGlobal("fetch", vi.fn(() => new Promise(() => {})));
    render();
    fireEvent.change(urlField(), { target: { value: GITHUB } });
    submit();
    expect(screen.getByRole("button", { name: "Starting scan" })).toBeDisabled();
  });
});
