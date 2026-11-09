import { fireEvent, screen, waitFor } from "@testing-library/react";
import NewScan from "../pages/NewScan.jsx";
import { SCAN_ID, mockApi, renderPage } from "../test/helpers.jsx";

const CREATED = { scan_id: SCAN_ID, artifact_id: SCAN_ID, status: "queued" };
const GITHUB = "https://github.com/pallets/flask";

afterEach(() => vi.unstubAllGlobals());

const render = () => renderPage(<NewScan />, { path: "/scans/new", route: "/scans/new" });
const urlField = () => screen.getByLabelText("Repository URL (https)");
const submit = () => fireEvent.click(screen.getByRole("button", { name: "Start scan" }));
const location = () => screen.getByTestId("location").textContent;

describe("New Scan", () => {
  it("starts a software scan and opens it", async () => {
    const fetchMock = mockApi([[/\/scans\/software/, CREATED]]);
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
    const fetchMock = mockApi([[/\/scans\/model/, CREATED]]);
    render();
    fireEvent.click(screen.getByLabelText("AI / ML"));
    fireEvent.change(screen.getByLabelText("Model artifact type"), { target: { value: "lora" } });
    fireEvent.change(urlField(), { target: { value: "https://huggingface.co/a/b" } });
    submit();
    await waitFor(() => expect(location()).toBe(`/scans/${SCAN_ID}`));
    expect(fetchMock.mock.calls[0][1].body.get("artifact_type")).toBe("lora");
  });

  it("uploads a ZIP", async () => {
    const fetchMock = mockApi([[/\/scans\/software/, CREATED]]);
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

  it("shows progress while starting", () => {
    vi.stubGlobal("fetch", vi.fn(() => new Promise(() => {})));
    render();
    fireEvent.change(urlField(), { target: { value: GITHUB } });
    submit();
    expect(screen.getByRole("button", { name: "Starting scan" })).toBeDisabled();
  });
});
