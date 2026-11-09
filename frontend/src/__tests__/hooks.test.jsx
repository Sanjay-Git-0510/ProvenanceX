import { act, renderHook, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import useFindings from "../hooks/useFindings.js";
import useScan from "../hooks/useScan.js";
import useScanSelection from "../hooks/useScanSelection.js";
import useVerification from "../hooks/useVerification.js";
import { SCAN_B, SCAN_ID, calledUrls, findingsPage, mockApi } from "../test/helpers.jsx";

const future = { v7_startTransition: true, v7_relativeSplatPath: true };

function setHidden(hidden) {
  Object.defineProperty(document, "hidden", { configurable: true, get: () => hidden });
  document.dispatchEvent(new Event("visibilitychange"));
}

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
  delete document.hidden;
});

describe("useScan", () => {
  const advance = (ms) => act(() => vi.advanceTimersByTimeAsync(ms));

  async function startRunning() {
    vi.useFakeTimers();
    const fetchMock = mockApi([[/\/evidence/, { scan_status: "running" }]]);
    const view = renderHook(() => useScan(SCAN_ID, { pollMs: 1000 }));
    await advance(0);
    return { fetchMock, ...view };
  }

  it("requests the sanitized summary with small pages", async () => {
    const { fetchMock } = await startRunning();
    expect(calledUrls(fetchMock)).toEqual([`/api/v1/scans/${SCAN_ID}/evidence?findings_limit=1&components_limit=1`]);
  });

  it("polls while the scan runs", async () => {
    const { fetchMock } = await startRunning();
    await advance(2000);
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it("stops when the scan finishes", async () => {
    vi.useFakeTimers();
    let status = "running";
    const fetchMock = mockApi([[/\/evidence/, () => ({ scan_status: status })]]);
    const { result } = renderHook(() => useScan(SCAN_ID, { pollMs: 1000 }));
    await advance(0);
    status = "completed";
    await advance(1000);
    const calls = fetchMock.mock.calls.length;
    await advance(5000);
    expect(fetchMock).toHaveBeenCalledTimes(calls);
    expect(result.current.data.scan_status).toBe("completed");
  });

  it("pauses while hidden and refreshes on return", async () => {
    const { fetchMock } = await startRunning();
    const before = fetchMock.mock.calls.length;
    setHidden(true);
    await advance(5000);
    expect(fetchMock).toHaveBeenCalledTimes(before);
    setHidden(false);
    await advance(0);
    expect(fetchMock).toHaveBeenCalledTimes(before + 1);
  });

  it("does not schedule a poll from a response that lands while hidden", async () => {
    vi.useFakeTimers();
    const fetchMock = mockApi([[/\/evidence/, { scan_status: "running" }]]);
    renderHook(() => useScan(SCAN_ID, { pollMs: 1000 }));
    setHidden(true);
    await advance(5000);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("stops polling after an error and resumes on reload", async () => {
    vi.useFakeTimers();
    const fetchMock = mockApi([[/\/evidence/, { error: { code: "down", message: "x" } }, 503]]);
    const { result } = renderHook(() => useScan(SCAN_ID, { pollMs: 1000 }));
    await advance(0);
    expect(result.current.status).toBe("error");
    await advance(5000);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    act(() => result.current.reload());
    await advance(0);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("stops after unmount", async () => {
    const { fetchMock, unmount } = await startRunning();
    const before = fetchMock.mock.calls.length;
    unmount();
    await advance(5000);
    expect(fetchMock).toHaveBeenCalledTimes(before);
  });

  it("does nothing without a scan id", () => {
    const fetchMock = mockApi([]);
    const { result } = renderHook(() => useScan(null));
    expect(result.current.status).toBe("idle");
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe("useScanSelection", () => {
  const wrapperAt = (entry) =>
    function Wrapper({ children }) {
      return (
        <MemoryRouter initialEntries={[entry]} future={future}>
          {children}
        </MemoryRouter>
      );
    };

  it("reads a valid scan", () => {
    const { result } = renderHook(useScanSelection, { wrapper: wrapperAt(`/x?scan=${SCAN_ID}`) });
    expect(result.current).toMatchObject({ scanId: SCAN_ID, invalid: false });
  });

  it("rejects a malformed scan", () => {
    const { result } = renderHook(useScanSelection, { wrapper: wrapperAt("/x?scan=../health") });
    expect(result.current).toMatchObject({ scanId: null, invalid: true });
  });

  it("is empty with no scan", () => {
    const { result } = renderHook(useScanSelection, { wrapper: wrapperAt("/x") });
    expect(result.current).toMatchObject({ scanId: null, invalid: false });
  });

  it("selecting a scan replaces its filters", () => {
    const { result } = renderHook(useScanSelection, {
      wrapper: wrapperAt(`/x?scan=${SCAN_ID}&category=static&offset=50`),
    });
    act(() => result.current.selectScan(SCAN_B));
    expect(result.current.scanId).toBe(SCAN_B);
  });
});

describe("useFindings", () => {
  it("passes filters to the API", async () => {
    const fetchMock = mockApi([[/\/findings/, findingsPage([])]]);
    const { result } = renderHook(() => useFindings(SCAN_ID, { category: "static", limit: 5, offset: 10 }));
    await waitFor(() => expect(result.current.status).toBe("success"));
    expect(calledUrls(fetchMock)[0]).toBe(`/api/v1/scans/${SCAN_ID}/findings?category=static&limit=5&offset=10`);
  });

  it("waits for a scan id", () => {
    const fetchMock = mockApi([]);
    expect(renderHook(() => useFindings(null)).result.current.status).toBe("idle");
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe("useVerification", () => {
  const answer = { state: "VERIFIED", reason: { code: "x", message: "y" }, fields: [] };

  it("is idle and sends nothing until asked", () => {
    const fetchMock = mockApi([[/\/verify$/, answer]]);
    const { result } = renderHook(() => useVerification(SCAN_ID));
    expect(result.current.status).toBe("idle");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("reports the answer", async () => {
    mockApi([[/\/verify$/, answer]]);
    const { result } = renderHook(() => useVerification(SCAN_ID));
    await act(() => result.current.verify());
    expect(result.current.status).toBe("done");
    expect(result.current.result.state).toBe("VERIFIED");
  });

  it("reports a failed request as failed, with no result", async () => {
    mockApi([[/\/verify$/, { error: { code: "boom", message: "No" } }, 500]]);
    const { result } = renderHook(() => useVerification(SCAN_ID));
    await act(() => result.current.verify());
    expect(result.current.status).toBe("failed");
    expect(result.current.result).toBeNull();
    expect(result.current.error.code).toBe("boom");
  });

  it("forgets the result when the scan changes", async () => {
    const fetchMock = mockApi([[/\/verify$/, answer]]);
    const { result, rerender } = renderHook(({ id }) => useVerification(id), { initialProps: { id: SCAN_ID } });
    await act(() => result.current.verify());
    rerender({ id: SCAN_B });
    expect(result.current.status).toBe("idle");
    expect(result.current.result).toBeNull();
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("drops a late answer for the previous scan", async () => {
    let release;
    vi.stubGlobal(
      "fetch",
      vi.fn(() => new Promise((resolve) => { release = () => resolve({ ok: true, status: 200, json: () => Promise.resolve(answer) }); })),
    );
    const { result, rerender } = renderHook(({ id }) => useVerification(id), { initialProps: { id: SCAN_ID } });
    act(() => { result.current.verify(); });
    rerender({ id: SCAN_B });
    await act(async () => { release(); });
    expect(result.current.status).toBe("idle");
  });

  it("does not send a second request while one is running", async () => {
    let release;
    const fetchMock = vi.fn(() => new Promise((resolve) => { release = () => resolve({ ok: true, status: 200, json: () => Promise.resolve(answer) }); }));
    vi.stubGlobal("fetch", fetchMock);
    const { result } = renderHook(() => useVerification(SCAN_ID));
    act(() => { result.current.verify(); });
    act(() => { result.current.verify(); });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    await act(async () => { release(); });
  });
});
