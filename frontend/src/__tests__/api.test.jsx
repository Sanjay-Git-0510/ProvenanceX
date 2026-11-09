import { act, renderHook, waitFor } from "@testing-library/react";
import useApi from "../hooks/useApi.js";
import { ApiError, api, request } from "../services/api.js";

const ID = "11111111-2222-4333-8444-555555555555";

function jsonResponse(status, body) {
  return Promise.resolve({ ok: status < 400, status, json: () => Promise.resolve(body) });
}

let fetchMock;

beforeEach(() => {
  fetchMock = vi.fn(() => jsonResponse(200, { ok: true }));
  vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

const lastCall = () => fetchMock.mock.calls.at(-1);

describe("request", () => {
  it("parses the structured error envelope", async () => {
    fetchMock.mockReturnValue(
      jsonResponse(422, { error: { code: "validation_error", message: "bad", details: [1] } }),
    );
    const err = await request("/x").catch((e) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(err).toMatchObject({ code: "validation_error", message: "bad", status: 422, details: [1] });
  });

  it("handles a non-JSON error body", async () => {
    fetchMock.mockReturnValue(
      Promise.resolve({ ok: false, status: 502, json: () => Promise.reject(new Error("html")) }),
    );
    await expect(request("/x")).rejects.toMatchObject({ code: "http_502", status: 502 });
  });

  it("reports an unreachable API", async () => {
    fetchMock.mockReturnValue(Promise.reject(new TypeError("Failed to fetch")));
    await expect(request("/x")).rejects.toMatchObject({ code: "network_error", status: 0 });
  });

  it("reports a cancelled request separately", async () => {
    fetchMock.mockReturnValue(Promise.reject(new DOMException("stop", "AbortError")));
    await expect(request("/x")).rejects.toMatchObject({ code: "aborted" });
  });

  it("merges caller headers with Accept", async () => {
    await request("/x", { headers: { "X-Test": "1" } });
    expect(lastCall()[1].headers).toEqual({ Accept: "application/json", "X-Test": "1" });
  });
});

describe("endpoints", () => {
  it.each([
    ["listScans", () => api.listScans(), "/api/v1/scans"],
    [
      "listScans with params",
      () => api.listScans({ limit: 20, offset: 0, status: "failed" }),
      "/api/v1/scans?limit=20&offset=0&status=failed",
    ],
    ["getScan", () => api.getScan(ID), `/api/v1/scans/${ID}`],
    ["getFindings", () => api.getFindings(ID), `/api/v1/scans/${ID}/findings`],
    [
      "getFindings with filters",
      () => api.getFindings(ID, { category: "static", severity: "HIGH", source: "osv", limit: 50, offset: 100 }),
      `/api/v1/scans/${ID}/findings?category=static&severity=HIGH&source=osv&limit=50&offset=100`,
    ],
    ["getGraph", () => api.getGraph(ID), `/api/v1/scans/${ID}/graph`],
    ["getRisk", () => api.getRisk(ID), `/api/v1/scans/${ID}/risk`],
    [
      "getEvidence",
      () => api.getEvidence(ID, { findingsLimit: 1, findingsOffset: 2, componentsLimit: 3, componentsOffset: 4 }),
      `/api/v1/scans/${ID}/evidence?findings_limit=1&findings_offset=2&components_limit=3&components_offset=4`,
    ],
    ["getBlockchain", () => api.getBlockchain(ID), `/api/v1/scans/${ID}/blockchain`],
  ])("%s", async (_, call, url) => {
    await call();
    expect(lastCall()[0]).toBe(url);
    expect(lastCall()[1].method).toBeUndefined();
  });

  it("verifies with POST", async () => {
    await api.verifyScan(ID);
    expect(lastCall()[0]).toBe(`/api/v1/scans/${ID}/verify`);
    expect(lastCall()[1].method).toBe("POST");
  });

  it("has no anchor call", () => {
    expect(Object.keys(api).filter((name) => /anchor/i.test(name))).toEqual([]);
  });

  it("encodes scan ids in the path", async () => {
    await api.getScan("../health");
    expect(lastCall()[0]).toBe("/api/v1/scans/..%2Fhealth");
  });

  it("sends a software scan as a form without a manual Content-Type", async () => {
    await api.createSoftwareScan({ sourceUrl: "https://github.com/a/b", revision: "main", name: "" });
    const [url, options] = lastCall();
    expect(url).toBe("/api/v1/scans/software");
    expect(options.method).toBe("POST");
    expect(options.headers["Content-Type"]).toBeUndefined();
    expect(Object.fromEntries(options.body)).toEqual({
      source_url: "https://github.com/a/b",
      revision: "main",
    });
  });

  it("sends a model upload with its artifact type", async () => {
    const file = new File(["zip"], "m.zip", { type: "application/zip" });
    await api.createModelScan({ file, artifactType: "lora" });
    const [url, options] = lastCall();
    expect(url).toBe("/api/v1/scans/model");
    expect(options.body.get("artifact_type")).toBe("lora");
    expect(options.body.get("file").name).toBe("m.zip");
  });

  it("passes the abort signal", async () => {
    const { signal } = new AbortController();
    await api.getRisk(ID, { signal });
    expect(lastCall()[1].signal).toBe(signal);
  });
});

describe("useApi", () => {
  it("goes from loading to success", async () => {
    const fetcher = vi.fn(() => Promise.resolve({ value: 1 }));
    const { result } = renderHook(() => useApi(fetcher));
    expect(result.current.status).toBe("loading");
    await waitFor(() => expect(result.current.status).toBe("success"));
    expect(result.current.data).toEqual({ value: 1 });
  });

  it("reports errors", async () => {
    const error = new ApiError({ code: "x", message: "failed", status: 500 });
    const fetcher = () => Promise.reject(error);
    const { result } = renderHook(() => useApi(fetcher));
    await waitFor(() => expect(result.current.status).toBe("error"));
    expect(result.current.error).toBe(error);
    expect(result.current.data).toBeNull();
  });

  it("stays idle without a fetcher", () => {
    const { result } = renderHook(() => useApi(null));
    expect(result.current.status).toBe("idle");
  });

  it("reloads on request", async () => {
    const fetcher = vi.fn(() => Promise.resolve(1));
    const { result } = renderHook(() => useApi(fetcher));
    await waitFor(() => expect(result.current.status).toBe("success"));
    act(() => result.current.reload());
    await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(2));
    await waitFor(() => expect(result.current.status).toBe("success"));
  });

  it("ignores a stale response and clears the old data", async () => {
    let resolveFirst;
    const first = () => new Promise((resolve) => (resolveFirst = resolve));
    const second = () => Promise.resolve("second");
    const { result, rerender } = renderHook(({ fetcher }) => useApi(fetcher), {
      initialProps: { fetcher: first },
    });
    rerender({ fetcher: second });
    await waitFor(() => expect(result.current.data).toBe("second"));
    await act(async () => resolveFirst("first"));
    expect(result.current.data).toBe("second");
  });

  it("aborts on unmount", () => {
    let seen;
    const fetcher = ({ signal }) => {
      seen = signal;
      return new Promise(() => {});
    };
    const { unmount } = renderHook(() => useApi(fetcher));
    unmount();
    expect(seen.aborted).toBe(true);
  });
});
