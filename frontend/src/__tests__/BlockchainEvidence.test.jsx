import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { readdirSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import FieldComparisonTable from "../components/blockchain/FieldComparisonTable.jsx";
import BlockchainEvidence from "../pages/BlockchainEvidence.jsx";
import { HOST_PATH, SCAN_B, SCAN_ID, SHA, calledUrls, mockApi, renderPage, scanList, scanRow } from "../test/helpers.jsx";
import { render } from "@testing-library/react";

const MOCK_TX = `mock-tx-${"a".repeat(32)}`;
const REAL_TX = `0x${"c".repeat(64)}`;

const field = (name, status = "match", values = {}) => ({
  field: name,
  stored: SHA,
  source_table: SHA,
  recomputed: SHA,
  chain: SHA,
  status,
  detail: null,
  ...values,
});

const verification = (overrides = {}) => ({
  scan_id: SCAN_ID,
  state: "VERIFIED",
  reason: { code: "all_match", message: "All fields match" },
  source: "web3",
  is_mock: false,
  fields: [field("artifact_hash")],
  missing_evidence: [],
  tx_hash: REAL_TX,
  verified_at: "2026-11-09T07:06:00Z",
  note: "A note",
  ...overrides,
});

const record = (overrides = {}) => ({
  status: "confirmed",
  source: "web3",
  is_mock: false,
  error_code: null,
  record_hash: SHA,
  artifact_id: SCAN_B,
  artifact_hash: SHA,
  bom_hash: null,
  provenance_hash: SHA,
  risk_score: null,
  risk_score_scaled: 4294967295,
  decision: "REVIEW",
  scanner_version: "0.1.0",
  evidence_timestamp: 1794207960,
  missing_evidence: ["bom_hash"],
  tx_hash: REAL_TX,
  block_number: 0,
  block_hash: REAL_TX,
  anchor_index: 0,
  chain_id: 31337,
  contract_address: `0x${"d".repeat(40)}`,
  anchored_at: "2026-11-09T07:06:00Z",
  ...overrides,
});

afterEach(() => vi.unstubAllGlobals());

function open({ verify = verification(), stored = record(), verifyStatus = 200 } = {}) {
  const fetchMock = mockApi([
    [/\/verify$/, verify, verifyStatus],
    [/\/blockchain$/, { scan_id: SCAN_ID, anchor_recorded: !!stored, record: stored, note: "Stored data only." }],
    [/\/scans\?/, scanList([scanRow()])],
  ]);
  const view = renderPage(<BlockchainEvidence />, { path: `/blockchain?scan=${SCAN_ID}`, route: "/blockchain" });
  return { fetchMock, ...view };
}

const verifyCalls = (fetchMock) => calledUrls(fetchMock).filter((url) => url.endsWith("/verify"));

async function clickVerify() {
  fireEvent.click(await screen.findByRole("button", { name: "Verify" }));
}

describe("verification", () => {
  it("does nothing until the user clicks", async () => {
    const { fetchMock } = open();
    await screen.findByText("Anchor status");
    expect(screen.getByText("Not checked yet")).toBeInTheDocument();
    expect(verifyCalls(fetchMock)).toEqual([]);
  });

  it("sends one POST on click", async () => {
    const { fetchMock } = open();
    await clickVerify();
    await screen.findByText(/not scanner correct/);
    expect(verifyCalls(fetchMock)).toHaveLength(1);
    const [, options] = fetchMock.mock.calls.find(([url]) => url.endsWith("/verify"));
    expect(options.method).toBe("POST");
  });

  it("labels VERIFIED as record unchanged, not scanner correct", async () => {
    open();
    await clickVerify();
    expect((await screen.findByText(/^VERIFIED/)).textContent).toContain("record unchanged, not scanner correct");
  });

  it.each([
    ["MISMATCH", "evidence_mismatch", "Changed: artifact_hash"],
    ["NOT ANCHORED", "no_anchor", "This scan has not been anchored"],
    ["UNKNOWN", "chain_unavailable", "The chain could not be reached"],
  ])("shows %s with its reason code", async (state, code, message) => {
    const { container } = open({ verify: verification({ state, reason: { code, message } }) });
    await clickVerify();
    expect(await screen.findByText(code)).toBeInTheDocument();
    expect(screen.getByText(message)).toBeInTheDocument();
    expect(container.querySelector(".verify__head")).toHaveTextContent(state);
    expect(container.querySelector(".verify__head")).not.toHaveTextContent("VERIFIED");
  });

  it("shows an unrecognized state as UNKNOWN", async () => {
    const { container } = open({ verify: verification({ state: "verified" }) });
    await clickVerify();
    await screen.findByText("all_match");
    expect(container.querySelector(".verify__head")).toHaveTextContent("UNKNOWN");
    expect(container.querySelector(".verify__head")).not.toHaveTextContent("VERIFIED");
  });

  it.each([
    [500, { error: { code: "boom", message: "Server error" } }],
    [200, { no_state: true }],
  ])("keeps a failed request (%i) separate from UNKNOWN", async (verifyStatus, verify) => {
    const { container } = open({ verify, verifyStatus });
    await clickVerify();
    expect(await screen.findByText("The verification request failed")).toBeInTheDocument();
    const head = container.querySelector(".verify__head");
    expect(head).toHaveTextContent("Not checked yet");
    expect(head).not.toHaveTextContent("UNKNOWN");
    expect(container.querySelector(".badge--unknown")).toBeNull();
    expect(screen.queryByRole("table", { name: "Field by field comparison" })).toBeNull();
  });

  it("labels a mock verification", async () => {
    open({ verify: verification({ source: "mock", is_mock: true }) });
    await clickVerify();
    await screen.findByText("all_match");
    expect(within(document.querySelector(".verify__head")).getByText("MOCK DATA")).toBeInTheDocument();
  });

  it("sanitizes reason text", async () => {
    const { container } = open({ verify: verification({ reason: { code: "x", message: `at ${HOST_PATH}` } }) });
    await clickVerify();
    await screen.findByText("x");
    expect(container.innerHTML).not.toContain("/home/victim");
  });

  it("has no Anchor button or anchor request anywhere", async () => {
    const { fetchMock } = open();
    await clickVerify();
    await screen.findByText("all_match");
    expect(screen.queryByRole("button", { name: /anchor/i })).toBeNull();
    expect(calledUrls(fetchMock).some((url) => url.endsWith("/anchor"))).toBe(false);

    const walk = (dir) =>
      readdirSync(dir, { withFileTypes: true }).flatMap((entry) =>
        entry.isDirectory() ? (entry.name === "__tests__" ? [] : walk(join(dir, entry.name))) : [join(dir, entry.name)],
      );
    const callers = walk(resolve(process.cwd(), "src")).filter((path) => /\/anchor\b/.test(readFileSync(path, "utf8")));
    expect(callers).toEqual([]);
  });
});

describe("FieldComparisonTable", () => {
  it("shows all four values for each field", () => {
    render(
      <FieldComparisonTable
        fields={[field("scanner_version", "match", { stored: "s-val", recomputed: "r-val", chain: "c-val", source_table: "t-val" })]}
      />,
    );
    ["Stored", "Recomputed", "Chain", "Source table"].forEach((name) =>
      expect(screen.getByRole("columnheader", { name })).toBeInTheDocument(),
    );
    ["s-val", "r-val", "c-val", "t-val"].forEach((value) => expect(screen.getByText(value)).toBeInTheDocument());
  });

  it("trusts the server when values look different", () => {
    render(<FieldComparisonTable fields={[field("decision", "match", { stored: "ALLOW", chain: "BLOCK", recomputed: "x", source_table: "y" })]} />);
    expect(screen.getByText("Match")).toBeInTheDocument();
    expect(screen.queryByText("Mismatch")).toBeNull();
  });

  it("trusts the server when values look identical", () => {
    render(<FieldComparisonTable fields={[field("artifact_hash", "mismatch")]} />);
    expect(screen.getByText("Mismatch")).toBeInTheDocument();
    expect(screen.queryByText("Match")).toBeNull();
  });

  it.each(["", "ok", "MATCH", "constructor", null])("never shows Match for status %j", (status) => {
    render(<FieldComparisonTable fields={[field("artifact_hash", status)]} />);
    expect(screen.getByText("Unrecognized status")).toBeInTheDocument();
    expect(screen.queryByText("Match")).toBeNull();
  });

  it("keeps a real 0 and shows null as no value", () => {
    render(<FieldComparisonTable fields={[field("risk_score", "absent", { stored: 0, recomputed: null, chain: null, source_table: null })]} />);
    expect(screen.getByText("0")).toBeInTheDocument();
    expect(screen.getAllByText("No value")).toHaveLength(3);
  });

  it("does not print objects or bad hashes", () => {
    const { container } = render(
      <FieldComparisonTable fields={[field("decision", "match", { stored: { raw: "PX_BLOB" } }), field("record_hash", "mismatch", { chain: "<b>nope</b>" })]} />,
    );
    expect(container.innerHTML).not.toContain("PX_BLOB");
    expect(container.querySelector("b")).toBeNull();
    expect(screen.getByText("Invalid format")).toBeInTheDocument();
  });
});

describe("anchor record", () => {
  it("shows stored values and keeps block 0 and a null score distinct", async () => {
    open();
    expect((await screen.findByText("Block number")).closest(".dl__row")).toHaveTextContent("0");
    expect(screen.getByText("ProvenanceX risk when anchored").closest(".dl__row")).toHaveTextContent("Not computed yet");
    expect(screen.getByText("BOM hash").closest(".dl__row")).toHaveTextContent("Absent when anchored");
  });

  it("shows a mock tx id with a mock label", async () => {
    open({ stored: record({ source: "mock", is_mock: true, tx_hash: MOCK_TX, block_hash: null, chain_id: null, contract_address: null }) });
    const row = (await screen.findByText("Transaction")).closest(".dl__row");
    expect(within(row).getByText("mock")).toBeInTheDocument();
    expect(row).toHaveTextContent(MOCK_TX);
    expect(screen.getByText("MOCK DATA")).toBeInTheDocument();
  });

  it("rejects a mock id on a real record", async () => {
    open({ stored: record({ tx_hash: MOCK_TX }) });
    const row = (await screen.findByText("Transaction")).closest(".dl__row");
    expect(row).toHaveTextContent("Invalid format");
    expect(row).not.toHaveTextContent("mock-tx");
  });

  it("rejects a real hash on a mock record", async () => {
    open({ stored: record({ source: "mock", is_mock: true, tx_hash: REAL_TX }) });
    expect((await screen.findByText("Transaction")).closest(".dl__row")).toHaveTextContent("Invalid format");
  });

  it("treats source=mock as mock when is_mock is missing", async () => {
    open({ stored: record({ source: "mock", is_mock: false, tx_hash: MOCK_TX }) });
    const row = (await screen.findByText("Transaction")).closest(".dl__row");
    expect(row).toHaveTextContent(MOCK_TX);
    expect(within(row).getByText("mock")).toBeInTheDocument();
  });

  it("shows no ALLOW badge without its caveat", async () => {
    const { container } = open({ stored: record({ decision: "ALLOW" }) });
    await screen.findByText("Decision when anchored");
    expect(container.querySelector(".badge--allow")).toBeNull();
  });

  it("explains a missing anchor", async () => {
    open({ stored: null });
    expect(await screen.findByText("No anchor recorded")).toBeInTheDocument();
    await waitFor(() => expect(screen.getByText(/cannot be started from the dashboard/)).toBeInTheDocument());
  });
});
