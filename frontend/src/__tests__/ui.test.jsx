import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { useState } from "react";
import { MemoryRouter } from "react-router-dom";
import Badge from "../components/ui/Badge.jsx";
import Button from "../components/ui/Button.jsx";
import DataTable from "../components/ui/DataTable.jsx";
import DecisionBadge from "../components/ui/DecisionBadge.jsx";
import ErrorState from "../components/ui/ErrorState.jsx";
import HashValue from "../components/ui/HashValue.jsx";
import LoadingState from "../components/ui/LoadingState.jsx";
import MockLabel from "../components/ui/MockLabel.jsx";
import Modal from "../components/ui/Modal.jsx";
import Pagination from "../components/ui/Pagination.jsx";
import Panel from "../components/ui/Panel.jsx";
import VerificationBadge from "../components/ui/VerificationBadge.jsx";
import { ApiError } from "../services/api.js";

const SHA = "a".repeat(64);
const UUID = "11111111-2222-4333-8444-555555555555";
const hasIcon = (element) => element.querySelector('svg[aria-hidden="true"]') !== null;

describe("Button", () => {
  it("renders a button that does not submit by default", () => {
    render(<Button>Go</Button>);
    expect(screen.getByRole("button", { name: "Go" })).toHaveAttribute("type", "button");
  });

  it("renders a link with `to`", () => {
    render(
      <MemoryRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
        <Button to="/x">Go</Button>
      </MemoryRouter>,
    );
    expect(screen.getByRole("link", { name: "Go" })).toHaveAttribute("href", "/x");
  });

  it("is disabled and busy while loading", () => {
    render(<Button loading>Go</Button>);
    const button = screen.getByRole("button");
    expect(button).toBeDisabled();
    expect(button).toHaveAttribute("aria-busy", "true");
  });
});

describe("Badge", () => {
  it.each(["neutral", "accent", "allow", "review", "block", "unknown", "mock"])(
    "%s tone has text and an icon",
    (tone) => {
      render(<Badge tone={tone}>Label</Badge>);
      expect(hasIcon(screen.getByText("Label"))).toBe(true);
    },
  );
});

describe("DecisionBadge", () => {
  it.each(["ALLOW", "REVIEW", "BLOCK"])("shows %s with an icon", (decision) => {
    render(<DecisionBadge decision={decision} />);
    expect(hasIcon(screen.getByText(decision))).toBe(true);
  });

  it.each([null, undefined])("%s decision is not computed yet", (decision) => {
    const { container } = render(<DecisionBadge decision={decision} />);
    expect(screen.getByText("Not computed yet")).toBeInTheDocument();
    expect(container).not.toHaveTextContent(/0|ALLOW|REVIEW|BLOCK/);
  });

  it.each(["SAFE", "allow", "constructor"])("treats %s as UNKNOWN, never ALLOW", (decision) => {
    render(<DecisionBadge decision={decision} />);
    expect(screen.getByText("UNKNOWN")).toBeInTheDocument();
  });
});

describe("VerificationBadge", () => {
  it("says VERIFIED only means the record is unchanged", () => {
    render(<VerificationBadge state="VERIFIED" />);
    const badge = screen.getByText(/VERIFIED/);
    expect(badge).toHaveTextContent("record unchanged");
    expect(hasIcon(badge)).toBe(true);
  });

  it.each(["MISMATCH", "NOT ANCHORED", "UNKNOWN"])("shows %s", (state) => {
    const { container } = render(<VerificationBadge state={state} />);
    expect(hasIcon(screen.getByText(state))).toBe(true);
    expect(container).not.toHaveTextContent("VERIFIED");
  });

  it("shows an unrecognized state as UNKNOWN", () => {
    const { container } = render(<VerificationBadge state="verified" />);
    expect(container).toHaveTextContent("UNKNOWN");
    expect(container).not.toHaveTextContent("record unchanged");
  });

  it("shows a missing state as not checked", () => {
    render(<VerificationBadge state={null} />);
    expect(screen.getByText("Not checked yet")).toBeInTheDocument();
  });
});

describe("MockLabel", () => {
  it("labels source=mock", () => {
    render(<MockLabel source="mock" />);
    expect(screen.getByText("MOCK DATA")).toBeInTheDocument();
  });

  it("labels is_mock", () => {
    render(<MockLabel isMock />);
    expect(screen.getByText("MOCK DATA")).toBeInTheDocument();
  });

  it("is absent for real data", () => {
    const { container } = render(<MockLabel source="osv" />);
    expect(container).toBeEmptyDOMElement();
  });
});

describe("Panel", () => {
  it("is a named region at the requested level", () => {
    render(
      <Panel title="Evidence" level={2} eyebrow="Scan">
        body
      </Panel>,
    );
    const region = screen.getByRole("region", { name: "Evidence" });
    expect(region).toHaveClass("panel--level-2");
    expect(region).toHaveTextContent("Scan");
  });
});

describe("DataTable", () => {
  const columns = [
    { key: "name", header: "Name" },
    { key: "score", header: "Score", align: "end", render: (row) => row.score },
  ];

  it("renders semantic headers and rows", () => {
    render(
      <DataTable caption="Scans" columns={columns} rows={[{ id: 1, name: "a", score: 0 }]} getRowKey={(r) => r.id} />,
    );
    const table = screen.getByRole("table", { name: "Scans" });
    expect(within(table).getByRole("columnheader", { name: "Name" })).toHaveAttribute("scope", "col");
    expect(within(table).getByRole("cell", { name: "0" })).toBeInTheDocument();
  });

  it("makes the scroll region keyboard reachable", () => {
    render(<DataTable caption="Scans" columns={columns} rows={[{ id: 1, name: "a" }]} getRowKey={(r) => r.id} />);
    expect(screen.getByRole("region", { name: "Scans" })).toHaveAttribute("tabindex", "0");
  });

  it("shows words for a null cell", () => {
    render(<DataTable caption="Scans" columns={columns} rows={[{ id: 1, name: null, score: null }]} getRowKey={(r) => r.id} />);
    expect(screen.getAllByText("Not available")).toHaveLength(2);
  });

  it("renders the supplied empty state", () => {
    render(<DataTable caption="Scans" columns={columns} rows={[]} getRowKey={(r) => r.id} empty={<p>Stage did not run</p>} />);
    expect(screen.getByText("Stage did not run")).toBeInTheDocument();
    expect(screen.queryByRole("table")).toBeNull();
  });

  it("has a default empty state", () => {
    render(<DataTable caption="Scans" columns={columns} rows={[]} getRowKey={(r) => r.id} />);
    expect(screen.getByRole("heading", { name: "No rows" })).toBeInTheDocument();
  });

  it("renders artifact markup as text", () => {
    const rows = [{ id: 1, name: "<img src=x onerror=alert(1)>" }];
    const { container } = render(<DataTable caption="Scans" columns={columns} rows={rows} getRowKey={(r) => r.id} />);
    expect(container.querySelector("img")).toBeNull();
    expect(screen.getByText(rows[0].name)).toBeInTheDocument();
  });
});

describe("Pagination", () => {
  it("shows the range and moves by page", () => {
    const onChange = vi.fn();
    render(<Pagination total={45} limit={20} offset={20} hasMore onChange={onChange} />);
    expect(screen.getByText("Showing 21 to 40 of 45")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Next" }));
    expect(onChange).toHaveBeenLastCalledWith(40);
    fireEvent.click(screen.getByRole("button", { name: "Previous" }));
    expect(onChange).toHaveBeenLastCalledWith(0);
  });

  it("disables Previous on the first page and Next on the last", () => {
    render(<Pagination total={3} limit={20} offset={0} hasMore={false} onChange={() => {}} />);
    expect(screen.getByRole("button", { name: "Previous" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Next" })).toBeDisabled();
  });

  it("derives has-more from the total for /findings", () => {
    render(<Pagination total={45} limit={20} offset={0} onChange={() => {}} />);
    expect(screen.getByRole("button", { name: "Next" })).toBeEnabled();
  });

  it("handles no results and a page past the end", () => {
    const { rerender } = render(<Pagination total={0} limit={20} offset={0} onChange={() => {}} />);
    expect(screen.getByText("No results")).toBeInTheDocument();
    rerender(<Pagination total={3} limit={20} offset={40} hasMore={false} onChange={() => {}} />);
    expect(screen.getByText("No rows at this page of 3")).toBeInTheDocument();
  });
});

describe("LoadingState", () => {
  it("announces its label", () => {
    render(<LoadingState label="Loading scans" />);
    expect(screen.getByRole("status")).toHaveTextContent("Loading scans");
  });
});

describe("ErrorState", () => {
  it("offers retry for a temporary failure", () => {
    const onRetry = vi.fn();
    render(<ErrorState error={new ApiError({ code: "x", message: "down", status: 503 })} onRetry={onRetry} />);
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    expect(onRetry).toHaveBeenCalledOnce();
    expect(screen.getByRole("alert")).toHaveTextContent("You can retry");
  });

  it("offers no retry for a client error", () => {
    render(<ErrorState error={new ApiError({ code: "scan_not_found", message: "Scan not found", status: 404 })} onRetry={() => {}} />);
    expect(screen.queryByRole("button", { name: "Retry" })).toBeNull();
    expect(screen.getByRole("alert")).toHaveTextContent("scan_not_found");
  });

  it("redacts host paths and never shows details", () => {
    const error = new ApiError({
      code: "x",
      message: "failed at /home/victim/app.py",
      details: { secret_detail: "PX_CANARY" },
      status: 500,
    });
    render(<ErrorState error={error} />);
    const alert = screen.getByRole("alert");
    expect(alert).not.toHaveTextContent("/home/victim");
    expect(alert).not.toHaveTextContent("PX_CANARY");
    expect(alert).toHaveTextContent("[redacted]");
  });

  it("has a message when the error has none", () => {
    render(<ErrorState error={null} />);
    expect(screen.getByRole("alert")).toHaveTextContent("An unexpected error occurred.");
  });
});

describe("HashValue", () => {
  it.each([
    ["sha256", SHA],
    ["commit", "b".repeat(40)],
    ["tx", `0x${"c".repeat(64)}`],
    ["address", `0x${"d".repeat(40)}`],
    ["uuid", UUID],
  ])("shows a valid %s as plain text", (kind, value) => {
    const { container } = render(<HashValue kind={kind} value={value} />);
    const code = container.querySelector("code");
    expect(code.textContent).toBe(value);
    expect(code.children).toHaveLength(0);
  });

  it.each([
    ["sha256", "abc"],
    ["sha256", `${"a".repeat(64)}\n`],
    ["sha256", `${"g".repeat(64)}`],
    ["sha256", `<img src=x onerror=alert(1)>${"a".repeat(36)}`],
    ["uuid", SHA],
    ["tx", SHA],
    ["address", `0x${"e".repeat(64)}`],
    ["not-a-kind", SHA],
    ["sha256", 12345],
    ["sha256", { toString: () => SHA }],
  ])("refuses kind %s value %s without showing it", (kind, value) => {
    const { container } = render(<HashValue kind={kind} value={value} />);
    expect(screen.getByText("Invalid format")).toBeInTheDocument();
    expect(container.querySelector("code")).toBeNull();
    expect(container.querySelector("img")).toBeNull();
    expect(container).not.toHaveTextContent(String(value).slice(0, 12));
    expect(screen.queryByRole("button")).toBeNull();
  });

  it.each([null, undefined, ""])("shows the reason for a missing value (%s)", (value) => {
    render(<HashValue value={value} reason="No SBOM was produced" />);
    expect(screen.getByText("No SBOM was produced")).toBeInTheDocument();
  });

  it("has a default for a missing value", () => {
    render(<HashValue value={null} />);
    expect(screen.getByText("Not available")).toBeInTheDocument();
  });

  it("truncates visually and keeps the full value in the title", () => {
    const { container } = render(<HashValue value={SHA} truncate />);
    const code = container.querySelector("code");
    expect(code.textContent).toBe(`${"a".repeat(10)}…${"a".repeat(8)}`);
    expect(code).toHaveAttribute("title", SHA);
  });

  it("copies the validated value", async () => {
    const writeText = vi.fn(() => Promise.resolve());
    vi.stubGlobal("navigator", { clipboard: { writeText } });
    render(<HashValue value={SHA} label="artifact hash" />);
    fireEvent.click(screen.getByRole("button", { name: "Copy artifact hash" }));
    await screen.findByRole("button", { name: "Copied artifact hash" });
    expect(writeText).toHaveBeenCalledWith(SHA);
    vi.unstubAllGlobals();
  });

  it("reports a failed copy", async () => {
    vi.stubGlobal("navigator", { clipboard: { writeText: () => Promise.reject(new Error("denied")) } });
    render(<HashValue value={SHA} label="hash" />);
    fireEvent.click(screen.getByRole("button", { name: "Copy hash" }));
    await screen.findByRole("button", { name: "Copy failed hash" });
    vi.unstubAllGlobals();
  });
});

describe("Modal", () => {
  function Harness({ onClose = () => {} }) {
    const [open, setOpen] = useState(false);
    return (
      <>
        <button onClick={() => setOpen(true)}>Open</button>
        <Modal
          open={open}
          title="Details"
          onClose={() => {
            onClose();
            setOpen(false);
          }}
          footer={<button>Confirm</button>}
        >
          <p>Body</p>
        </Modal>
      </>
    );
  }

  function openModal(onClose) {
    render(<Harness onClose={onClose} />);
    const opener = screen.getByRole("button", { name: "Open" });
    opener.focus();
    fireEvent.click(opener);
    return { opener, dialog: screen.getByRole("dialog", { name: "Details" }) };
  }

  it("is absent until opened", () => {
    render(<Harness />);
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("is modal, takes focus, and locks page scroll", () => {
    const { dialog } = openModal();
    expect(dialog).toHaveAttribute("aria-modal", "true");
    expect(dialog).toHaveFocus();
    expect(document.body.style.overflow).toBe("hidden");
  });

  it("closes on Escape and restores focus and scrolling", async () => {
    const onClose = vi.fn();
    const { opener } = openModal(onClose);
    fireEvent.keyDown(document, { key: "Escape" });
    expect(onClose).toHaveBeenCalledOnce();
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(opener).toHaveFocus();
    expect(document.body.style.overflow).toBe("");
  });

  it("closes on a backdrop click but not a panel click", () => {
    const onClose = vi.fn();
    const { dialog } = openModal(onClose);
    fireEvent.mouseDown(dialog);
    expect(onClose).not.toHaveBeenCalled();
    fireEvent.mouseDown(dialog.parentElement);
    expect(onClose).toHaveBeenCalledOnce();
  });

  it("traps Tab inside the panel", () => {
    openModal();
    const close = screen.getByRole("button", { name: "Close" });
    const confirm = screen.getByRole("button", { name: "Confirm" });
    confirm.focus();
    fireEvent.keyDown(document, { key: "Tab" });
    expect(close).toHaveFocus();
    fireEvent.keyDown(document, { key: "Tab", shiftKey: true });
    expect(confirm).toHaveFocus();
  });
});
