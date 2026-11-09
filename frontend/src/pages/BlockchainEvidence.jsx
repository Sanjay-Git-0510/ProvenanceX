import AnchorRecord from "../components/blockchain/AnchorRecord.jsx";
import VerificationPanel from "../components/blockchain/VerificationPanel.jsx";
import EmptyState from "../components/EmptyState.jsx";
import ScanPicker from "../components/scan/ScanPicker.jsx";
import Panel from "../components/ui/Panel.jsx";
import useScanSelection from "../hooks/useScanSelection.js";

export default function BlockchainEvidence() {
  const { scanId, invalid, selectScan } = useScanSelection();
  return (
    <>
      <header className="page-head">
        <div>
          <h1>Blockchain Evidence</h1>
          <p className="page-head__lede">
            Compare the anchored evidence of a scan with the chain and its off-chain files. VERIFIED means the record is
            unchanged, not that the scanner was correct.
          </p>
        </div>
      </header>
      <div className="toolbar">
        <ScanPicker scanId={scanId} onSelect={selectScan} />
      </div>
      {invalid ? <EmptyState title="Not a valid scan ID" message="Choose a scan from the list." headingLevel={2} /> : null}
      {!scanId && !invalid ? (
        <EmptyState title="Choose a scan" message="Anchors are shown per scan." headingLevel={2} />
      ) : null}
      {scanId ? (
        <div className="bento" key={scanId}>
          <Panel title="Verification" eyebrow="Runs only when you click Verify" className="span-12">
            <VerificationPanel scanId={scanId} />
          </Panel>
          <Panel title="Anchor record" eyebrow="Stored data only" className="span-12">
            <AnchorRecord scanId={scanId} />
          </Panel>
        </div>
      ) : null}
    </>
  );
}
