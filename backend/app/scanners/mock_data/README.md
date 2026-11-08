# Mock provider data

Used only when `SBOM_PROVIDER=mock` or `VULN_PROVIDER=mock` (development and tests).
Everything these providers return is tagged `source="mock"` in the API and the UI.

- `mock_sbom.cdx.json`: real Syft 1.57.0 CycloneDX output for the benign fixture
  `backend/tests/fixtures/software/npm_lock_project`. The mock SBOM provider returns it
  for **every** input, whatever was uploaded. That is why its output is labeled mock.
- `osv_recorded.json`: real OSV API responses (querybatch + `/v1/vulns/{id}`), recorded
  for the fixture packages on the `recorded_at` date. The `affected[].versions` lists are
  removed to keep the file small. The advisories are real public records, but a mock
  lookup is not a live lookup, so the findings it produces are tagged `source="mock"`.
