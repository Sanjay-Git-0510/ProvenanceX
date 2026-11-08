# Vulnerability-source fixtures

Real public API responses, recorded on 2026-11-08:
- `osv_recorded.json`: OSV querybatch plus `/v1/vulns/{id}` records for the fixture packages
  (`affected[].versions` lists removed). It is the same file as `app/scanners/mock_data/osv_recorded.json`.
- `nvd_CVE-2024-47081.json`: NVD CVE API 2.0 response for CVE-2024-47081 (requests .netrc leak).
