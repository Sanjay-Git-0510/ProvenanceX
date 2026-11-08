# SBOM fixtures

Real Syft 1.57.0 CycloneDX output, recorded on 2026-11-08:
- `syft_npm_lock.cdx.json`: from `../software/npm_lock_project` (lockfile with transitive edges)
- `syft_requirements_only.cdx.json`: from `../software/simple_python_project` (no edges)

Malformed and hostile SBOMs are generated inside the tests themselves.
