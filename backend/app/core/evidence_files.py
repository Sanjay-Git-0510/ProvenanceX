"""Fixed names of the off-chain evidence files kept in a scan's workspace root.

Shared by the pipeline (which writes them) and the rehash worker (which hashes them for /verify),
so both sides agree without the worker importing the pipeline. Never read from the database.
"""

SBOM_FILENAME = "sbom.cdx.json"
AIBOM_FILENAME = "aibom.json"
PROVENANCE_FILENAME = "provenance.json"
