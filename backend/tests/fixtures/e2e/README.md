# End-to-end fixtures (benign, synthetic, text only)

Used by `backend/tests/e2e/test_full_pipeline.py`. Nothing here is real malware, and nothing is
installed, imported or executed. `tests/security/test_e2e_fixtures.py` fails if a binary, a pickle,
an archive, a symlink or a fixture import of `os`, `subprocess`, `socket` or a network library
appears here.

- `software_clean/`: a small project with one pinned dependency.
- `software_risky_config/`: the same, plus a `setup.py` with an install hook that does nothing.
- `model_clean/`: a model card and a config, with no weights.
- `model_risky_config/`: the same, plus an `auto_map` config and code files that do nothing.

The dangerous-global case is not stored here. The test writes a few pickle opcode bytes to a
temporary directory at run time: a global reference and `STOP`, with no call. The file is only
parsed with `pickletools`, and is never loaded.

The tampered case has no fixture of its own: the test edits a file in a scan's workspace after
anchoring it.

A scan of these fixtures checks that the pipeline is wired together. It is not a detection result.
