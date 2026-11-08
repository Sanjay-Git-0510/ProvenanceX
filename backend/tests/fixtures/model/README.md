# Model fixtures (benign, synthetic)

Text-only fixtures for the Phase 3 AI ingestion tests. Binary model files (safetensors,
pickles, torch-style ZIPs) are generated inside the tests by `tests/model_helpers.py`
and written to temporary directories. No real model, malware or third-party weights are
committed. The hostile pickles used by the security tests are built from raw opcodes in
memory and are only ever parsed, never loaded.

- `lora_adapter/`: a PEFT LoRA adapter config, a model card and requirements
- `card_minimal/`: a README without YAML front matter
- `remote_code_model/`: a config whose `auto_map` points at repository code, plus that code
