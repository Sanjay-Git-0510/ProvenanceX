---
license: apache-2.0
library_name: peft
base_model: hf-internal-testing/tiny-random-gpt2
datasets:
  - provenancex-fixtures/synthetic-instructions
language:
  - en
pipeline_tag: text-generation
tags:
  - synthetic
  - provenancex-mock
---

# ProvenanceX mock LoRA adapter (synthetic fixture)

This is a synthetic, benign fixture used only by the ProvenanceX mock Hugging Face
provider. It is not a real model and its weights are zeros.

## Intended use

Development and tests of the ProvenanceX AI ingestion pipeline.

## Limitations

The adapter has no useful weights. The dataset name is fictional.
