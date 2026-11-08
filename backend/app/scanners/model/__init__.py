"""Parse-only analysis of AI/ML artifacts (Phase 3).

Nothing in this package imports, loads or executes artifact content. Pickles are
inspected with `pickletools.genops` (opcode parsing), never with pickle/torch loaders.
"""
