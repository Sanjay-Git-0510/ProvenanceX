"""Worker exit codes for its self-imposed limits. No imports: the worker loads this first."""

EXIT_DEADLINE = 124  # the in-container wall-clock deadline passed (as coreutils `timeout`)
EXIT_CPU_LIMIT = 152  # RLIMIT_CPU was reached (128 + SIGXCPU)
