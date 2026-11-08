# npm_lock_project (benign fixture)

A tiny npm project with a `package-lock.json` (lockfile v3) so Syft produces real
dependency edges, including transitive ones (express -> body-parser -> qs).
There is no `node_modules` directory and nothing here is ever installed or run.
The pinned versions are old on purpose, so OSV returns known public advisories for them.
The `integrity` values are placeholders, because no package is ever downloaded.
