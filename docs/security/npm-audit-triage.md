# npm audit triage: frontend

**Report only.** No package was changed and `npm audit fix` was not run. Data is from `npm audit` in `frontend/` and the
GitHub Advisory Database on 2026-11-09. Scope is the 5 frontend entries. The `contracts/` tree has its own advisories
(see `docs/HANDOFF.md`), which were not triaged here.

| Package | Severity | Installed | Where it runs | Fix |
|---|---|---|---|---|
| `tinypool` | critical | 1.1.1 | Test runner only | Via `vitest` 5.1.0 (major) |
| `vitest` | critical, through `tinypool` | 3.2.7 | Test runner only | 5.1.0 (major) |
| `@vitest/mocker` | moderate | 3.2.7 | Test runner only | Via `vitest` 5.1.0 (major) |
| `react-router` | moderate | 6.30.6 | **Browser bundle** | Via `react-router-dom` 7.18.5 (major) |
| `react-router-dom` | moderate, through `react-router` | 6.30.6 | **Browser bundle** | 7.18.5 (major) |

## Advisories checked against this code

### GHSA-wrjc-x8rr-h8h6: open redirect via backslash in `<Link>` and `useNavigate` (`react-router`, moderate)

- **Applies to:** attacker-supplied paths passed to navigation.
- **How this code uses it:** `<Link>`, `<NavLink>`, `Button to=` and `navigate()` receive one of three things: a fixed
  route from `routes.js`, a literal internal prefix followed by an ID (`/scans/${id}`, `/findings?scan=${id}`), or the
  output of `evidenceRoute`, which accepts only known paths with a UUID and returns null otherwise. No path is taken
  directly from a URL parameter or artifact text.
- **Assessment:** likely not reachable, because every dynamic path starts with a literal internal prefix.
- **Limit:** some IDs inserted after a prefix come from API responses without a UUID check on the client. This rests on
  reading the code. The advisory gives no technical detail, and no exploit was attempted.

### GHSA-337j-9hxr-rhxg: constructor injection in SSR hydration (`react-router`, moderate)

- **Applies to:** Framework Mode and Data Mode with manual SSR or hydration. The advisory says Declarative Mode is not
  affected.
- **How this code uses it:** `main.jsx` uses `<BrowserRouter>` with `createRoot`. There is no `createBrowserRouter`,
  `RouterProvider`, `StaticRouter`, `hydrateRoot`, `hydrationData` or server rendering in `src/`.
- **Assessment:** not applicable, per the advisory's own scope.

### GHSA-82fw-gwwq-j7x9 and GHSA-qxg6-89mg-rqv8: unauthenticated mock registration (`@vitest/mocker`, moderate)

- **Applies to:** a reachable dev server using the public `mockerPlugin` or `interceptorPlugin`. The first advisory says
  Vitest's own browser mode uses an authenticated channel.
- **How this code uses it:** `vite.config.js` uses only the React plugin, with `environment: "jsdom"`. `@vitest/browser`
  and `@vitest/ui` are not installed. `src/` has no `vi.mock`. Neither plugin name appears in `vitest/dist`.
- **Assessment:** the affected plugins are not wired in.
- **Limit:** whether other internal Vitest code paths touch the same handlers was checked only by searching for those two
  names.

### GHSA-5gmw-xhrv-c9v3: prototype pollution through worker options (`tinypool`, critical)

- **Applies to:** a process where `Object.prototype` is already polluted. Options are then passed to `new Worker()`.
- **How this code uses it:** only Vitest uses `tinypool`, and only during `npm test`. Vitest's default pool is `forks`,
  and the config does not change it.
- **Assessment:** an attacker needs code or a pollution primitive already inside the test process. That is a much smaller
  exposure than the critical rating suggests, but it is not zero.
- **Limit:** whether the `forks` path reads the same options as the worker path was not established.

### GHSA-85c8-ppgw-ccpr: prototype pollution through `run()` options (`tinypool`, critical)

- **Applies to:** callers passing an options object to `pool.run()` in a process with a polluted prototype.
- **How this code uses it:** Vitest **does** pass an options object to `pool.run()`, so that half of the precondition is
  met. Pollution would still have to happen inside the test process.
- **Assessment:** same as above. The realistic risk is a malicious development dependency or test file, which could
  already run code during `npm test`.

## Where these packages are present

- **Production bundle:** a search of `frontend/dist` found no `tinypool` or `interceptorPlugin`. `react-router` is imported
  by `main.jsx`, so it is in the bundle.
- **Frontend image:** `npm ci` installs dev packages, so `tinypool` is on disk in the container. Inspection of a running
  demo container showed only the Vite dev server running, and no Vitest process.
- **CI:** `npx vitest --run` runs on ephemeral GitHub runners, with `contents: read` and no secrets.

## What could not be verified

- No exploit was attempted for any advisory, so every "not reachable" above comes from reading code and advisory text.
- Not every transitive dependency was audited for prototype pollution. `lodash.merge` 4.6.2 is present through `eslint`
  and `jest-axe` (dev only). Its use inside those packages was not reviewed.
- The advisory for GHSA-wrjc-x8rr-h8h6 does not describe the exact input or browser behaviour.
- The effect of the fixes is untested. All are major upgrades (`vitest` 3 to 5, `react-router-dom` 6 to 7).
- `npm audit` covers only published advisories on the date above.

## Recommendation (owner decision, nothing applied)

1. Upgrade `vitest` to a patched major on a branch and run the frontend suite. It clears 3 of the 5 entries, including both
   critical ones, and changes no shipped code.
2. Treat `react-router-dom` 7 as a planned migration. It is the only item in the browser bundle, and the assessment above
   does not suggest urgency, but a v6 line patch is not listed by the advisories.
3. Until then, do not pass URL parameters or artifact text directly to `<Link>` or `navigate()`.
