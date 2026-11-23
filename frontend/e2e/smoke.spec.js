// Browser smoke test on the REAL stack: the API, scan runner and analyzer sandbox must be up.
// Scans are real uploads of the benign e2e fixtures. Requests intercepted below never reach the
// API; the test says so in the response it returns, and those responses are never shown as data.
import { execFileSync } from "node:child_process";
import { mkdirSync, truncateSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { expect, test } from "@playwright/test";

const FIXTURES = resolve(import.meta.dirname, "../../backend/tests/fixtures/e2e");
const MB = 1024 * 1024;
const SCAN_URL = /\/scans\/[0-9a-f-]{36}$/;
const SCAN_TIMEOUT = 15 * 60 * 1000;

test.describe.configure({ mode: "serial" });

/** Zip a fixture folder with its files at the top level (python3 stdlib zipfile). */
function zipFixture(name, out) {
  execFileSync("python3", [
    "-I",
    "-c",
    "import sys,zipfile,pathlib\n" +
      "src=pathlib.Path(sys.argv[1]); z=zipfile.ZipFile(sys.argv[2],'w')\n" +
      "[z.write(p,p.relative_to(src).as_posix()) for p in sorted(src.rglob('*')) if p.is_file()]\n" +
      "z.close()",
    resolve(FIXTURES, name),
    out,
  ]);
  return out;
}

function trackScanPosts(page) {
  const posts = [];
  page.on("request", (req) => {
    if (req.method() === "POST" && /\/api\/v1\/scans\/(software|model)$/.test(req.url())) posts.push(req.url());
  });
  return posts;
}

/** Click the visible workflow card, as a user does, and confirm its radio is selected. */
async function chooseWorkflow(page, label) {
  await page.locator("label.type-picker__option", { hasText: label }).click();
  await expect(page.getByLabel(new RegExp(`^${label}`))).toBeChecked();
}

test("New Scan: four workflows, hints and server limits", async ({ page, request }) => {
  const limits = await (await request.get("/api/v1/limits")).json();
  await page.goto("/scans/new");
  await expect(page.getByText(`Uploads up to ${limits.max_upload_mb} MB`)).toBeVisible();
  const cases = [
    ["Software package", "GitHub URL", /Manifests and lockfiles/],
    ["AI model", "Hugging Face URL", /Weights are parsed, never loaded/],
    ["Dataset", "Hugging Face URL", /under \/datasets\//],
    ["LoRA adapter", "Hugging Face URL", /base model is recorded as lineage/],
  ];
  for (const [label, source, hint] of cases) {
    await chooseWorkflow(page, label);
    await expect(page.getByText(hint)).toBeVisible();
    await expect(page.getByLabel(source)).toBeVisible();
  }
});

test("New Scan: pre-scan checks stop bad input before any request", async ({ page, request }, info) => {
  const limits = await (await request.get("/api/v1/limits")).json();
  const posts = trackScanPosts(page);
  await page.goto("/scans/new");
  const url = page.getByLabel("Repository URL (https)");
  const start = page.getByRole("button", { name: "Start scan" });

  await chooseWorkflow(page, "AI model");
  await url.fill("https://huggingface.co/datasets/owner/name");
  await start.click();
  await expect(page.getByRole("alert")).toContainText("Dataset workflow");
  await expect(url).toHaveAttribute("aria-invalid", "true");

  await chooseWorkflow(page, "Dataset");
  await url.fill("https://huggingface.co/owner/name");
  await start.click();
  await expect(page.getByRole("alert")).toContainText("huggingface.co/datasets/");

  await chooseWorkflow(page, "Software package");
  await url.fill("http://github.com/pallets/flask");
  await start.click();
  await expect(page.getByRole("alert")).toContainText("GitHub");

  await url.fill("https://github.com/pallets/flask");
  await page.getByLabel(/^Revision/).fill("--upload-pack=x");
  await start.click();
  await expect(page.getByRole("alert")).toContainText("branch name, tag or full commit SHA");
  await page.getByLabel(/^Revision/).fill("");

  await page.getByLabel("Upload ZIP").check();
  // A sparse file one byte over the server's upload limit (never sent: the check is client-side).
  const big = info.outputPath("big.zip");
  mkdirSync(dirname(big), { recursive: true });
  writeFileSync(big, "");
  truncateSync(big, limits.max_upload_mb * MB + 1);
  await page.getByLabel("ZIP file").setInputFiles(big);
  await start.click();
  await expect(page.getByRole("alert")).toContainText(`up to ${limits.max_upload_mb} MB`);

  expect(posts).toEqual([]);
});

test("New Scan: LoRA and dataset send their artifact type", async ({ page }) => {
  const seen = [];
  await page.route("**/api/v1/scans/model", async (route) => {
    seen.push(route.request().postData() || "");
    await route.fulfill({
      status: 400,
      contentType: "application/json",
      body: JSON.stringify({ error: { code: "browser_test_intercepted", message: "Intercepted by the browser test; no scan was created" } }),
    });
  });
  await page.goto("/scans/new");
  for (const [label, address, type] of [
    ["LoRA adapter", "https://huggingface.co/ybelkada/opt-350m-lora", "lora"],
    ["Dataset", "https://huggingface.co/datasets/cornell-movie-review-data/rotten_tomatoes", "dataset"],
  ]) {
    await chooseWorkflow(page, label);
    await page.getByLabel("Repository URL (https)").fill(address);
    await page.getByRole("button", { name: "Start scan" }).click();
    await expect(page.getByRole("alert")).toContainText("The scan was not started");
    expect(seen.at(-1)).toMatch(new RegExp(`name="artifact_type"\\r\\n\\r\\n${type}\\r\\n`));
  }
  expect(seen).toHaveLength(2);
});

let softwareScan;

test("Software upload: progress stages, then Scan Details evidence panels", async ({ page }, info) => {
  const zip = zipFixture("software_clean", info.outputPath("software_clean.zip"));
  await page.goto("/scans/new");
  await page.getByLabel("Upload ZIP").check();
  await page.getByLabel("ZIP file").setInputFiles(zip);
  await page.getByLabel(/^Display name/).fill("browser-smoke-software");
  await page.getByRole("button", { name: "Start scan" }).click();

  const dialog = page.getByRole("dialog");
  const stages = dialog.getByRole("list", { name: "Scan stages" });
  await expect(stages.getByText("Fetch and hash artifact")).toBeVisible();
  await expect(stages.getByText("Generate SBOM")).toBeVisible();
  await expect(stages.getByText("Anchor evidence on the chain")).toBeVisible();
  await expect(stages.getByText("Done").first()).toBeVisible({ timeout: SCAN_TIMEOUT });

  await page.waitForURL(SCAN_URL, { timeout: SCAN_TIMEOUT });
  softwareScan = page.url().split("/").pop();
  for (const name of ["Risk summary", "Evidence status", "Evidence completeness", "Top contributing factors"]) {
    await expect(page.getByRole("region", { name })).toBeVisible({ timeout: 60_000 });
  }
  const summary = page.getByRole("region", { name: "Risk summary" });
  await expect(summary).toContainText(/(LOW|MEDIUM|HIGH) RISK|NO RISK LEVEL|No risk summary/);
  await expect(summary).toContainText(/hand-set research parameters|No risk summary/);
  await expect(page.getByRole("region", { name: "Scan summary" })).toContainText(/ALLOW|REVIEW|BLOCK|UNKNOWN/);
  await expect(page.getByRole("region", { name: "Timeline" })).toBeVisible();
});

test("Risk Analysis shows the same summary and evidence status", async ({ page }) => {
  test.skip(!softwareScan, "needs the software scan from the previous test");
  await page.goto(`/risk?scan=${softwareScan}`);
  for (const name of ["Risk summary", "Evidence status", "Evidence completeness", "Top contributing factors", "Decision"]) {
    await expect(page.getByRole("region", { name })).toBeVisible({ timeout: 60_000 });
  }
  await expect(page.getByRole("region", { name: "Evidence status" })).toContainText(/Confirmed|Signal|Gap|No evidence states apply/);
});

test("Blockchain Evidence: anchor record and an on-demand verification", async ({ page }) => {
  test.skip(!softwareScan, "needs the software scan from an earlier test");
  await page.goto(`/blockchain?scan=${softwareScan}`);
  const anchor = page.getByRole("region", { name: "Anchor record", exact: true });
  await expect(anchor).toBeVisible();
  await expect(anchor).toContainText(/No anchor recorded|Transaction|tx/i);
  const verification = page.getByRole("region", { name: "Verification" });
  await verification.getByRole("button", { name: "Verify" }).click();
  // With BLOCKCHAIN_PROVIDER=disabled the honest outcomes are NOT ANCHORED, UNKNOWN or a failed request.
  await expect(verification).toContainText(/VERIFIED|MISMATCH|NOT ANCHORED|UNKNOWN|The verification request failed/, {
    timeout: 10 * 60 * 1000,
  });
  info_log(await verification.innerText());
});

test("AI model upload: completes and links to Model Lineage", async ({ page }, info) => {
  const zip = zipFixture("model_clean", info.outputPath("model_clean.zip"));
  await page.goto("/scans/new");
  await chooseWorkflow(page, "AI model");
  await page.getByLabel("Upload ZIP").check();
  await page.getByLabel("ZIP file").setInputFiles(zip);
  await page.getByLabel(/^Display name/).fill("browser-smoke-model");
  await page.getByRole("button", { name: "Start scan" }).click();
  await expect(page.getByRole("dialog").getByText("Build AI-BOM")).toBeVisible();
  await page.waitForURL(SCAN_URL, { timeout: SCAN_TIMEOUT });
  await expect(page.getByRole("region", { name: "Risk summary" })).toBeVisible({ timeout: 60_000 });
  await expect(page.getByRole("link", { name: "Open model lineage" })).toBeVisible();
});

function info_log(text) {
  console.log(`[blockchain panel] ${text.replace(/\s+/g, " ").slice(0, 300)}`);
}
