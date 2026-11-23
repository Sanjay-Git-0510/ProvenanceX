import { fileProblem, revisionProblem, validateScanInput } from "../lib/scanValidation.js";

const check = (workflow, url, revision = "") => validateScanInput({ workflow, mode: "url", url, revision });
const zip = (size, name = "a.zip") => ({ name, size });

describe("validateScanInput: URLs", () => {
  it.each([
    ["software", "https://github.com/pallets/flask"],
    ["software", "https://github.com/pallets/flask.git"],
    ["software", "https://github.com/pallets/flask/"],
    ["model", "https://huggingface.co/owner/model"],
    ["model", "https://huggingface.co/gpt2"],
    ["lora", "https://huggingface.co/owner/adapter"],
    ["dataset", "https://huggingface.co/datasets/owner/name"],
  ])("accepts %s %s", (workflow, url) => {
    expect(check(workflow, url)).toBeNull();
  });

  it.each([
    ["software", "http://github.com/a/b"],
    ["software", "https://huggingface.co/a/b"],
    ["software", "https://github.com/a"],
    ["software", "https://github.com/a/b/tree/main"],
    ["software", "https://github.com/-bad/b"],
    ["software", "https://github.com/a/b?x=1"],
    ["software", "https://user:pw@github.com/a/b"],
    ["software", "https://github.com:8443/a/b"],
    ["model", "https://huggingface.co/datasets/a/b"],
    ["model", "https://huggingface.co/spaces/a"],
    ["model", "https://huggingface.co/a/b/c"],
    ["model", "https://huggingface.co/a/b--c"],
    ["dataset", "https://huggingface.co/a/b"],
    ["dataset", "https://huggingface.co/datasets/a"],
    ["lora", "https://github.com/a/b"],
    ["model", "file:///etc/passwd"],
    ["model", ""],
  ])("refuses %s %s", (workflow, url) => {
    expect(check(workflow, url)).toMatchObject({ field: "url" });
  });

  it("points a dataset URL to the Dataset workflow", () => {
    expect(check("model", "https://huggingface.co/datasets/a/b").message).toMatch(/Dataset workflow/);
  });
});

describe("revisionProblem", () => {
  it.each(["", "main", "v1.2.3", "release/2.x", "a".repeat(40)])("accepts %s", (rev) => {
    expect(revisionProblem(rev)).toBeNull();
  });
  it.each(["-x", "a..b", "a//b", "a/.b", "a/", "a.", "a.lock", "a b", "a".repeat(201)])("refuses %s", (rev) => {
    expect(revisionProblem(rev)).not.toBeNull();
  });
  it("is reported against the revision field", () => {
    expect(check("software", "https://github.com/a/b", "--upload-pack=x")).toMatchObject({ field: "revision" });
  });
});

describe("fileProblem", () => {
  it("requires a non-empty ZIP", () => {
    expect(fileProblem(null)).toMatch(/Choose a ZIP/);
    expect(fileProblem(zip(10, "a.tar"))).toMatch(/Only .zip/);
    expect(fileProblem(zip(0))).toMatch(/empty/);
    expect(fileProblem(zip(10, "A.ZIP"))).toBeNull();
  });
  it("checks size only against a known server limit", () => {
    const big = zip(3 * 1024 * 1024);
    expect(fileProblem(big, { max_upload_mb: 2 })).toMatch(/up to 2 MB/);
    expect(fileProblem(big, { max_upload_mb: 5 })).toBeNull();
    expect(fileProblem(big, null)).toBeNull();
    expect(fileProblem(big, { max_upload_mb: "2" })).toBeNull();
  });
  it("is reported against the file field", () => {
    expect(validateScanInput({ workflow: "lora", mode: "upload", file: null })).toMatchObject({ field: "file" });
  });
});
