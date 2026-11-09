import { MAX_TEXT, REDACTED, TRUNCATED, sanitizeDisplay } from "../lib/sanitizeDisplay.js";

const SECRETS = {
  path: "/home/victim/provenancex/workspace/scan/src/app.py",
  rootOnly: "/tmp",
  windows: "C:\\Users\\victim\\secrets.txt",
  unc: "\\\\server\\share\\file.txt",
  github: `ghp_${"a1B2".repeat(9)}`,
  githubPat: `github_pat_${"a1B2".repeat(9)}`,
  huggingface: `hf_${"Zz9y".repeat(8)}`,
  apiKey: `sk-${"a1B2".repeat(8)}`,
  aws: "AKIAABCDEFGHIJKLMNOP",
  chain: `0x${"ab".repeat(32)}`,
  pem: "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----",
  bearer: "Bearer abcdefgh12345678",
  assignment: "password=hunter2",
  mixedCase: "API_KEY: abc123",
  urlCredentials: "https://user:hunter2@example.test/x",
  fileUrl: "file:///etc/passwd",
};

describe("sanitizeDisplay", () => {
  it.each(Object.entries(SECRETS))("redacts %s", (_, secret) => {
    const output = sanitizeDisplay(`before ${secret} after`);
    expect(output).toContain(REDACTED);
    expect(output).not.toContain(secret);
  });

  it("removes every occurrence", () => {
    expect(sanitizeDisplay("/home/a and /home/b")).toBe(`${REDACTED} and ${REDACTED}`);
  });

  it("gives the same answer on repeated calls", () => {
    expect(sanitizeDisplay(SECRETS.path)).toBe(sanitizeDisplay(SECRETS.path));
  });

  it.each([
    "requests 2.32.3",
    "https://github.com/pallets/flask",
    "GHSA-abcd-efgh-ijkl",
    "pkg:pypi/requests@2.32.3",
    "src/app/main.py",
    "a token of appreciation",
  ])("leaves %s alone", (text) => {
    expect(sanitizeDisplay(text)).toBe(text);
  });

  it("caps long text", () => {
    const output = sanitizeDisplay("a".repeat(MAX_TEXT + 5));
    expect(output).toBe("a".repeat(MAX_TEXT) + TRUNCATED);
  });

  it.each([null, undefined, 0, {}, []])("returns an empty string for %s", (value) => {
    expect(sanitizeDisplay(value)).toBe("");
  });

  it("returns markup as inert text for React to escape", () => {
    expect(sanitizeDisplay("<img src=x onerror=alert(1)>")).toBe("<img src=x onerror=alert(1)>");
  });
});
