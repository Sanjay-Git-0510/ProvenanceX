// Pre-scan checks that mirror the server's rules so problems show before upload.
// The server still enforces every rule; passing here never means the scan will be accepted.

export const WORKFLOWS = {
  software: {
    label: "Software package",
    endpoint: "software",
    artifactType: "software",
    host: "github.com",
    hostName: "GitHub",
    placeholder: "github.com/owner/repository",
    hint: "A public GitHub repository, or a ZIP of the project. Manifests and lockfiles are parsed for an SBOM.",
  },
  model: {
    label: "AI model",
    endpoint: "model",
    artifactType: "model",
    host: "huggingface.co",
    hostName: "Hugging Face",
    placeholder: "huggingface.co/owner/model",
    hint: "A public Hugging Face model repository, or a ZIP of a model directory. Weights are parsed, never loaded.",
  },
  dataset: {
    label: "Dataset",
    endpoint: "model",
    artifactType: "dataset",
    host: "huggingface.co",
    hostName: "Hugging Face",
    placeholder: "huggingface.co/datasets/owner/name",
    hint: "A public Hugging Face dataset repository (under /datasets/), or a ZIP of the dataset files.",
  },
  lora: {
    label: "LoRA adapter",
    endpoint: "model",
    artifactType: "lora",
    host: "huggingface.co",
    hostName: "Hugging Face",
    placeholder: "huggingface.co/owner/adapter",
    hint: "A public Hugging Face adapter repository, or a ZIP of the adapter files. The base model is recorded as lineage.",
  },
};

const MAX_URL_LENGTH = 2048;
const MAX_REVISION_LENGTH = 200;
const GH_OWNER = /^[A-Za-z0-9][A-Za-z0-9-]{0,38}$/;
const GH_REPO = /^[A-Za-z0-9._-]{1,100}$/;
const HF_SEGMENT = /^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,94}[A-Za-z0-9])?$/;
const HF_RESERVED = new Set(["api", "spaces", "models", "docs", "settings", "datasets"]);
const REVISION = /^[A-Za-z0-9][A-Za-z0-9._/+-]{0,199}$/;
const MB = 1024 * 1024;

function hasControlChars(value) {
  return [...value].some((ch) => ch.charCodeAt(0) < 33 || ch.charCodeAt(0) === 127);
}

function parseHttpsUrl(value, host, hostName) {
  const fail = { error: `Enter a full https address on ${hostName} (${host}).` };
  if (!value || value.length > MAX_URL_LENGTH || hasControlChars(value) || value.includes("\\")) return fail;
  let url;
  try {
    url = new URL(value);
  } catch {
    return fail;
  }
  if (url.protocol !== "https:" || url.hostname !== host || url.username || url.password || url.port) return fail;
  if (url.search || url.hash) return { error: "Remove the query string or fragment from the address." };
  const segments = url.pathname.replace(/\/$/, "").split("/").slice(1);
  return { segments };
}

function githubProblem(segments) {
  if (segments.length !== 2) return "Expected an https address like github.com/<owner>/<repository>.";
  const [owner, rawRepo] = segments;
  const repo = rawRepo.endsWith(".git") ? rawRepo.slice(0, -4) : rawRepo;
  if (!GH_OWNER.test(owner) || !GH_REPO.test(repo) || repo === "." || repo === "..") {
    return "The GitHub owner or repository name is not valid.";
  }
  return null;
}

function validHfSegment(segment) {
  return HF_SEGMENT.test(segment) && !segment.includes("..") && !segment.includes("--") && !segment.endsWith(".git");
}

function huggingFaceProblem(segments, workflow) {
  const isDataset = segments[0] === "datasets";
  if (workflow === "dataset" && !isDataset) {
    return "A dataset address is under huggingface.co/datasets/.";
  }
  if (workflow !== "dataset" && isDataset) {
    return "This is a dataset address. Choose the Dataset workflow instead.";
  }
  const rest = isDataset ? segments.slice(1) : segments;
  if (isDataset && rest.length !== 2) return "Expected an https address like huggingface.co/datasets/<owner>/<name>.";
  if (!rest.length || rest.length > 2) return "Expected an https address like huggingface.co/<owner>/<name>.";
  if (HF_RESERVED.has(rest[0].toLowerCase())) return "This Hugging Face address is not a repository.";
  if (!rest.every(validHfSegment)) return "The Hugging Face owner or repository name is not valid.";
  return null;
}

/** Same rule as backend/app/security/revision.py. Empty is allowed (the default branch). */
export function revisionProblem(value) {
  const rev = (value || "").trim();
  if (!rev) return null;
  if (
    rev.length > MAX_REVISION_LENGTH ||
    !REVISION.test(rev) ||
    rev.includes("..") ||
    rev.includes("//") ||
    rev.includes("/.") ||
    rev.endsWith("/") ||
    rev.endsWith(".") ||
    rev.endsWith(".lock")
  ) {
    return "Use a branch name, tag or full commit SHA (letters, digits, . _ / + -).";
  }
  return null;
}

/** Size check against the server limit. With no known limit, nothing is claimed. */
export function fileProblem(file, limits) {
  if (!file) return "Choose a ZIP file to upload.";
  if (!file.name.toLowerCase().endsWith(".zip")) return "Only .zip uploads are supported.";
  if (file.size === 0) return "The file is empty.";
  const maxMb = limits?.max_upload_mb;
  if (typeof maxMb === "number" && maxMb > 0 && file.size > maxMb * MB) {
    return `The file is ${(file.size / MB).toFixed(1)} MB. The server accepts uploads up to ${maxMb} MB.`;
  }
  return null;
}

/**
 * Returns { field, message } for the first problem, or null. `field` is "url", "file" or
 * "revision", so the message can be shown next to its input.
 */
export function validateScanInput({ workflow, mode, url, file, revision }, limits = null) {
  const spec = WORKFLOWS[workflow];
  if (!spec) return { field: "workflow", message: "Choose what to scan." };
  if (mode === "url") {
    const parsed = parseHttpsUrl((url || "").trim(), spec.host, spec.hostName);
    if (parsed.error) return { field: "url", message: parsed.error };
    const problem =
      workflow === "software" ? githubProblem(parsed.segments) : huggingFaceProblem(parsed.segments, workflow);
    if (problem) return { field: "url", message: problem };
  } else {
    const problem = fileProblem(file, limits);
    if (problem) return { field: "file", message: problem };
  }
  const revProblem = revisionProblem(revision);
  return revProblem ? { field: "revision", message: revProblem } : null;
}
