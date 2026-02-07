const core = require("@actions/core");
const github = require("@actions/github");
const fs = require("fs");
const AdmZip = require("adm-zip");

function toBool(s, def) {
  if (s === undefined || s === null || s === "") return def;
  return /^(true|yes|1|on)$/i.test(String(s).trim());
}

const CI_FAILURE_MARKER = "<!-- ci-failure-explainer:v0 -->";

// -------------------- Output helpers --------------------

function appendStepSummary(markdown) {
  const summaryPath = process.env.GITHUB_STEP_SUMMARY;
  if (!summaryPath) {
    core.info(markdown);
    return;
  }
  fs.appendFileSync(summaryPath, markdown + "\n", { encoding: "utf8" });
}

function codeBlock(text, lang = "") {
  const safe = (text ?? "").toString().replace(/```/g, "``\\`");
  return `\n\`\`\`${lang}\n${safe}\n\`\`\`\n`;
}

// -------------------- Normalization + detection --------------------

function normalize(line) {
  return (line ?? "")
      .toString()
      // strip GitHub Actions timestamp prefix (common in downloaded logs)
      .replace(/^\uFEFF?\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z\s+/g, "")
      .replace(/\b0x[0-9a-fA-F]+\b/g, "0x…")
      .replace(/\b[0-9a-f]{7,40}\b/g, "…sha…")
      .replace(/:\d+:\d+/g, ":<line>:<col>")
      .replace(/:\d+/g, ":<line>")
      .trim();
}

/**
 * Try to infer which *step* a line belongs to by scanning the log for step boundaries.
 * GitHub logs usually have:
 *   ##[group]Run <command>
 *   ...
 *   ##[endgroup]
 *
 * Sometimes:
 *   ##[group]Step: <name>
 */
function buildStepIndex(lines) {
  const stepStarts = []; // { idx, name }
  let current = "Unknown step";

  const groupRun = /^.*##\[group\]Run\s+(.+)\s*$/;
  const groupStep = /^.*##\[group\]Step:\s+(.+)\s*$/;
  const groupName = /^.*##\[group\](.+)\s*$/; // fallback

  for (let i = 0; i < lines.length; i++) {
    const l = lines[i];

    let m = l.match(groupStep);
    if (m) {
      current = m[1].trim();
      stepStarts.push({ idx: i, name: current });
      continue;
    }

    m = l.match(groupRun);
    if (m) {
      current = `Run ${m[1].trim()}`;
      stepStarts.push({ idx: i, name: current });
      continue;
    }

    // Fallback: many actions group things (not perfect, but better than nothing)
    m = l.match(groupName);
    if (m) {
      const n = m[1].trim();
      // avoid noisy generic groups
      if (n && !/^Post\b/i.test(n) && !/^Cleaning up\b/i.test(n)) {
        current = n;
        stepStarts.push({ idx: i, name: current });
      }
    }
  }

  return stepStarts;
}

function findStepForLineIndex(stepStarts, lineIndex) {
  if (!stepStarts || stepStarts.length === 0) return "Unknown step";
  // stepStarts is increasing by idx
  let lo = 0,
      hi = stepStarts.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if (stepStarts[mid].idx <= lineIndex) lo = mid + 1;
    else hi = mid - 1;
  }
  return stepStarts[Math.max(0, hi)].name;
}

function pickFirstMeaningfulError(lines) {
  // More precise Node/TS/Frontend CI rules first (less false positives)
  const rules = [
    // ESLint: common formats
    { name: "ESLint", re: /^\s*\d+:\d+\s+(error|warning)\s+.+\s+.+$/i }, // classic table output
    { name: "ESLint", re: /\bESLint\b.*(found|problems?)/i },
    { name: "ESLint", re: /eslint(?:\.js)?:\s+.*(error|failed)/i },

    // TypeScript compiler
    { name: "TypeScript", re: /error TS\d+:/i },
    { name: "TypeScript", re: /Type error:|TS\d{3,5}\b/i },

    // npm/yarn/pnpm errors
    { name: "npm", re: /\bnpm ERR!\b/i },
    { name: "npm", re: /\bERR_PNPM_\w+\b/i },
    { name: "npm", re: /\byarn (run|install)\b.*(error|failed)/i },

    // Jest/Vitest
    { name: "Jest/Vitest", re: /^(FAIL|●)\b/ },
    { name: "Jest/Vitest", re: /(Test Suites: \d+ failed|AssertionError)/ },

    // Build tools (Vite/Webpack/etc.)
    { name: "Build", re: /\b(vite|webpack)\b.*(error|failed)/i },
    { name: "Build", re: /\bBuild failed\b/i },

    // Docker
    { name: "Docker", re: /(failed to solve|executor failed|ERROR: failed|docker buildx|#\d+ ERROR)/i },

    // Python: pytest
    { name: "pytest", re: /FAILED\s+\S+\.py/i },
    { name: "pytest", re: /ERROR\s+\S+\.py/i },

    // Python: mypy
    { name: "mypy", re: /\.py:\d+: error:/i },

    // Python: ruff/flake8
    { name: "ruff/flake8", re: /\.py:\d+:\d+:\s+[A-Z]\d+/i },

    // Python: pip
    { name: "pip", re: /ERROR:.*pip/i },

    // Go: test failures
    { name: "Go", re: /--- FAIL:/i },

    // Go: lint
    { name: "Go", re: /\.go:\d+:\d+:/i },

    // Go: build errors
    { name: "Go", re: /cannot find package/i },
    { name: "Go", re: /\bundefined:/i },

    // Generic JS runtime errors (keep late to avoid noise)
    { name: "Node", re: /\b(TypeError|ReferenceError|SyntaxError)\b/ },
    { name: "Node", re: /\bUnhandledPromiseRejection\b|\bUnhandled rejection\b/i }
  ];

  for (const rule of rules) {
    const idx = lines.findIndex((l) => rule.re.test(l));
    if (idx !== -1) {
      const excerpt = lines.slice(Math.max(0, idx - 2), Math.min(lines.length, idx + 12));
      return { rule: rule.name, line: lines[idx], excerpt, lineIndex: idx };
    }
  }

  // fallback: first line that looks like an error (avoid super-noisy GitHub markers)
  const idx = lines.findIndex((l) => {
    if (!l) return false;
    if (/##\[(group|endgroup|debug|notice)\]/i.test(l)) return false;
    return /\berror\b|exception|failed/i.test(l);
  });

  if (idx !== -1) {
    const excerpt = lines.slice(Math.max(0, idx - 2), Math.min(lines.length, idx + 12));
    return { rule: "Generic", line: lines[idx], excerpt, lineIndex: idx };
  }

  return null;
}

function hintFor(ruleName) {
  const hints = {
    ESLint: [
      "Run the linter locally and apply the suggested fix (often `npm run lint -- --fix` depending on your script).",
      "If it’s intentional, adjust the specific rule or add a targeted disable (avoid global ignores)."
    ],
    TypeScript: [
      "Open the referenced file/line and fix the type mismatch; TS errors often cascade, so start with the first one.",
      "If it’s dependency types, check lockfile drift and TypeScript version compatibility."
    ],
    npm: [
      "Scroll up to the first `npm ERR!` / pnpm error line; the last lines are usually summaries.",
      "If it’s install-related, verify Node version, lockfile, and registry/auth."
    ],
    "Jest/Vitest": [
      "Run the failing test locally; focus on the first failing assertion and any snapshot mismatch.",
      "If flaky, check timers, async cleanup, and shared state."
    ],
    Build: [
      "Look for the first bundler error (missing import, invalid config, env mismatch).",
      "If it’s environment-only, compare Node version and build-time env vars."
    ],
    Docker: [
      "The first failing build step is the real cause; missing files and auth issues are common.",
      "Verify build context paths and base image tag availability."
    ],
    pytest: [
      "Run the failing test locally with `pytest -x` to stop at the first failure.",
      "Check for fixture issues, missing mocks, or environment-dependent tests."
    ],
    mypy: [
      "Fix the type annotation at the referenced file/line; mypy errors often cascade from a single root cause.",
      "If it's a third-party library, check for missing type stubs (`types-*` packages)."
    ],
    "ruff/flake8": [
      "Run `ruff check --fix` or `flake8` locally to see and auto-fix lint issues.",
      "If the rule is intentionally violated, add a `# noqa: <code>` comment on the specific line."
    ],
    pip: [
      "Check Python version compatibility and that all dependencies are available.",
      "If it's a build dependency, ensure system packages (e.g., `libffi-dev`) are installed."
    ],
    Go: [
      "Run `go test ./...` locally to reproduce the failure.",
      "For build errors, check `go.mod` / `go.sum` and run `go mod tidy`."
    ],
    Node: [
      "Find the first stack trace frame pointing to your code; earlier frames are often library internals.",
      "If it's an unhandled promise, ensure awaits/returns are correct and add proper error handling."
    ],
    Generic: [
      "Start from the first error-looking line; later failures are often symptoms.",
      "If logs are huge, split steps or fail fast to reduce noise."
    ]
  };
  return hints[ruleName] || hints.Generic;
}

// -------------------- Logs download + parsing --------------------

function bufferFromOctokitData(data) {
  if (!data) return Buffer.alloc(0);
  if (Buffer.isBuffer(data)) return data;
  if (data instanceof ArrayBuffer) return Buffer.from(new Uint8Array(data));
  if (ArrayBuffer.isView(data)) return Buffer.from(data);
  if (typeof data === "string") return Buffer.from(data, "utf8");
  return Buffer.from(data);
}

function classifyLogsPayload(buf, contentType = "") {
  const isZip = buf.length >= 2 && buf[0] === 0x50 && buf[1] === 0x4b;
  if (isZip) return { kind: "zip", zipBuf: buf, contentType };

  let text = buf.toString("utf8");
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
  return { kind: "text", text, contentType };
}

async function downloadJobLogs({ octokit, owner, repo, jobId }) {
  const resp = await octokit.request("GET /repos/{owner}/{repo}/actions/jobs/{job_id}/logs", {
    owner,
    repo,
    job_id: jobId,
    request: { redirect: "manual" }
  });

  if (resp.status === 200) {
    const buf = bufferFromOctokitData(resp.data);
    const ct = resp.headers?.["content-type"] || "";
    return classifyLogsPayload(buf, ct);
  }

  const location = resp.headers?.location || resp.headers?.Location;
  if (!location) throw new Error(`Expected redirect with Location header, got status=${resp.status}`);

  const r = await fetch(location);
  if (!r.ok) throw new Error(`Failed to fetch redirected logs URL: ${r.status} ${r.statusText}`);

  const ct = r.headers.get("content-type") || "";
  const arr = await r.arrayBuffer();
  const buf = Buffer.from(arr);
  return classifyLogsPayload(buf, ct);
}

function extractTextFilesFromZip(zipBuf, { maxFiles = 80, maxTotalBytes = 12 * 1024 * 1024 } = {}) {
  const zip = new AdmZip(zipBuf);
  const entries = zip.getEntries();

  const candidates = entries
      .filter((e) => !e.isDirectory)
      .filter((e) => {
        const n = (e.entryName || "").toLowerCase();
        return n.endsWith(".txt") || n.endsWith(".log") || n.includes("log");
      })
      .slice(0, maxFiles);

  const out = [];
  let used = 0;

  for (const e of candidates) {
    const buf = e.getData();
    if (!buf || buf.length === 0) continue;
    if (used + buf.length > maxTotalBytes) break;
    used += buf.length;

    let text = buf.toString("utf8");
    if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);

    out.push({ name: e.entryName, text });
  }

  return out;
}

function findFirstErrorInText({ text, fileName }) {
  const lines = text.split(/\r?\n/);
  const stepStarts = buildStepIndex(lines);
  const hit = pickFirstMeaningfulError(lines);
  if (!hit) return null;

  const stepName = findStepForLineIndex(stepStarts, hit.lineIndex);
  return { ...hit, stepName, fileName };
}

function findFirstErrorAcrossTexts(textFiles) {
  for (const f of textFiles) {
    const hit = findFirstErrorInText({ text: f.text, fileName: f.name });
    if (hit) return hit;
  }
  return null;
}

// -------------------- PR comment --------------------

async function getRunContext(octokit) {
  const ctx = github.context;

  if (ctx.payload?.workflow_run?.id) {
    const runId = ctx.payload.workflow_run.id;
    const { owner, repo } = ctx.repo;
    let prs = [];
    try {
      const prResp = await octokit.rest.actions.listPullRequestsAssociatedWithWorkflowRun({
        owner, repo, run_id: runId
      });
      prs = (prResp.data || []).map((p) => p.number);
    } catch {
      prs = [];
    }
    return { owner, repo, runId, prNumbers: prs };
  }

  return {
    owner: ctx.repo.owner,
    repo: ctx.repo.repo,
    runId: ctx.runId,
    prNumbers: ctx.payload?.pull_request ? [ctx.payload.pull_request.number] : []
  };
}

async function upsertComment(octokit, { owner, repo, issue_number, body }) {
  const comments = await octokit.rest.issues.listComments({
    owner, repo, issue_number, per_page: 100
  });

  const existing = comments.data.find((c) => (c.body || "").includes(CI_FAILURE_MARKER));
  if (existing) {
    await octokit.rest.issues.updateComment({
      owner, repo, comment_id: existing.id, body
    });
    return { updated: true, url: existing.html_url };
  }

  const created = await octokit.rest.issues.createComment({
    owner, repo, issue_number, body
  });
  return { updated: false, url: created.data.html_url };
}

// -------------------- Main --------------------

async function run() {
  try {
    const token = core.getInput("github_token", { required: true });
    const commentOnPR = toBool(core.getInput("comment_on_pr"), false);
    const jsonOutput = toBool(core.getInput("json_output"), false);

    const octokit = github.getOctokit(token);
    const { owner, repo, runId, prNumbers } = await getRunContext(octokit);
    const summaryParts = [];
    const jsonResults = [];

    core.info(`CI Explainer: analyzing ${owner}/${repo} run_id=${runId}`);

    const jobsResp = await octokit.rest.actions.listJobsForWorkflowRun({
      owner,
      repo,
      run_id: runId,
      per_page: 100
    });

    const failedJobs = jobsResp.data.jobs.filter((j) => j.conclusion === "failure");

    if (failedJobs.length === 0) {
      appendStepSummary("### CI Explainer\nNo failed jobs detected.\n");
      return;
    }

    appendStepSummary("### CI Explainer\n");
    summaryParts.push("### CI Explainer\n");

    for (const job of failedJobs.slice(0, 5)) {
      appendStepSummary(`#### Failed job: ${job.name}\n`);
      appendStepSummary(`- Conclusion: **${job.conclusion}**\n`);
      appendStepSummary(`- URL: ${job.html_url}\n`);
      summaryParts.push(`#### Failed job: ${job.name}\n`);

      let payload;
      try {
        payload = await downloadJobLogs({ octokit, owner, repo, jobId: job.id });
      } catch (e) {
        const msg = e?.message || String(e);
        core.warning(`Could not download logs: ${msg}`);
        appendStepSummary(`- Could not download logs: ${msg}\n\n`);
        continue;
      }

      let hit = null;

      if (payload.kind === "zip") {
        core.info(`CI Explainer: job ${job.id} logs=zip (${payload.contentType || "?"})`);
        const textFiles = extractTextFilesFromZip(payload.zipBuf);
        hit = findFirstErrorAcrossTexts(textFiles);
      } else {
        core.info(`CI Explainer: job ${job.id} logs=text (${payload.contentType || "?"})`);
        hit = findFirstErrorInText({ text: payload.text, fileName: `job-${job.id}.log` });
      }

      if (!hit) {
        appendStepSummary(`- No obvious error signature found (rules too limited or logs too noisy).\n\n`);
        continue;
      }

      const normalized = normalize(hit.line);
      const [primaryHint, secondaryHint] = hintFor(hit.rule);
      const excerpt = (hit.excerpt || []).slice(0, 16).map(normalize).join("\n");

      appendStepSummary(`- Failing step: **${hit.stepName}**\n`);
      appendStepSummary(`- Detected type: **${hit.rule}**\n`);
      appendStepSummary(`- Source log: \`${hit.fileName}\`\n`);
      appendStepSummary(`- First error (normalized):${codeBlock(normalized)}\n`);
      appendStepSummary(`- Likely fix: ${primaryHint}\n`);
      if (secondaryHint) appendStepSummary(`- Also check: ${secondaryHint}\n`);
      appendStepSummary(`- Context:${codeBlock(excerpt)}\n`);

      summaryParts.push(
        `- Failing step: **${hit.stepName}**\n` +
        `- Detected type: **${hit.rule}**\n` +
        `- First error:${codeBlock(normalized)}\n` +
        `- Likely fix: ${primaryHint}\n`
      );

      if (jsonOutput) {
        jsonResults.push({
          job: job.name,
          step: hit.stepName,
          errorType: hit.rule,
          error: normalized,
          hint: primaryHint,
          context: excerpt
        });
      }

      core.info(`CI Explainer: ${job.name} -> step="${hit.stepName}" rule="${hit.rule}" line="${normalized}"`);
    }

    if (commentOnPR && prNumbers.length > 0) {
      const body = `${CI_FAILURE_MARKER}\n` + summaryParts.join("\n");
      for (const prNumber of prNumbers.slice(0, 3)) {
        const c = await upsertComment(octokit, { owner, repo, issue_number: prNumber, body });
        core.info(`PR #${prNumber} comment ${c.updated ? "updated" : "created"}: ${c.url}`);
      }
    }

    if (jsonOutput) {
      core.setOutput("failures_json", JSON.stringify(jsonResults));
      core.info(`Exported ${jsonResults.length} failure(s) as JSON.`);
    }
  } catch (err) {
    core.setFailed(err?.message || String(err));
  }
}

run();