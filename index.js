const core = require("@actions/core");
const github = require("@actions/github");
const crypto = require("crypto");
const fs = require("fs");
const AdmZip = require("adm-zip");

function toBool(s, def) {
  if (s === undefined || s === null || s === "") return def;
  return /^(true|yes|1|on)$/i.test(String(s).trim());
}

const CI_FAILURE_MARKER = "<!-- ci-failure-explainer:v0 -->";

const RUNBOOK_SLUGS = {
  ESLint: "eslint",
  TypeScript: "typescript",
  npm: "npm",
  "Jest/Vitest": "jest",
  Build: "build",
  Docker: "docker",
  Node: "node",
  pytest: "pytest",
  mypy: "mypy",
  "ruff/flake8": "ruff",
  pip: "pip",
  Go: "go",
  Java: "java",
  Maven: "maven",
  Gradle: "gradle",
  JUnit: "junit",
  Generic: "generic"
};

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

function parseCustomRules(raw) {
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed
      .filter((r) => r.name && r.pattern)
      .map((r) => ({ name: r.name, re: new RegExp(r.pattern, "i"), hint: r.hint || "" }));
  } catch {
    return [];
  }
}

function pickFirstMeaningfulError(lines, customRules = []) {
  // Custom rules take priority
  const rules = [
    ...customRules.map((r) => ({ name: r.name, re: r.re })),
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

    // Java: compilation
    { name: "Java", re: /error:\s+.*java/i },
    { name: "Java", re: /\bjavac\b.*error/i },
    { name: "Java", re: /COMPILATION ERROR/i },

    // Java: Maven
    { name: "Maven", re: /\[ERROR\].*BUILD FAILURE/i },
    { name: "Maven", re: /\[ERROR\].*Failed to execute goal/i },

    // Java: Gradle
    { name: "Gradle", re: /FAILURE: Build failed/i },
    { name: "Gradle", re: /Execution failed for task/i },

    // Java: JUnit
    { name: "JUnit", re: /Tests run:.*Failures: [1-9]/i },
    { name: "JUnit", re: /\bFAILURE!\b.*Tests run/i },

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

function hintFor(ruleName, customRules = []) {
  const custom = customRules.find((r) => r.name === ruleName);
  if (custom && custom.hint) return [custom.hint, ""];

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
    Java: [
      "Check the referenced file/line for the compilation error; fix type mismatches or missing imports.",
      "Verify Java version compatibility between source and CI environment."
    ],
    Maven: [
      "Run `mvn clean install` locally to reproduce; check dependency resolution and plugin versions.",
      "If it's a dependency issue, run `mvn dependency:tree` to identify conflicts."
    ],
    Gradle: [
      "Run the failing task locally with `--stacktrace` for details.",
      "Check Gradle wrapper version and dependency resolution in `build.gradle`."
    ],
    JUnit: [
      "Run the failing test class locally; focus on the first assertion failure.",
      "Check for test order dependencies and shared state between tests."
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

// -------------------- Deploy risk --------------------

const DEPLOY_RISK = {
  Docker: "high",
  Build: "high",
  npm: "high",
  Maven: "high",
  Gradle: "high",
  TypeScript: "medium",
  "Jest/Vitest": "medium",
  JUnit: "medium",
  pytest: "medium",
  Go: "medium",
  Java: "medium",
  Node: "medium",
  ESLint: "low",
  "ruff/flake8": "low",
  mypy: "low",
  pip: "medium",
  Generic: "medium"
};

function getDeployRisk(ruleName) {
  return DEPLOY_RISK[ruleName] || "medium";
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

function findFirstErrorInText({ text, fileName, customRules }) {
  const lines = text.split(/\r?\n/);
  const stepStarts = buildStepIndex(lines);
  const hit = pickFirstMeaningfulError(lines, customRules);
  if (!hit) return null;

  const stepName = findStepForLineIndex(stepStarts, hit.lineIndex);
  return { ...hit, stepName, fileName };
}

function findFirstErrorAcrossTexts(textFiles, customRules) {
  for (const f of textFiles) {
    const hit = findFirstErrorInText({ text: f.text, fileName: f.name, customRules });
    if (hit) return hit;
  }
  return null;
}

// -------------------- Deduplication --------------------

function sha1(s) {
  return crypto.createHash("sha1").update(String(s)).digest("hex");
}

async function findPatternIssue(octokit, { owner, repo, hash, label }) {
  const q = `repo:${owner}/${repo} is:issue in:title "${hash}" label:${label}`;
  const found = await octokit.rest.search.issuesAndPullRequests({ q, per_page: 5 });
  if (found.data.items.length > 0) {
    return found.data.items[0].html_url;
  }
  return null;
}

// -------------------- Flaky detection --------------------

function clampInt(val, def, min, max) {
  const n = parseInt(String(val ?? def), 10);
  if (!Number.isFinite(n)) return def;
  return Math.max(min, Math.min(max, n));
}

async function detectFlaky(octokit, { owner, repo, workflowId, jobName, lookback }) {
  // Fetch recent runs for the same workflow
  const params = { owner, repo, per_page: lookback, status: "completed" };
  if (workflowId) params.workflow_id = workflowId;

  const runs = await octokit.rest.actions.listWorkflowRunsForRepo(params);

  let passes = 0;
  let failures = 0;

  for (const run of runs.data.workflow_runs.slice(0, lookback)) {
    const jobsResp = await octokit.rest.actions.listJobsForWorkflowRun({
      owner, repo, run_id: run.id, per_page: 100
    });

    const matchingJob = jobsResp.data.jobs.find((j) => j.name === jobName);
    if (!matchingJob) continue;

    if (matchingJob.conclusion === "success") passes++;
    else if (matchingJob.conclusion === "failure") failures++;
  }

  // Flaky = fails sometimes and passes sometimes in recent history
  const isFlaky = passes >= 2 && failures >= 2;
  return { isFlaky, passes, failures, total: passes + failures };
}

// -------------------- Time-to-fix metrics --------------------

async function computeTimeToFix(octokit, { owner, repo, label }) {
  // Find closed pattern issues and compute median time from first occurrence to close
  const q = `repo:${owner}/${repo} is:issue is:closed label:${label}`;
  const result = await octokit.rest.search.issuesAndPullRequests({ q, per_page: 50 });

  const fixTimes = {};

  for (const item of result.data.items) {
    const closedAt = new Date(item.closed_at);

    // Infer error type from title: [CI Pattern hash] TypeScript: ...
    const typeMatch = item.title.match(/\]\s*(\w[\w/]*?):/);
    const errorType = typeMatch ? typeMatch[1] : "Generic";

    const createdAt = new Date(item.created_at);
    const hours = Math.round((closedAt - createdAt) / 3600000);

    if (!fixTimes[errorType]) fixTimes[errorType] = [];
    fixTimes[errorType].push(hours);
  }

  // Compute median for each type
  const medians = {};
  for (const [type, times] of Object.entries(fixTimes)) {
    times.sort((a, b) => a - b);
    const mid = Math.floor(times.length / 2);
    medians[type] = times.length % 2 === 0
      ? Math.round((times[mid - 1] + times[mid]) / 2)
      : times[mid];
  }

  return medians;
}

function formatFixTime(hours) {
  if (hours < 1) return "<1h";
  if (hours < 24) return `${hours}h`;
  const days = Math.round(hours / 24);
  return `${days}d`;
}

// -------------------- Reviewer suggestions --------------------

function extractFilePaths(errorLine, excerpt) {
  // Extract file paths from error lines (e.g., src/foo.ts:42:10, ./src/bar.js)
  const pathRe = /(?:^|\s|['"`])((?:\.\/)?(?:[\w.-]+\/)*[\w.-]+\.[a-zA-Z]{1,5})(?::\d+)?/g;
  const paths = new Set();
  const sources = [errorLine, ...(excerpt || [])];

  for (const line of sources) {
    let m;
    while ((m = pathRe.exec(line || "")) !== null) {
      const p = m[1].replace(/^\.\//, "");
      // skip common non-file patterns
      if (!/\.(js|ts|jsx|tsx|py|go|java|rb|rs|css|scss|vue|svelte)$/i.test(p)) continue;
      paths.add(p);
    }
  }

  return [...paths].slice(0, 5);
}

async function suggestReviewersForFiles(octokit, { owner, repo, filePaths, prAuthor }) {
  const authorCounts = new Map();

  for (const filePath of filePaths) {
    try {
      const commits = await octokit.rest.repos.listCommits({
        owner, repo, path: filePath, per_page: 10
      });

      for (const c of commits.data) {
        const login = c.author?.login;
        if (!login || login === prAuthor || login.includes("[bot]")) continue;
        authorCounts.set(login, (authorCounts.get(login) || 0) + 1);
      }
    } catch {
      // file may not exist in default branch
    }
  }

  return [...authorCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 3)
    .map(([login, commits]) => ({ login, commits }));
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
    const checkPatterns = toBool(core.getInput("check_patterns"), false);
    const patternLabel = core.getInput("pattern_label") || "ci-failure-pattern";
    const runbookUrl = (core.getInput("runbook_url") || "").replace(/\/+$/, "");
    const customRules = parseCustomRules(core.getInput("custom_rules"));
    const flakyDetection = toBool(core.getInput("flaky_detection"), false);
    const flakyLookback = clampInt(core.getInput("flaky_lookback"), 10, 3, 30);
    const suggestReviewers = toBool(core.getInput("suggest_reviewers"), false);
    const showDeployRisk = toBool(core.getInput("deploy_risk"), false);

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

    let fixTimeMedians = {};
    if (checkPatterns) {
      try {
        fixTimeMedians = await computeTimeToFix(octokit, { owner, repo, label: patternLabel });
      } catch {
        // time-to-fix is best-effort
      }
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
        hit = findFirstErrorAcrossTexts(textFiles, customRules);
      } else {
        core.info(`CI Explainer: job ${job.id} logs=text (${payload.contentType || "?"})`);
        hit = findFirstErrorInText({ text: payload.text, fileName: `job-${job.id}.log`, customRules });
      }

      if (!hit) {
        appendStepSummary(`- No obvious error signature found (rules too limited or logs too noisy).\n\n`);
        continue;
      }

      const normalized = normalize(hit.line);
      const [primaryHint, secondaryHint] = hintFor(hit.rule, customRules);
      const excerpt = (hit.excerpt || []).slice(0, 16).map(normalize).join("\n");

      appendStepSummary(`- Failing step: **${hit.stepName}**\n`);
      appendStepSummary(`- Detected type: **${hit.rule}**\n`);
      if (showDeployRisk) {
        appendStepSummary(`- Deploy risk: **${getDeployRisk(hit.rule)}**\n`);
      }
      if (fixTimeMedians[hit.rule] !== undefined) {
        appendStepSummary(`- Typical fix time: **${formatFixTime(fixTimeMedians[hit.rule])}**\n`);
      }
      appendStepSummary(`- Source log: \`${hit.fileName}\`\n`);
      appendStepSummary(`- First error (normalized):${codeBlock(normalized)}\n`);
      appendStepSummary(`- Likely fix: ${primaryHint}\n`);
      if (secondaryHint) appendStepSummary(`- Also check: ${secondaryHint}\n`);

      if (runbookUrl) {
        const runbookSlug = RUNBOOK_SLUGS[hit.rule] || hit.rule.toLowerCase().replace(/[^a-z0-9]+/g, "-");
        appendStepSummary(`- [Runbook](${runbookUrl}/${runbookSlug})\n`);
      }

      let patternLink = null;
      if (checkPatterns) {
        const signature = `${hit.rule}: ${normalized}`;
        const hash = sha1(signature).slice(0, 8);
        patternLink = await findPatternIssue(octokit, { owner, repo, hash, label: patternLabel });
        if (patternLink) {
          appendStepSummary(`- Seen before — tracking issue: ${patternLink}\n`);
        }
      }

      let flakyNote = "";
      if (flakyDetection) {
        try {
          const flakyResult = await detectFlaky(octokit, {
            owner, repo, workflowId: null, jobName: job.name, lookback: flakyLookback
          });
          if (flakyResult.isFlaky) {
            const msg = `Likely flaky (${flakyResult.failures}/${flakyResult.total} recent runs failed)`;
            appendStepSummary(`- **${msg}**\n`);
            flakyNote = `- **${msg}**\n`;
            core.warning(`${job.name}: ${msg}`);
          }
        } catch {
          // flaky detection is best-effort
        }
      }

      let reviewerNote = "";
      if (suggestReviewers) {
        try {
          const filePaths = extractFilePaths(hit.line, hit.excerpt);
          if (filePaths.length > 0) {
            const prAuthor = github.context.payload?.pull_request?.user?.login || "";
            const suggestions = await suggestReviewersForFiles(octokit, { owner, repo, filePaths, prAuthor });
            if (suggestions.length > 0) {
              const names = suggestions.map((s) => `@${s.login} (${s.commits} commits)`).join(", ");
              appendStepSummary(`- Suggested reviewers: ${names}\n`);
              reviewerNote = `- Suggested reviewers: ${names}\n`;
            }
          }
        } catch {
          // reviewer suggestion is best-effort
        }
      }

      appendStepSummary(`- Context:${codeBlock(excerpt)}\n`);

      const riskLine = showDeployRisk ? `- Deploy risk: **${getDeployRisk(hit.rule)}**\n` : "";
      const fixTimeLine = fixTimeMedians[hit.rule] !== undefined
        ? `- Typical fix time: **${formatFixTime(fixTimeMedians[hit.rule])}**\n`
        : "";
      let partBlock =
        `- Failing step: **${hit.stepName}**\n` +
        `- Detected type: **${hit.rule}**\n` +
        riskLine +
        fixTimeLine +
        `- First error:${codeBlock(normalized)}\n` +
        `- Likely fix: ${primaryHint}\n`;
      if (patternLink) {
        partBlock += `- Seen before — tracking issue: ${patternLink}\n`;
      }
      if (runbookUrl) {
        const slug = RUNBOOK_SLUGS[hit.rule] || hit.rule.toLowerCase().replace(/[^a-z0-9]+/g, "-");
        partBlock += `- [Runbook](${runbookUrl}/${slug})\n`;
      }
      partBlock += flakyNote;
      partBlock += reviewerNote;
      summaryParts.push(partBlock);

      if (jsonOutput) {
        jsonResults.push({
          job: job.name,
          step: hit.stepName,
          errorType: hit.rule,
          error: normalized,
          hint: primaryHint,
          context: excerpt,
          flakyNote: flakyNote ? flakyNote.trim() : ""
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