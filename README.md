# Explain CI Failure

CI Failure Explainer is a small GitHub Action that turns noisy CI logs into a human-readable failure summary.

Instead of scrolling through thousands of lines of logs, the action:
- detects which job and step failed
- extracts the first meaningful error
- classifies the failure (ESLint, TypeScript, Jest, npm, Docker, etc.)
- shows context and likely fixes in the GitHub Actions Summary

The scope is intentionally small. This is meant to remove friction, not introduce a new platform.

## Problem

CI failures waste time because:
- logs are verbose and poorly structured
- the real error is usually buried
- the same failures repeat across runs
- engineers keep rediscovering the same issues

This action optimizes for the first minute after a CI failure.

## What the Action Does

For failed workflow runs, the action:
1. Detects failed jobs
2. Downloads job logs (ZIP or plain text)
3. Identifies the first meaningful error
4. Infers the failing step name (best effort, log-based)
5. Classifies the failure type
6. Writes a concise explanation to the GitHub Actions Step Summary

There is:
- no blocking behavior
- no configuration required

## Example Output

CI Explainer

Failed job: test-and-build  
Failing step: Run npm run lint  
Detected type: ESLint  

First error:  
src/foo.ts:<line>:<col> error Unexpected any. Specify a different type.

Likely fix:  
Run the linter locally and apply the suggested fix.

Context:  
... surrounding log lines ...

## Usage

Add the action after your main CI job and run it only when that job fails.

```yaml
jobs:
  test-and-build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm ci
      - run: npm run lint
      - run: npm test

  explain:
    needs: [test-and-build]
    if: ${{ always() && needs.test-and-build.result == 'failure' }}
    runs-on: ubuntu-latest
    steps:
      - name: Explain CI failure
        uses: lukekania/explain-ci-failure@v0.1.5
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
```

## Supported Error Types

Currently optimized for common CI stacks:
- ESLint
- TypeScript (tsc)
- npm / pnpm / yarn
- Jest / Vitest
- Vite / Webpack builds
- Docker build failures
- Generic Node.js runtime errors
- pytest / mypy / ruff / flake8 / pip (Python)
- go test / golangci-lint / go build (Go)

If no rule matches, the action falls back to a generic error detector.

## Design Principles

- Zero configuration
- Heuristics over machine learning
- Explain the first error, not every error
- Reduce cognitive load
- Stay out of the way

## Known Limitations

- Step detection is log-based and best effort
- PR comments are opt-in via `comment_on_pr`
- No merge blocking
- No deep root-cause analysis

## Possible Future Features

- Repository-specific rule packs
- Flaky test detection across runs
- Failure deduplication (seen before)
- Auto-linking errors to docs or runbooks
- Reviewer suggestions based on failing files
- Deploy-risk correlation
- Time-to-fix metrics per error type
- Support for additional stacks (Java)

## Why This Exists

Most CI failures are boring, repetitive, and predictable.

They should not cost minutes of attention every single time.

This action removes friction from a daily annoyance.

## License

MIT
