# AI Git Code Reviewer

A GitHub-first code review project that scans pull-request diffs for risky patterns, produces Markdown/JSON findings, and optionally uses an OpenAI-compatible API for a second-pass review. **No Jenkins dependency.** Rules-based review works without API keys or third-party Python packages.

## Features
- GitHub Actions workflow for pull requests plus manual review runs
- Flags destructive SQL, dangerous shell commands, weak authentication/TLS, credential-like assignments, and infrastructure/security changes
- Risk triage score, recommendations, and changed-file statistics
- Optional AI enrichment via AI_API_KEY, AI_BASE_URL, and AI_MODEL
- JSON/Markdown reports uploaded as workflow artifacts
- Review summary comment on same-repository pull requests
- Secret-like values redacted in rule-based finding excerpts
- Python unit tests

## Run locally (Python 3.10+)
```bash
python -m unittest discover -s tests -v
python -m reviewer.review --base HEAD~1 --head HEAD --out-dir review-results
python -m reviewer.review --diff-file sample/example.diff --out-dir review-results
```

To enable AI, set AI_API_KEY as an environment secret and add --use-ai. Configure AI_BASE_URL and AI_MODEL for compatible providers. Never commit keys or send proprietary code to an external service without approval.

## GitHub Actions
Workflow: .github/workflows/ai-code-review.yml. It checks out the PR, runs tests, analyzes the diff, uploads reports, and comments on same-repository PRs. Fork PRs can run analysis but GitHub restricts their secrets and write permissions, so comments are limited to same-repository PRs.

## Limitations
This is an educational triage tool, not a full static analyzer or security certification. Rules can miss issues and create false positives; AI can also be wrong. Keep human review, tests, branch protection, and dedicated security tooling in place.
