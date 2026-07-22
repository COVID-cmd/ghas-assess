# ghas-assess

> Read-only **GitHub Advanced Security (GHAS) posture assessment** — connect to a GitHub
> organisation, inspect the effective GHAS configuration and alert state per repository, and
> get a prioritised gap report in your terminal, plus JSON, HTML and Word.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![Read-only](https://img.shields.io/badge/access-read--only-green)

`ghas-assess` never changes anything. Every API call is a `GET`. It's meant for security
teams, consultants and platform engineers who have turned GHAS *on* and want to know how far
from *enforced and effective* they actually are.

---

## Why

Enabling GHAS is one click. Knowing whether it's actually protecting you is not. Dashboards
show green while push protection is off on the repo that matters, criticals sit unowned for
months, and a "required" code-scanning check gates nothing because no ruleset consumes it.
This tool walks an org and reports those gaps against a practical **16-point checklist**.

---

## Quick start

```bash
pip install ghas-assess          # or: pip install -r requirements.txt

# See sample output immediately — no token needed
ghas-assess --demo --formats terminal,html,docx --out ./sample

# Run against a real org
export GITHUB_TOKEN=ghp_your_token
ghas-assess --org my-org --formats terminal,json,html,docx --out ./assessment
```

Not published to PyPI yet? Run from source:

```bash
git clone https://github.com/<you>/ghas-assess && cd ghas-assess
python -m ghas_assess --demo
```

GitHub Enterprise Server:

```bash
ghas-assess --org my-org --api-url https://ghe.example.com/api/v3
```

---

## Authentication

A **fine-grained Personal Access Token** is the simplest option and works anywhere. For
scaled/multi-org use, a **GitHub App** is cleaner (higher rate limits, org-installable,
no personal token) — see the roadmap.

Minimum **read-only** permissions:

| Fine-grained permission        | Enables |
|--------------------------------|---------|
| Metadata (Read)                | list repositories |
| Administration (Read)          | rulesets / branch protection / `security_and_analysis` |
| Contents (Read)                | detect `dependabot.yml` |
| Code scanning alerts (Read)    | alert severity, query suite, backlog age |
| Dependabot alerts (Read)       | dependency alerts and update config |
| Secret scanning alerts (Read)  | secret alert counts |
| Org · Advanced security (Read) | config coverage, custom secret patterns |

Classic PAT equivalent: `repo`, `read:org`, `security_events`.

**Never commit a token or paste it into a shared terminal. Rotate any token that is exposed.**

---

## What it checks

`ghas-assess` evaluates **26 best-practice checks across 6 categories**. For every check the
report shows: the current state (**what is configured**), the **best practice** (what should
be), and the **why** (the risk if it isn't) — plus the concrete fix for anything that's a gap.

| Category | Checks include |
|----------|----------------|
| **Secret Protection** | push protection, AI-detected secrets, custom patterns, push-protection bypasses |
| **Code Scanning** | CodeQL extended suite, code-scanning required to merge, Copilot Autofix, scheduled scans |
| **Dependencies** | Dependabot alerts, update management (dependabot.yml), automatic submission, access scope |
| **Enforcement** | default-branch PR requirement, required reviews |
| **Governance** | unresolved critical/high alerts, stale backlog, dismissal review, stored-secret review |
| **Organisation** | security-configuration coverage, org-wide 2FA, security policy (SECURITY.md), Code Quality |

Each check is tagged by how its state is determined:

**AUTO** = determined from the API. **PARTIAL** = the API gives a signal, confirm the nuance.
**MANUAL** = not exposed by the API, so the tool flags it for UI verification rather than
guessing. A MANUAL row is a checklist item, not a false pass — that honesty is deliberate.

> GitHub's API surface changes. Some MANUAL checks may become AUTO over time; contributions
> that promote them are very welcome (see CONTRIBUTING).

### Evaluating the MANUAL settings too

Settings GitHub doesn't expose via API don't have to stay unevaluated. The tool can emit a
**checklist** for them (with the exact UI path for each), you record `gap`/`ok`/`na` once, and
re-run to merge those verdicts into the report — so every one of the 16 findings ends with a
real answer, nothing left as "MANUAL".

```bash
# 1. generate the checklist for your org (lists every API-invisible setting + where to look)
ghas-assess --org my-org --emit-checklist manual.ini

# 2. open manual.ini, set each 'unknown' to gap / ok / na  (comments show where to look)

# 3. re-run, merging your answers in
ghas-assess --org my-org --manual-answers manual.ini --formats terminal,html,docx --out ./assessment
```

Answers can be org-wide (`[org]`), applied to all repos (`[repo:default]`), or per-repo
(`[repo:<name>]`). The file is plain INI with `#` comments — hand-editable, no extra tooling.

Two of the MANUAL items (**ORG-CONFIG-COVERAGE**, **SECRET-CUSTOM-PATTERNS**) are actually API-visible and
become **AUTO** as soon as your token has org **Advanced security (Read)** permission — no
checklist needed for those.

---

## Output

- `terminal` — colour table, gaps first by severity
- `json` — full results incl. raw evidence, for pipelines/dashboards
- `html` — styled shareable report
- `docx` — Word report

Exit code is **1** when any High/Critical gap is found (useful as a CI gate), else 0.

### Sharing the report

The HTML report is a single self-contained file (chart and styles inline), so you can:
- **Open or email it** - double-click, or drop it in SharePoint/Teams/Slack. No server needed.
- **Publish to GitHub Pages** - the workflow has an optional `publish` job that pushes the HTML
  dashboard to a Pages URL on each run. **Keep the repo private** so the report stays behind your
  org login - a GHAS gap report is a map of your weaknesses and should never be world-readable.
- **Download from Actions** - the scheduled run uploads the report as an artifact.

For a PDF, open the HTML in a browser (or the .docx in Word) and Print > Save as PDF.

### Run in CI

A ready-to-use workflow lives at [`.github/workflows/ghas-assess.yml`](.github/workflows/ghas-assess.yml):
it runs weekly, uploads the reports as artifacts, and fails on High/Critical gaps.

---

## Roadmap

- Publish to PyPI
- GitHub App authentication
- Promote MANUAL checks to AUTO as endpoints appear (dismissal settings, dependency submission, Code Quality)
- Trend mode: diff against a previous JSON run to show improvement over time
- Optional exporters (SARIF, Defender for Cloud, DefectDojo)
- Declarative policy file: assert a target state, fail on drift

---

## Contributing

Issues and PRs welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). Good first contributions:
new checks, promoting a MANUAL check to AUTO, additional output formats, GHES compatibility fixes.

## Security

Report vulnerabilities privately — see [SECURITY.md](SECURITY.md). The tool is strictly
read-only and has no write/delete/patch code path.

## License

[MIT](LICENSE) — free to use, modify and distribute.

## Acknowledgements

The 16-point checklist distils common findings from real-world secure-SDLC assessments. It is
not affiliated with or endorsed by GitHub or Microsoft. "GitHub" and "GitHub Advanced Security"
are trademarks of their respective owners.
