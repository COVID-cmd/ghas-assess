# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/); versions use SemVer.

## [2.8.0] - 2026-07-22
### Added
- "How to read this report" status legend (GAP / OK / MANUAL / INFO, plus severity meaning) at the top of the Detailed findings tab in HTML and in the Word report, so any reader understands the statuses.

## [2.7.0] - 2026-07-22
### Fixed
- Corrected the affected-repository count on the priority list (previously always showed 1; now shows the true number of repos each finding affects, e.g. 9/9).
### Changed
- Replaced "Fix these first" with a management-grade **Priority remediation plan**: ordered by severity then blast radius, with an estate-impact bar (how many repos affected), and a fix-type tag distinguishing one-change **org-wide fixes** from per-repo work.
- Added an **Org-wide quick wins** headline stat and a **stacked gap-severity-by-category** chart (High/Medium/Low) in place of the flat category bars.

## [2.6.0] - 2026-07-22
### Changed
- Redesigned the dashboard: a hero posture-score gauge (0-100, colour-banded), colour-accented stat tiles, panelled sections, and a cleaner category/repo layout. Far more scannable at a glance.

## [2.5.0] - 2026-07-22
### Changed
- Renamed all finding IDs to readable, category-based codes (e.g. SECRET-PUSH-PROTECTION, ENF-PR-REQUIRED, ORG-CONFIG-COVERAGE) so the report is self-explanatory for any user. Reports, checklist and manual-answers files now use the new IDs.

## [2.4.0] - 2026-07-22
### Added
- Tabbed HTML report: a **Dashboard** tab (metric cards, severity chips, radar chart, gaps-by-category bars, per-repository posture ranking worst-first, and the most-urgent findings) plus a **Detailed findings** tab with everything else.
- README guidance on sharing the report (file/email, GitHub Pages behind private access, Actions artifact) and producing a PDF.
- Optional GitHub Pages publish job in the workflow (commented; repo must stay private).

## [2.3.0] - 2026-07-22
### Added
- "Checks performed" section in HTML and Word reports: the full catalogue of checks run, grouped by category, with each check's scope, how it is determined (AUTO/PARTIAL/MANUAL), and its results this run - plus a coverage summary (distinct checks, total evaluations, counts by status).

## [2.2.0] - 2026-07-22
### Added
- Base feature-enablement checks so the report confirms the fundamentals are ON, not just sub-config gaps: Secret scanning enabled (F23), Code scanning/CodeQL enabled (F24), Dependency graph enabled (F25). Now 26 checks.

## [2.1.0] - 2026-07-22
### Added
- Three new checks: push-protection bypass activity (F21), dismissal-review workflow in use (F13B), and stored Actions/agent secrets review (F22) - now 23 checks.
- HTML/Word reports gained: a "What is already configured" section (shows what is correct, not just gaps), a radar chart of gaps-by-category, and per-gap evidence ("Why flagged") showing the raw value that triggered each finding.

## [2.0.0] - 2026-07-22
### Changed
- Reworked into a comprehensive best-practice framework: 20 checks across 6 categories.
- Every finding now carries a best-practice target and a plain-language WHY (risk rationale).
- Reports (terminal, HTML, DOCX, JSON) group findings by category and show what-is / what-should-be / why.
### Added
- New checks: org-wide 2FA (F17), security policy / SECURITY.md (F18), Dependabot alerts enabled (F19), required PR reviews (F20).

## [1.1.0] - 2026-07-22
### Added
- Manual evaluation layer: `--emit-checklist` writes a checklist (with UI paths) for settings
  not exposed by the API; `--manual-answers` merges filled-in gap/ok/na verdicts into the report.
- Every finding can now reach a real verdict; nothing need remain "MANUAL".

## [1.0.0] - 2026-07-22
### Added
- Initial public release.
- Read-only assessment across 16 GHAS posture checks (F1–F16).
- Org-level checks: coverage, custom secret patterns; repo-level: push protection,
  AI-detected secrets, rulesets/enforcement, dependabot.yml, alert severity and age.
- Output formats: terminal, JSON, HTML, DOCX.
- `--demo` mode with fictional sample data (no token required).
- GitHub Action workflow for scheduled assessment.
- CI-friendly exit code (non-zero on High/Critical gaps).
