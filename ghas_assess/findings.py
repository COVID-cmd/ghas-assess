"""
GHAS security best-practice catalogue.

A comprehensive, vendor-neutral checklist of GitHub Advanced Security settings, grouped
into categories. Each check declares WHAT good looks like, and WHY it matters, so the report
can explain not just the gap but the reason to close it.

Fields per check:
  category    - grouping (Secret Protection, Code Scanning, Dependencies, Enforcement,
                Governance, Organisation)
  title       - short name
  scope       - 'org' or 'repo'
  automation  - AUTO / PARTIAL / MANUAL (how the state is determined)
  default_severity - severity if the check fails
  best_practice - the target state (what SHOULD be configured)
  why         - the risk/rationale (why it needs to be configured)
  improvement - the concrete action to take

The tool is strictly read-only: it reports state and guidance, it never changes settings.
"""

AUTO, PARTIAL, MANUAL = "AUTO", "PARTIAL", "MANUAL"
OK, GAP, INFO, UNKNOWN = "OK", "GAP", "INFO", "UNKNOWN"
SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}

CATEGORIES = [
    "Secret Protection", "Code Scanning", "Dependencies",
    "Enforcement", "Governance", "Organisation",
]

FINDINGS = {
    # ---------------- Secret Protection ----------------
    "SECRET-PUSH-PROTECTION": dict(
        category="Secret Protection", title="Push protection enabled",
        scope="repo", automation=AUTO, default_severity="High",
        best_practice="Push protection ON, so secrets are blocked before they enter git history.",
        why="Without push protection, a leaked credential is only detected AFTER it is committed - "
            "by then it must be treated as compromised and rotated. Blocking at push time prevents "
            "the exposure entirely.",
        improvement="Enable push protection (ideally enforced via the org security configuration so "
                    "it cannot be turned off per repo).",
    ),
    "SECRET-AI-DETECTION": dict(
        category="Secret Protection", title="AI-detected secrets enabled",
        scope="repo", automation=AUTO, default_severity="Medium",
        best_practice="AI/non-provider secret detection ON, in addition to pattern matching.",
        why="Regex patterns only catch credentials with a known shape. Hardcoded passwords, "
            "connection strings and home-grown tokens have no fixed format and slip through - "
            "AI detection covers that residual class.",
        improvement="Enable AI-detected secrets; measure detection quality on a pilot repo first.",
    ),
    "SECRET-CUSTOM-PATTERNS": dict(
        category="Secret Protection", title="Custom secret patterns defined",
        scope="org", automation=PARTIAL, default_severity="Medium",
        best_practice="Custom patterns defined for organisation-specific credential formats.",
        why="Built-in patterns cover public cloud/SaaS tokens. Internal API keys and service "
            "credentials unique to your organisation are invisible to them and leak silently.",
        improvement="Define custom patterns (dry-run first, then enforce) for your internal formats.",
    ),
    # ---------------- Code Scanning ----------------
    "CODE-EXTENDED-SUITE": dict(
        category="Code Scanning", title="CodeQL extended query suite",
        scope="repo", automation=PARTIAL, default_severity="Medium",
        best_practice="security-extended query suite enabled where a triage capability exists.",
        why="The default suite favours precision and omits lower-severity/lower-precision queries. "
            "Real vulnerabilities in those classes are never surfaced, understating true risk.",
        improvement="Enable the security-extended suite; measure the findings delta before rollout.",
    ),
    "CODE-REQUIRED-CHECK": dict(
        category="Code Scanning", title="Code scanning required to merge",
        scope="repo", automation=AUTO, default_severity="High",
        best_practice="A ruleset requires the code-scanning check to pass at a set severity threshold.",
        why="Scanning without enforcement is advisory only. If findings don't gate the pull request, "
            "code with known criticals merges and is discovered later in the backlog.",
        improvement="Create a ruleset requiring the code-scanning check on protected branches.",
    ),
    "CODE-SCHEDULED-SCANS": dict(
        category="Code Scanning", title="Scheduled scans for inactive repos",
        scope="org", automation=MANUAL, default_severity="Low",
        best_practice="30-day scheduled scans kept running for inactive repositories.",
        why="Dormant code stops being scanned after 6 months of inactivity, so newly disclosed "
            "vulnerability classes are never applied to it - the code is unchanged but the threat "
            "landscape is not.",
        improvement="Enable scheduled scans for inactive repositories (org code-security setting).",
    ),
    # ---------------- Dependencies ----------------
    "DEP-ALERTS-ENABLED": dict(
        category="Dependencies", title="Dependabot alerts enabled",
        scope="repo", automation=AUTO, default_severity="High",
        best_practice="Dependabot vulnerability alerts enabled on every repository.",
        why="Most breaches exploit known-vulnerable dependencies. Without alerts you have no "
            "visibility of which of your dependencies carry published CVEs.",
        improvement="Enable Dependabot alerts (and the dependency graph that feeds them).",
    ),
    "DEP-UPDATE-CONFIG": dict(
        category="Dependencies", title="Dependabot update management",
        scope="repo", automation=AUTO, default_severity="Medium",
        best_practice="A dependabot.yml with grouped updates, a schedule and PR limits.",
        why="Without grouping, every vulnerable package raises its own PR; developers facing a wall "
            "of PRs ignore them all, so fixes stall and alerts age.",
        improvement="Add a dependabot.yml defining ecosystems, schedule, grouping and PR limits.",
    ),
    "DEP-AUTO-SUBMISSION": dict(
        category="Dependencies", title="Automatic dependency submission",
        scope="repo", automation=MANUAL, default_severity="Low",
        best_practice="Automatic dependency submission on for compiled ecosystems.",
        why="For compiled languages, build-time and transitive dependencies aren't visible from "
            "manifests alone. If the graph can't see a dependency, Dependabot can't alert on it.",
        improvement="Add the dependency-submission action to the build for compiled ecosystems.",
    ),
    "DEP-ACCESS-SCOPE": dict(
        category="Dependencies", title="Dependabot repository access scope",
        scope="org", automation=MANUAL, default_severity="Medium",
        best_practice="Dependabot access includes all repositories that need dependency updates.",
        why="If access is limited to public/internal only, private repositories silently sit "
            "outside dependency update flows - no error, just absent alerts.",
        improvement="Confirm scope; add private repos explicitly if any are excluded.",
    ),
    # ---------------- Enforcement ----------------
    "ENF-PR-REQUIRED": dict(
        category="Enforcement", title="Default branch requires pull requests",
        scope="repo", automation=AUTO, default_severity="High",
        best_practice="Protected default branch: PRs required, no direct pushes.",
        why="Direct pushes to the default branch bypass review and all PR-gated security checks - "
            "unreviewed, unscanned code reaches production.",
        improvement="Require pull requests (and block direct pushes) via a ruleset or branch protection.",
    ),
    "ENF-REVIEWS-REQUIRED": dict(
        category="Enforcement", title="Pull request reviews required",
        scope="repo", automation=AUTO, default_severity="Medium",
        best_practice="At least one required approving review before merge.",
        why="Peer review is a primary control against both mistakes and malicious changes; without "
            "it a single actor can merge anything.",
        improvement="Require >=1 approving review in the branch ruleset/protection.",
    ),
    # ---------------- Governance ----------------
    "GOV-NO-OPEN-CRITICALS": dict(
        category="Governance", title="No unresolved critical/high alerts",
        scope="repo", automation=AUTO, default_severity="High",
        best_practice="No open critical/high alerts left undispositioned.",
        why="Open criticals are the alerts most likely to be actively exploited; leaving them "
            "unowned is the single clearest measure of unmanaged risk.",
        improvement="Remediate or formally risk-accept every critical/high, starting with the most "
                    "concentrated repositories.",
    ),
    "GOV-BACKLOG-FRESH": dict(
        category="Governance", title="Alert backlog not stale",
        scope="repo", automation=AUTO, default_severity="Medium",
        best_practice="Alerts closed within severity-based SLAs; backlog does not age.",
        why="A rising average alert age means the easy fixes are done and a stale residue is "
            "accumulating and normalising - 'those alerts have always been there'.",
        improvement="Set severity-based SLAs and assign alert ownership.",
    ),
    "GOV-DISMISSAL-CONTROL": dict(
        category="Governance", title="Direct alert dismissals prevented",
        scope="repo", automation=MANUAL, default_severity="High",
        best_practice="'Prevent direct alert dismissals' on for all three scanners.",
        why="If anyone can self-dismiss an alert with no review, dismissals become invisible and "
            "every closure metric becomes untrustworthy - reductions may be dismissals, not fixes.",
        improvement="Enable 'prevent direct alert dismissals'; route dismissals through review.",
    ),
    # ---------------- Organisation ----------------
    "ORG-CONFIG-COVERAGE": dict(
        category="Organisation", title="Security configuration coverage",
        scope="org", automation=PARTIAL, default_severity="High",
        best_practice="Every active repository attached to a security configuration; default for new.",
        why="A '100% protected' dashboard is meaningless if some repositories aren't attached at "
            "all - unattached repos are unscanned code with zero visibility.",
        improvement="Attach the org security configuration to every active repo; set as default.",
    ),
    "ORG-2FA-REQUIRED": dict(
        category="Organisation", title="Two-factor authentication required",
        scope="org", automation=AUTO, default_severity="High",
        best_practice="2FA required for all organisation members.",
        why="Account takeover via phished or reused passwords is a leading breach vector; org-wide "
            "2FA is the highest-leverage single control against it.",
        improvement="Require two-factor authentication in organisation security settings.",
    ),
    "ORG-SECURITY-POLICY": dict(
        category="Organisation", title="Security policy published",
        scope="repo", automation=AUTO, default_severity="Low",
        best_practice="A SECURITY.md tells researchers how to report vulnerabilities.",
        why="Without a disclosure policy, external finders have no safe channel and may disclose "
            "publicly or not at all - a missed chance to fix issues before they're weaponised.",
        improvement="Add a SECURITY.md with a private reporting route.",
    ),
    "ORG-CODE-QUALITY": dict(
        category="Organisation", title="Code Quality enabled",
        scope="org", automation=MANUAL, default_severity="Low",
        best_practice="Code Quality (Preview) trialled to add maintainability signal.",
        why="Not a security control, but low-cost quality signal in the same PR workflow; an "
            "opportunity rather than a defect.",
        improvement="Trial Code Quality on a pilot repo; keep or drop on evidence.",
    ),
    "CODE-COPILOT-AUTOFIX": dict(
        category="Code Scanning", title="Copilot Autofix enabled",
        scope="repo", automation=PARTIAL, default_severity="Low",
        best_practice="Copilot Autofix on, suggesting AI fixes for code-scanning alerts.",
        why="Autofix shortens remediation time by proposing the fix, not just the finding - "
            "accelerating closure of the very alerts enforcement will block on.",
        improvement="Enable Copilot Autofix; measure suggestion and acceptance rates.",
    ),
    # ---------------- base feature enablement ----------------
    "SECRET-SCANNING-ENABLED": dict(
        category="Secret Protection", title="Secret scanning enabled",
        scope="repo", automation=AUTO, default_severity="High",
        best_practice="Secret scanning enabled on every repository.",
        why="Secret scanning is the foundation of secret protection - without it, leaked credentials "
            "in the codebase are never detected at all.",
        improvement="Enable secret scanning (via the org security configuration).",
    ),
    "CODE-SCANNING-ENABLED": dict(
        category="Code Scanning", title="Code scanning (CodeQL) enabled",
        scope="repo", automation=AUTO, default_severity="High",
        best_practice="CodeQL code scanning configured (default or advanced setup).",
        why="Code scanning is the SAST layer that finds vulnerabilities in your own code. Without it, "
            "injection flaws, unsafe deserialization and similar defects ship undetected.",
        improvement="Enable CodeQL (default setup is the fastest path).",
    ),
    "DEP-GRAPH-ENABLED": dict(
        category="Dependencies", title="Dependency graph enabled",
        scope="repo", automation=AUTO, default_severity="Medium",
        best_practice="Dependency graph enabled (prerequisite for Dependabot).",
        why="The dependency graph is what Dependabot reads to find vulnerable dependencies. If it's "
            "off, dependency alerting cannot function at all.",
        improvement="Enable the dependency graph in repository settings.",
    ),
    # ---------------- new checks ----------------
    "SECRET-PUSH-BYPASS": dict(
        category="Secret Protection", title="Push protection not bypassed",
        scope="repo", automation=AUTO, default_severity="High",
        best_practice="No secrets pushed via a push-protection bypass; any bypass reviewed.",
        why="A push-protection bypass means a developer deliberately pushed a detected secret past "
            "the block. Each one is a potential live credential in git history that must be reviewed "
            "and rotated.",
        improvement="Review every bypass; rotate any exposed secret; require justification for bypasses.",
    ),
    "GOV-DISMISSAL-WORKFLOW": dict(
        category="Governance", title="Dismissal-review workflow in use",
        scope="repo", automation=AUTO, default_severity="Medium",
        best_practice="Alert dismissals go through a review/request queue, not silent self-dismissal.",
        why="If dismissals are never routed for review, closure metrics can't be trusted - a "
            "'resolved' alert may simply have been waved away. A review workflow keeps dismissals honest.",
        improvement="Enable dismissal requests / 'prevent direct dismissals' so closures are reviewed.",
    ),
    "GOV-STORED-SECRETS": dict(
        category="Governance", title="Actions/agent secrets reviewed",
        scope="repo", automation=AUTO, default_severity="Low",
        best_practice="Stored Actions/agent secrets are known, owned, and rotated; no stale ones.",
        why="Long-lived CI/CD secrets are a standing credential-theft target. The tool cannot read "
            "their values, but flags their presence and age so stale or forgotten secrets get "
            "reviewed and rotated.",
        improvement="Review each stored secret; remove unused ones; rotate anything old.",
    ),
}
