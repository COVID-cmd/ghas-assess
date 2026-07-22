"""
Demo mode: synthetic results for a fictional 'acme-corp' organisation, so the tool's
output can be seen without hitting a live GitHub org. Uses the same Result objects
the live engine produces. No real organisation is represented here.
"""
from .assessor import Result
from .findings import GAP, OK, INFO, UNKNOWN


def demo_results():
    R = []

    def add(fid, title, scope, status, sev, detail, ev=None):
        R.append(Result(fid, title, scope, status, sev, detail, ev or {}))

    add("ORG-CONFIG-COVERAGE", "Repository coverage gap", "org", GAP, "High",
        "2 of 9 repositories are not attached to any security configuration.",
        {"total_repos": 9, "attached": 7, "missing": ["legacy-api", "infra-scripts"]})
    add("SECRET-CUSTOM-PATTERNS", "No custom secret scanning patterns", "org", GAP, "Medium",
        "No organisation custom secret-scanning patterns defined.", {"custom_patterns": 0})
    add("DEP-ACCESS-SCOPE", "Dependabot repository access scope", "org", UNKNOWN, "Info",
        "Access scope not exposed via API; verify manually in global settings.")
    add("CODE-SCHEDULED-SCANS", "Scheduled scans for inactive repos disabled", "org", UNKNOWN, "Info",
        "Not exposed via API; verify in org code-security global settings.")
    add("ORG-CODE-QUALITY", "Code Quality not enabled", "org", UNKNOWN, "Info",
        "Not exposed via API; verify manually (Preview feature).")

    s = "repo:payments-service"
    add("SECRET-PUSH-PROTECTION", "Push protection disabled at repository level", s, GAP, "High",
        "Secret scanning enabled but PUSH PROTECTION DISABLED - secrets detected after commit.",
        {"push_protection": "disabled"})
    add("GOV-NO-OPEN-CRITICALS", "Critical alert concentration", s, GAP, "High",
        "5 critical and 0 high open alerts (code scanning 5, dependabot 1, secrets 0).",
        {"critical": 5})
    add("CODE-REQUIRED-CHECK", "Failure threshold set but no ruleset enforces it", s, GAP, "High",
        "PR required, but no ruleset requires the code-scanning check - criticals don't block merge.")
    add("GOV-DISMISSAL-CONTROL", "Direct alert dismissals unrestricted", s, UNKNOWN, "Info",
        "Not exposed via API; verify per scanner in repo Advanced Security settings.")
    add("SECRET-AI-DETECTION", "AI-detected secrets not enabled", s, GAP, "Medium",
        "AI-detected secrets not enabled - non-conforming credentials may escape detection.")
    add("DEP-UPDATE-CONFIG", "Dependabot update management", s, GAP, "Medium",
        "No dependabot.yml - grouping and schedule unmanaged.", {"dependabot_yml": False})
    add("CODE-EXTENDED-SUITE", "CodeQL default query suite only", s, GAP, "Medium",
        "CodeQL 'default' suite in use - extended suite not enabled.", {"query_suite": "default"})

    # org-level additions
    # base feature enablement (shows in "what is configured")
    for repo in ["payments-service", "web-frontend", "iac-sandbox"]:
        add("SECRET-SCANNING-ENABLED", "Secret scanning enabled", f"repo:{repo}", OK, "Info",
            "Secret scanning enabled.", {"secret_scanning": "enabled"})
        add("CODE-SCANNING-ENABLED", "Code scanning (CodeQL) enabled", f"repo:{repo}", OK, "Info",
            "Code scanning (CodeQL) enabled.", {"default_setup": "configured"})
        add("DEP-GRAPH-ENABLED", "Dependency graph enabled", f"repo:{repo}", OK, "Info",
            "Dependency graph enabled.", {"dependency_graph": True})

    add("ORG-2FA-REQUIRED", "Two-factor authentication required", "org", GAP, "High",
        "Two-factor authentication is NOT required for organisation members.",
        {"two_factor_required": False})

    s = "repo:payments-service"
    add("DEP-ALERTS-ENABLED", "Dependabot alerts enabled", s, OK, "Info",
        "Dependabot vulnerability alerts enabled.", {"dependabot_alerts": True})
    add("ORG-SECURITY-POLICY", "Security policy published", s, GAP, "Low",
        "No SECURITY.md - external researchers have no defined way to report vulnerabilities.",
        {"security_policy": None})
    add("ENF-REVIEWS-REQUIRED", "Pull request reviews required", s, GAP, "Medium",
        "Pull requests required, but no approving review is mandated.", {"reviews_required": False})

    s = "repo:web-frontend"
    add("GOV-NO-OPEN-CRITICALS", "Critical alert concentration", s, INFO, "Info",
        "26 open alerts, none critical (9 High, 8 Medium, 9 Low).", {"critical": 0})
    add("GOV-BACKLOG-FRESH", "Alert age / stale backlog", s, GAP, "Medium",
        "Stale backlog: average open-alert age 26d, oldest 140d (>90d without SLA).",
        {"avg_age_days": 26, "oldest_age_days": 140})
    add("SECRET-PUSH-PROTECTION", "Push protection disabled at repository level", s, OK, "Info",
        "Push protection enabled.", {"push_protection": "enabled"})
    add("ENF-PR-REQUIRED", "Branch protection / enforcement unverified", s, GAP, "High",
        "Default branch does not require pull requests / enforced checks.",
        {"pr_required": False})

    add("SECRET-PUSH-BYPASS", "Push protection not bypassed", "repo:payments-service", GAP, "High",
        "2 push-protection bypass(es) recorded - each pushed a detected secret past the block.",
        {"bypasses": 2})
    add("GOV-STORED-SECRETS", "Actions/agent secrets reviewed", "repo:payments-service", GAP, "Low",
        "6 Actions secret(s) stored, oldest 430d - review/rotate stale secrets.",
        {"secret_count": 6, "oldest_age_days": 430, "names": ["AZURE_TOKEN","NPM_KEY","DB_PW"]})
    add("GOV-DISMISSAL-WORKFLOW", "Dismissal-review workflow in use", "repo:web-frontend", OK, "Info",
        "Dismissal-review workflow in use (3 request(s) on record).", {"dismissal_requests": 3})

    s = "repo:iac-sandbox"
    add("DEP-AUTO-SUBMISSION", "Automatic dependency submission disabled", s, UNKNOWN, "Info",
        "Not exposed via API; verify for compiled ecosystems (e.g. NuGet).")
    add("ENF-PR-REQUIRED", "Branch protection / enforcement unverified", s, OK, "Info",
        "Default branch requires PR and a code-scanning status check.",
        {"pr_required": True, "code_scanning_required": True})

    return R


def demo_summary(results):
    gaps = [r for r in results if r.status == GAP]
    by = {}
    for r in gaps:
        by[r.severity] = by.get(r.severity, 0) + 1
    from .findings import SEVERITY_ORDER
    return {
        "org": "acme-corp (demo)",
        "repos_assessed": 3,
        "total_results": len(results),
        "gaps": len(gaps),
        "gaps_by_severity": dict(sorted(by.items(), key=lambda kv: SEVERITY_ORDER.get(kv[0], 9))),
    }
