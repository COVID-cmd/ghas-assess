"""
Assessment engine. Runs read-only checks and emits Result records mapped to F1-F16.

A Result:
  finding_id, scope ('org' or 'repo:<name>'), status (OK/GAP/INFO/UNKNOWN),
  severity, detail (human-readable), evidence (raw values used)

The engine is defensive: any endpoint that is forbidden/missing degrades the
relevant check to UNKNOWN with an explanatory note, rather than aborting the run.
"""
import datetime
from dataclasses import dataclass, field, asdict
from .client import ForbiddenOrMissing
from .findings import (
    FINDINGS, OK, GAP, INFO, UNKNOWN, SEVERITY_ORDER,
)


@dataclass
class Result:
    finding_id: str
    title: str
    scope: str
    status: str
    severity: str
    detail: str
    evidence: dict = field(default_factory=dict)

    def to_dict(self):
        return asdict(self)


def _age_days(ts):
    if not ts:
        return None
    dt = datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))
    now = datetime.datetime.now(datetime.timezone.utc)
    return (now - dt).days


class Assessor:
    def __init__(self, client, org, max_repos=None, verbose=False):
        self.gh = client
        self.org = org
        self.max_repos = max_repos
        self.verbose = verbose
        self.results = []
        self.repos = []

    # ---- helpers ----
    def _add(self, fid, scope, status, detail, evidence=None, severity=None):
        meta = FINDINGS[fid]
        self.results.append(Result(
            finding_id=fid, title=meta["title"], scope=scope, status=status,
            severity=severity or (meta["default_severity"] if status == GAP else "Info"),
            detail=detail, evidence=evidence or {},
        ))

    def _safe(self, fn, *a, **k):
        try:
            return fn(*a, **k), None
        except ForbiddenOrMissing as e:
            return None, e

    # ---- org-level ----
    def load_repos(self):
        repos = []
        try:
            for r in self.gh.paginate(f"/orgs/{self.org}/repos?type=all"):
                repos.append(r)
                if self.max_repos and len(repos) >= self.max_repos:
                    break
        except ForbiddenOrMissing as e:
            raise RuntimeError(f"Cannot list repositories for org '{self.org}': {e}")
        self.repos = repos
        return repos

    def assess_org(self):
        # F1 - coverage: repos in org vs repos attached to a security configuration
        configs, err = self._safe(
            lambda: list(self.gh.paginate(f"/orgs/{self.org}/code-security/configurations"))
        )
        attached_repo_names = set()
        if configs:
            for cfg in configs:
                cid = cfg.get("id")
                res, e2 = self._safe(
                    lambda: list(self.gh.paginate(
                        f"/orgs/{self.org}/code-security/configurations/{cid}/repositories"))
                )
                if res:
                    for row in res:
                        rn = (row.get("repository") or {}).get("name")
                        if rn:
                            attached_repo_names.add(rn)
        all_names = {r["name"] for r in self.repos}
        if configs is None:
            self._add("ORG-CONFIG-COVERAGE", "org", UNKNOWN,
                      "Could not read code-security configurations (permission or GHEC feature). "
                      "Confirm coverage manually in Settings > Advanced Security.",
                      {"error": str(err)})
        else:
            missing = sorted(all_names - attached_repo_names) if attached_repo_names else []
            if attached_repo_names and missing:
                self._add("ORG-CONFIG-COVERAGE", "org", GAP,
                          f"{len(missing)} of {len(all_names)} repositories are not attached to any "
                          f"security configuration: {', '.join(missing[:10])}"
                          + (" ..." if len(missing) > 10 else ""),
                          {"total_repos": len(all_names), "attached": len(attached_repo_names),
                           "missing": missing})
            elif attached_repo_names:
                self._add("ORG-CONFIG-COVERAGE", "org", OK,
                          f"All {len(all_names)} repositories attached to a security configuration.",
                          {"total_repos": len(all_names)})
            else:
                self._add("ORG-CONFIG-COVERAGE", "org", INFO,
                          "Configurations exist but no repository attachment list was returned; "
                          "verify coverage manually.", {"configs": len(configs)})

        # F5 - Dependabot access scope (not reliably in API) -> MANUAL
        self._add("DEP-ACCESS-SCOPE", "org", UNKNOWN,
                  "Dependabot repository access scope (public/internal vs private) is not reliably "
                  "exposed via API. Check Settings > Advanced Security > Global settings manually.")
        # F6 - custom secret patterns
        pats, err6 = self._safe(
            lambda: list(self.gh.paginate(f"/orgs/{self.org}/secret-scanning/custom-patterns"))
        )
        if pats is None:
            self._add("SECRET-CUSTOM-PATTERNS", "org", UNKNOWN,
                      "Custom secret-scanning patterns endpoint not accessible; verify manually.",
                      {"error": str(err6)})
        elif len(pats) == 0:
            self._add("SECRET-CUSTOM-PATTERNS", "org", GAP,
                      "No organisation custom secret-scanning patterns defined. Built-in patterns "
                      "will not catch organisation-specific credential formats.", {"custom_patterns": 0})
        else:
            self._add("SECRET-CUSTOM-PATTERNS", "org", OK,
                      f"{len(pats)} custom secret-scanning pattern(s) defined.",
                      {"custom_patterns": len(pats)})
        # F8, F10 - not in API
        self._add("CODE-SCHEDULED-SCANS", "org", UNKNOWN,
                  "'Keep scheduled scans running for inactive repositories' is not exposed via API. "
                  "Verify in org code-security global settings.")
        self._add("ORG-CODE-QUALITY", "org", UNKNOWN,
                  "Code Quality (Preview) enablement is not exposed via API. Verify manually.")

        # F17 - org 2FA requirement
        org_obj, err17 = self._safe(lambda: self.gh.get(f"/orgs/{self.org}"))
        if org_obj and "two_factor_requirement_enabled" in org_obj:
            if org_obj.get("two_factor_requirement_enabled"):
                self._add("ORG-2FA-REQUIRED", "org", OK, "Two-factor authentication is required org-wide.",
                          {"two_factor_required": True})
            else:
                self._add("ORG-2FA-REQUIRED", "org", GAP,
                          "Two-factor authentication is NOT required for organisation members.",
                          {"two_factor_required": False})
        else:
            self._add("ORG-2FA-REQUIRED", "org", UNKNOWN,
                      "2FA requirement not readable (needs org admin read). Verify manually.",
                      {"error": str(err17) if err17 else "field absent"})

    # ---- repo-level ----
    def assess_repo(self, repo):
        name = repo["name"]
        full = repo["full_name"]
        owner = repo["owner"]["login"]
        scope = f"repo:{name}"
        sa = repo.get("security_and_analysis") or {}

        def st(key):
            return ((sa.get(key) or {}).get("status"))

        # F23 - secret scanning enabled (base feature)
        ss = st("secret_scanning")
        if ss == "enabled":
            self._add("SECRET-SCANNING-ENABLED", scope, OK, "Secret scanning enabled.", {"secret_scanning": ss})
        elif ss in ("disabled", None):
            self._add("SECRET-SCANNING-ENABLED", scope, GAP,
                      "Secret scanning is NOT enabled - leaked credentials are never detected.",
                      {"secret_scanning": ss})

        # F25 - dependency graph enabled (base feature)
        # security_and_analysis may not expose it; infer from the dependency-graph SBOM endpoint
        sbom, errsb = self._safe(lambda: self.gh.get(
            f"/repos/{owner}/{name}/dependency-graph/sbom"))
        if sbom is not None:
            self._add("DEP-GRAPH-ENABLED", scope, OK, "Dependency graph enabled.", {"dependency_graph": True})
        elif getattr(errsb, "status", None) in (403, 404):
            self._add("DEP-GRAPH-ENABLED", scope, GAP,
                      "Dependency graph appears disabled - Dependabot cannot see dependencies.",
                      {"dependency_graph": False})
        else:
            self._add("DEP-GRAPH-ENABLED", scope, UNKNOWN, "Dependency graph state not readable.",
                      {"error": str(errsb)})

        # F12 - push protection
        pp = st("secret_scanning_push_protection")
        ss = st("secret_scanning")
        if pp == "enabled":
            self._add("SECRET-PUSH-PROTECTION", scope, OK, "Push protection enabled.", {"push_protection": pp})
        elif ss == "enabled" and pp in ("disabled", None):
            self._add("SECRET-PUSH-PROTECTION", scope, GAP,
                      "Secret scanning enabled but PUSH PROTECTION DISABLED - secrets are detected "
                      "after commit, not blocked.", {"secret_scanning": ss, "push_protection": pp})
        elif ss in ("disabled", None):
            self._add("SECRET-PUSH-PROTECTION", scope, GAP,
                      "Secret scanning not enabled on this repository.",
                      {"secret_scanning": ss}, severity="High")
        else:
            self._add("SECRET-PUSH-PROTECTION", scope, INFO, "Push protection state indeterminate.",
                      {"secret_scanning": ss, "push_protection": pp})

        # F14 - AI-detected secrets
        ai = st("secret_scanning_ai_detection") or st("secret_scanning_non_provider_patterns")
        if ai == "enabled":
            self._add("SECRET-AI-DETECTION", scope, OK, "AI-detected secrets enabled.", {"ai_detection": ai})
        elif ss == "enabled":
            self._add("SECRET-AI-DETECTION", scope, GAP,
                      "AI-detected secrets not enabled - non-conforming credentials (passwords, "
                      "connection strings) may escape detection.", {"ai_detection": ai})
        else:
            self._add("SECRET-AI-DETECTION", scope, INFO, "AI-detected secrets not applicable (secret scanning off).",
                      {"ai_detection": ai})

        # F9 - dependabot config
        dg = st("dependabot_security_updates")
        has_yml, _ = self._safe(lambda: self.gh.get(
            f"/repos/{owner}/{name}/contents/.github/dependabot.yml"))
        if has_yml is None:
            has_yml2, _ = self._safe(lambda: self.gh.get(
                f"/repos/{owner}/{name}/contents/.github/dependabot.yaml"))
            has_yml = has_yml2
        if not has_yml:
            self._add("DEP-UPDATE-CONFIG", scope, GAP,
                      "No dependabot.yml - update schedule, grouping and PR limits are unmanaged "
                      "(defaults only).", {"dependabot_security_updates": dg, "dependabot_yml": False})
        else:
            self._add("DEP-UPDATE-CONFIG", scope, OK, "dependabot.yml present.",
                      {"dependabot_yml": True})

        # F16 - dependency graph auto submission (not in API) -> partial via checking manifests
        self._add("DEP-AUTO-SUBMISSION", scope, UNKNOWN,
                  "Automatic dependency submission state is not exposed via API; verify for compiled "
                  "ecosystems (e.g. NuGet) manually.", {})

        # F3 / F15 - rulesets & required checks on default branch
        default_branch = repo.get("default_branch", "main")
        rulesets, err = self._safe(lambda: list(self.gh.paginate(
            f"/repos/{owner}/{name}/rulesets")))
        prot = repo.get("default_branch")  # placeholder
        code_scan_required = False
        pr_required = False
        reviews_required = False
        if rulesets:
            for rs in rulesets:
                rid = rs.get("id")
                detail, _ = self._safe(lambda: self.gh.get(
                    f"/repos/{owner}/{name}/rulesets/{rid}"))
                if not detail:
                    continue
                for rule in detail.get("rules", []):
                    if rule.get("type") == "pull_request":
                        pr_required = True
                        params = rule.get("parameters") or {}
                        if (params.get("required_approving_review_count") or 0) >= 1:
                            reviews_required = True
                    if rule.get("type") == "code_scanning":
                        code_scan_required = True
                    if rule.get("type") == "required_status_checks":
                        checks = (rule.get("parameters") or {}).get("required_status_checks", [])
                        if any("codeql" in (c.get("context", "").lower()) for c in checks):
                            code_scan_required = True
        # branch protection fallback
        if not pr_required:
            bp, _ = self._safe(lambda: self.gh.get(
                f"/repos/{owner}/{name}/branches/{default_branch}/protection"))
            if bp:
                rpr = bp.get("required_pull_request_reviews")
                if rpr:
                    pr_required = True
                    if (rpr.get("required_approving_review_count") or 0) >= 1:
                        reviews_required = True
                checks = ((bp.get("required_status_checks") or {}).get("contexts")) or []
                if any("codeql" in c.lower() for c in checks):
                    code_scan_required = True

        if rulesets is None and err:
            self._add("ENF-PR-REQUIRED", scope, UNKNOWN,
                      "Could not read rulesets/branch protection (permission).", {"error": str(err)})
        elif pr_required and code_scan_required:
            self._add("ENF-PR-REQUIRED", scope, OK,
                      "Default branch requires PR and a code-scanning status check.",
                      {"pr_required": True, "code_scanning_required": True})
        elif pr_required and not code_scan_required:
            self._add("CODE-REQUIRED-CHECK", scope, GAP,
                      "PR required, but no ruleset requires the code-scanning check to pass - "
                      "a critical finding does not block merge.",
                      {"pr_required": True, "code_scanning_required": False})
        else:
            self._add("ENF-PR-REQUIRED", scope, GAP,
                      "Default branch does not require pull requests / enforced checks - "
                      "direct pushes and unchecked merges are possible.",
                      {"pr_required": pr_required, "code_scanning_required": code_scan_required})

        # F20 - required reviews
        if pr_required and reviews_required:
            self._add("ENF-REVIEWS-REQUIRED", scope, OK, "At least one approving review required before merge.",
                      {"reviews_required": True})
        elif pr_required and not reviews_required:
            self._add("ENF-REVIEWS-REQUIRED", scope, GAP,
                      "Pull requests required, but no approving review is mandated - a single actor "
                      "can merge unreviewed.", {"reviews_required": False})

        # F13 - prevent direct dismissals (not exposed) -> PARTIAL/manual
        self._add("GOV-DISMISSAL-CONTROL", scope, UNKNOWN,
                  "'Prevent direct alert dismissals' state is not exposed via API; verify per scanner "
                  "in repo Advanced Security settings.")

        # F19 - Dependabot alerts enabled (204 = enabled, 404 = not)
        _, err19 = self._safe(lambda: self.gh.get(
            f"/repos/{owner}/{name}/vulnerability-alerts"))
        if err19 is None:
            self._add("DEP-ALERTS-ENABLED", scope, OK, "Dependabot vulnerability alerts enabled.",
                      {"dependabot_alerts": True})
        elif getattr(err19, "status", None) == 404:
            self._add("DEP-ALERTS-ENABLED", scope, GAP,
                      "Dependabot vulnerability alerts NOT enabled - no visibility of vulnerable "
                      "dependencies.", {"dependabot_alerts": False})
        else:
            self._add("DEP-ALERTS-ENABLED", scope, UNKNOWN, "Dependabot alert status not readable.",
                      {"error": str(err19)})

        # F18 - security policy (SECURITY.md)
        sec_md = None
        for path in ("SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md"):
            res, _ = self._safe(lambda p=path: self.gh.get(
                f"/repos/{owner}/{name}/contents/{p}"))
            if res:
                sec_md = path
                break
        if sec_md:
            self._add("ORG-SECURITY-POLICY", scope, OK, f"Security policy present ({sec_md}).",
                      {"security_policy": sec_md})
        else:
            self._add("ORG-SECURITY-POLICY", scope, GAP,
                      "No SECURITY.md - external researchers have no defined way to report "
                      "vulnerabilities.", {"security_policy": None})

        # F11 - autofix (org/default-setup) - note only
        self._add("CODE-COPILOT-AUTOFIX", scope, INFO,
                  "Copilot Autofix usage (suggestion/acceptance rate) is a measurement task, not a "
                  "config flag; capture during triage.")

        # ---- alerts: F2, F4, F7 ----
        self._assess_alerts(owner, name, scope)

        # ---- F21: push protection bypasses ----
        bypasses, errb = self._safe(lambda: list(self.gh.paginate(
            f"/repos/{owner}/{name}/secret-scanning/push-protection-bypasses")))
        if bypasses is None:
            # older endpoint name / not available
            self._add("SECRET-PUSH-BYPASS", scope, UNKNOWN,
                      "Push-protection bypass history not readable on this instance.",
                      {"error": str(errb)})
        elif len(bypasses) == 0:
            self._add("SECRET-PUSH-BYPASS", scope, OK, "No push-protection bypasses recorded.",
                      {"bypasses": 0})
        else:
            self._add("SECRET-PUSH-BYPASS", scope, GAP,
                      f"{len(bypasses)} push-protection bypass(es) recorded - each pushed a detected "
                      "secret past the block; review and rotate.",
                      {"bypasses": len(bypasses)})

        # ---- F13B: dismissal-review workflow in use ----
        dr, errd = self._safe(lambda: list(self.gh.paginate(
            f"/repos/{owner}/{name}/secret-scanning/alerts?state=resolved&resolution=used_in_tests")))
        # Better signal: are dismissal *requests* present (requires the dismissal-requests feature)?
        reqs, errr = self._safe(lambda: list(self.gh.paginate(
            f"/repos/{owner}/{name}/dismissal-requests")))
        if reqs is not None:
            if len(reqs) > 0:
                self._add("GOV-DISMISSAL-WORKFLOW", scope, OK,
                          f"Dismissal-review workflow in use ({len(reqs)} request(s) on record).",
                          {"dismissal_requests": len(reqs)})
            else:
                self._add("GOV-DISMISSAL-WORKFLOW", scope, INFO,
                          "Dismissal-requests feature reachable but no requests yet - confirm "
                          "'prevent direct dismissals' is enabled.", {"dismissal_requests": 0})
        else:
            self._add("GOV-DISMISSAL-WORKFLOW", scope, UNKNOWN,
                      "Dismissal-request workflow state not readable; verify 'prevent direct "
                      "dismissals' in settings.", {"error": str(errr)})

        # ---- F22: Actions / agent secrets present (names + age only; values never exposed) ----
        secs, errs = self._safe(lambda: self.gh.get(f"/repos/{owner}/{name}/actions/secrets"))
        if secs is None:
            self._add("GOV-STORED-SECRETS", scope, UNKNOWN,
                      "Actions secrets not readable (needs Secrets read permission).",
                      {"error": str(errs)})
        else:
            items = secs.get("secrets", []) if isinstance(secs, dict) else []
            total = secs.get("total_count", len(items)) if isinstance(secs, dict) else 0
            if total == 0:
                self._add("GOV-STORED-SECRETS", scope, OK, "No stored Actions secrets.", {"secrets": 0})
            else:
                oldest_days = None
                names = []
                for s in items:
                    names.append(s.get("name"))
                    d = _age_days(s.get("created_at"))
                    if d is not None:
                        oldest_days = d if oldest_days is None else max(oldest_days, d)
                stale = oldest_days is not None and oldest_days > 365
                detail = (f"{total} Actions secret(s) stored"
                          + (f", oldest {oldest_days}d" if oldest_days is not None else "")
                          + (" - review/rotate stale secrets." if stale else " - review ownership."))
                self._add("GOV-STORED-SECRETS", scope, GAP if stale else INFO, detail,
                          {"secret_count": total, "oldest_age_days": oldest_days,
                           "names": [n for n in names if n][:20]},
                          severity="Low")

    def _assess_alerts(self, owner, name, scope):
        # Code scanning alerts (open)
        cs_alerts, err = self._safe(lambda: list(self.gh.paginate(
            f"/repos/{owner}/{name}/code-scanning/alerts?state=open")))
        dep_alerts, _ = self._safe(lambda: list(self.gh.paginate(
            f"/repos/{owner}/{name}/dependabot/alerts?state=open")))
        sec_alerts, _ = self._safe(lambda: list(self.gh.paginate(
            f"/repos/{owner}/{name}/secret-scanning/alerts?state=open")))

        # F4 - query suite from default setup
        ds, _ = self._safe(lambda: self.gh.get(
            f"/repos/{owner}/{name}/code-scanning/default-setup"))
        # F24 - code scanning (CodeQL) enabled at all?
        analyses, erra = self._safe(lambda: list(self.gh.paginate(
            f"/repos/{owner}/{name}/code-scanning/analyses")))
        ds_state = ds.get("state") if ds else None
        if ds_state == "configured" or (analyses and len(analyses) > 0):
            self._add("CODE-SCANNING-ENABLED", scope, OK, "Code scanning (CodeQL) enabled.",
                      {"default_setup": ds_state, "analyses": len(analyses or [])})
        elif ds_state in ("not-configured", None) and analyses is not None and len(analyses) == 0:
            self._add("CODE-SCANNING-ENABLED", scope, GAP,
                      "Code scanning (CodeQL) is NOT enabled - your own code is not scanned for "
                      "vulnerabilities.", {"default_setup": ds_state, "analyses": 0})
        # else indeterminate; skip silently
        if ds and ds.get("state") == "configured":
            suite = ds.get("query_suite")
            if suite == "extended":
                self._add("CODE-EXTENDED-SUITE", scope, OK, "CodeQL extended query suite in use.", {"query_suite": suite})
            elif suite:
                self._add("CODE-EXTENDED-SUITE", scope, GAP,
                          f"CodeQL '{suite}' suite in use - extended suite not enabled, lower-severity "
                          "queries are not running.", {"query_suite": suite})
        # else advanced setup or off; skip silently

        # severities
        def sev_counts(alerts, sev_key):
            counts = {}
            if not alerts:
                return counts
            for a in alerts:
                if sev_key == "cs":
                    s = ((a.get("rule") or {}).get("security_severity_level")
                         or (a.get("rule") or {}).get("severity") or "unknown")
                elif sev_key == "dep":
                    s = ((a.get("security_advisory") or {}).get("severity")
                         or (a.get("security_vulnerability") or {}).get("severity") or "unknown")
                else:
                    s = "high"
                s = str(s).capitalize()
                counts[s] = counts.get(s, 0) + 1
            return counts

        cs_c = sev_counts(cs_alerts, "cs")
        dep_c = sev_counts(dep_alerts, "dep")
        sec_n = len(sec_alerts or [])
        crit = cs_c.get("Critical", 0) + dep_c.get("Critical", 0)
        high = cs_c.get("High", 0) + dep_c.get("High", 0)
        total_open = sum(cs_c.values()) + sum(dep_c.values()) + sec_n

        # F2 - critical concentration
        if crit > 0:
            self._add("GOV-NO-OPEN-CRITICALS", scope, GAP,
                      f"{crit} critical and {high} high open alert(s) "
                      f"(code scanning {sum(cs_c.values())}, dependabot {sum(dep_c.values())}, "
                      f"secrets {sec_n}).",
                      {"critical": crit, "high": high, "code_scanning": cs_c, "dependabot": dep_c,
                       "secrets": sec_n}, severity="High" if crit else "Medium")
        elif total_open:
            self._add("GOV-NO-OPEN-CRITICALS", scope, INFO,
                      f"{total_open} open alert(s), none critical.",
                      {"code_scanning": cs_c, "dependabot": dep_c, "secrets": sec_n})

        # F7 - stale backlog
        ages = []
        for a in (cs_alerts or []) + (dep_alerts or []):
            d = _age_days(a.get("created_at"))
            if d is not None:
                ages.append(d)
        if ages:
            avg = round(sum(ages) / len(ages))
            oldest = max(ages)
            if oldest > 90:
                self._add("GOV-BACKLOG-FRESH", scope, GAP,
                          f"Stale backlog: average open-alert age {avg}d, oldest {oldest}d "
                          "(>90d without SLA).",
                          {"avg_age_days": avg, "oldest_age_days": oldest, "open": len(ages)})
            else:
                self._add("GOV-BACKLOG-FRESH", scope, INFO,
                          f"Average open-alert age {avg}d, oldest {oldest}d.",
                          {"avg_age_days": avg, "oldest_age_days": oldest})

    # ---- driver ----
    def run(self):
        self.load_repos()
        if self.verbose:
            print(f"Assessing org '{self.org}' - {len(self.repos)} repositories")
        self.assess_org()
        for i, repo in enumerate(self.repos, 1):
            if self.verbose:
                print(f"[{i}/{len(self.repos)}] {repo['full_name']}")
            try:
                self.assess_repo(repo)
            except Exception as e:  # never let one repo abort the run
                self._add("GOV-NO-OPEN-CRITICALS", f"repo:{repo['name']}", UNKNOWN,
                          f"Assessment error: {e}")
        return self.results

    # ---- summary ----
    def summary(self):
        gaps = [r for r in self.results if r.status == GAP]
        by_sev = {}
        for r in gaps:
            by_sev[r.severity] = by_sev.get(r.severity, 0) + 1
        return {
            "org": self.org,
            "repos_assessed": len(self.repos),
            "total_results": len(self.results),
            "gaps": len(gaps),
            "gaps_by_severity": dict(sorted(by_sev.items(),
                                            key=lambda kv: SEVERITY_ORDER.get(kv[0], 9))),
        }
