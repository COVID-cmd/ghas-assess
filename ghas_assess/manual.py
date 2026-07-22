"""
Manual evaluation layer.

Some GHAS settings are not exposed by the GitHub REST API. Rather than leaving those
as 'UNKNOWN', the tool emits a checklist (with the exact UI path for each), the assessor
records ok/gap/na once, and the answers are merged back into the report so every finding
gets a real verdict.

Answers file format is INI (hand-editable, supports # comments), parsed with the stdlib
configparser - no extra dependency.

Sections:
  [org]                 answers that apply org-wide
  [repo:default]        answers applied to every repo unless overridden
  [repo:<name>]         per-repo override

Values: gap | ok | na | unknown   (unknown = still not evaluated)
"""
import configparser

# For each manually-evaluated finding: the question, where to look, and which answer = GAP.
CHECKLIST = {
    "DEP-ACCESS-SCOPE": dict(
        scope="org",
        question="Is Dependabot repository access restricted so that private repos are excluded "
                 "(scope = 'Public and internal only' with no additional private repos selected)?",
        ui_path="Org > Settings > Advanced Security > Global settings > Dependabot > "
                "Grant Dependabot access to repositories",
        gap_answer="yes",  # yes = restricted = gap
    ),
    "CODE-SCHEDULED-SCANS": dict(
        scope="org",
        question="Is 'Keep scheduled scans running every 30 days for inactive repositories' DISABLED?",
        ui_path="Org > Settings > Advanced Security > Global settings > Code scanning",
        gap_answer="yes",  # yes = disabled = gap
    ),
    "ORG-CODE-QUALITY": dict(
        scope="org",
        question="Is GitHub Code Quality (Preview) currently NOT enabled?",
        ui_path="Org > Security & quality > Code quality (or Org settings)",
        gap_answer="yes",  # informational; yes = not enabled = opportunity(gap-low)
    ),
    "GOV-DISMISSAL-CONTROL": dict(
        scope="repo",
        question="Is 'Prevent direct alert dismissals' DISABLED for any of secret scanning / "
                 "code scanning / Dependabot (i.e. anyone can self-dismiss)?",
        ui_path="Repo > Settings > Advanced Security (per scanner: 'Prevent direct alert dismissals')",
        gap_answer="yes",  # yes = unrestricted = gap
    ),
    "DEP-AUTO-SUBMISSION": dict(
        scope="repo",
        question="For compiled ecosystems (e.g. NuGet/.NET, Maven, Gradle), is 'Automatic dependency "
                 "submission' DISABLED (build-time deps not reported)?",
        ui_path="Repo > Settings > Advanced Security > Dependency graph > Automatic dependency submission",
        gap_answer="yes",  # yes = disabled = gap
    ),
}

GAP_SEVERITY = {"DEP-ACCESS-SCOPE": "Medium", "CODE-SCHEDULED-SCANS": "Low", "ORG-CODE-QUALITY": "Low", "GOV-DISMISSAL-CONTROL": "High", "DEP-AUTO-SUBMISSION": "Low"}


def emit_template(org, repo_names):
    """Return an INI checklist string covering all manual findings."""
    lines = []
    lines.append(f"# GHAS manual evaluation checklist for org: {org}")
    lines.append("# For each item, set the value to: gap | ok | na")
    lines.append("#   gap = the setting is a finding (needs improvement)")
    lines.append("#   ok  = the setting is correctly configured")
    lines.append("#   na  = not applicable to this org/repo")
    lines.append("# Leave 'unknown' for anything you have not yet checked.")
    lines.append("# Each item shows the exact place to look and what answer counts as a gap.")
    lines.append("")

    # org section
    lines.append("[org]")
    for fid, c in CHECKLIST.items():
        if c["scope"] != "org":
            continue
        lines.append(f"# {fid}: {c['question']}")
        lines.append(f"#   Where: {c['ui_path']}")
        lines.append(f"#   A 'gap' means the answer to the question is '{c['gap_answer']}'.")
        lines.append(f"{fid} = unknown")
        lines.append("")

    # repo default section
    lines.append("[repo:default]")
    lines.append("# Applied to every repository unless overridden in a [repo:<name>] section below.")
    for fid, c in CHECKLIST.items():
        if c["scope"] != "repo":
            continue
        lines.append(f"# {fid}: {c['question']}")
        lines.append(f"#   Where: {c['ui_path']}")
        lines.append(f"#   A 'gap' means the answer to the question is '{c['gap_answer']}'.")
        lines.append(f"{fid} = unknown")
        lines.append("")

    # per-repo override stubs (commented, so the file stays clean)
    lines.append("# --- Optional per-repository overrides ---")
    lines.append("# Uncomment and set values only where a repo differs from [repo:default].")
    for name in repo_names:
        safe = name
        lines.append(f"# [repo:{safe}]")
        for fid, c in CHECKLIST.items():
            if c["scope"] == "repo":
                lines.append(f"#   {fid} = unknown")
        lines.append("")
    return "\n".join(lines)


def load_answers(path):
    """Parse an answers INI file into {'org': {...}, 'repo_default': {...}, 'repos': {name:{...}}}."""
    cp = configparser.ConfigParser(inline_comment_prefixes=("#", ";"))
    cp.read(path)
    out = {"org": {}, "repo_default": {}, "repos": {}}
    for section in cp.sections():
        items = {k.upper(): v.strip().lower() for k, v in cp.items(section)}
        if section == "org":
            out["org"] = items
        elif section == "repo:default":
            out["repo_default"] = items
        elif section.startswith("repo:"):
            out["repos"][section[len("repo:"):]] = items
    return out


def _verdict(fid, answer):
    """Map a raw answer to (status, severity, note)."""
    from .findings import GAP, OK, INFO
    c = CHECKLIST[fid]
    answer = (answer or "unknown").lower()
    if answer in ("gap",):
        sev = GAP_SEVERITY.get(fid, "Medium")
        return GAP, sev, "Confirmed by manual review."
    if answer in ("ok",):
        return OK, "Info", "Verified correctly configured (manual review)."
    if answer in ("na", "n/a"):
        return INFO, "Info", "Marked not applicable (manual review)."
    # allow answering the underlying yes/no question directly
    if answer in ("yes", "no"):
        is_gap = (answer == c["gap_answer"])
        if is_gap:
            return GAP, GAP_SEVERITY.get(fid, "Medium"), "Confirmed by manual review."
        return OK, "Info", "Verified correctly configured (manual review)."
    return None  # unknown -> leave as-is


def apply_answers(results, answers):
    """Convert UNKNOWN manual results into OK/GAP using the answers. Returns count updated."""
    from .findings import UNKNOWN, FINDINGS
    updated = 0
    for r in results:
        if r.status != UNKNOWN or r.finding_id not in CHECKLIST:
            continue
        fid = r.finding_id
        scope = r.scope
        ans = None
        if scope == "org":
            ans = answers.get("org", {}).get(fid)
        elif scope.startswith("repo:"):
            name = scope[len("repo:"):]
            ans = (answers.get("repos", {}).get(name, {}).get(fid)
                   or answers.get("repo_default", {}).get(fid))
        v = _verdict(fid, ans)
        if v is None:
            continue
        status, sev, note = v
        r.status = status
        r.severity = sev
        r.detail = f"{FINDINGS[fid]['title']}. {note}"
        r.evidence = {"manual_answer": ans}
        updated += 1
    return updated
