"""
ghas-assess - read-only GitHub Advanced Security posture assessment.

Usage:
  export GITHUB_TOKEN=ghp_xxx
  python -m ghas_assess --org my-org
  python -m ghas_assess --org my-org --formats terminal,json,html,docx --out ./out
  python -m ghas_assess --demo                 # offline sample output, no token needed
  python -m ghas_assess --org my-org --max-repos 5 --verbose

Auth: a fine-grained or classic PAT with (read-only) repo security scopes:
  - 'repo' or fine-grained: Contents(R), Administration(R), Code scanning alerts(R),
    Dependabot alerts(R), Secret scanning alerts(R), Metadata(R), and org
    'Advanced security'/'Administration' read for coverage checks.
GitHub Enterprise Server: pass --api-url https://HOST/api/v3
"""
import os
import sys
import argparse

from .client import GitHubClient
from .assessor import Assessor
from . import reporters
from . import manual
from .demo import demo_results, demo_summary


def _recompute_summary(results, org, repos_assessed):
    from .findings import GAP, SEVERITY_ORDER
    gaps = [r for r in results if r.status == GAP]
    by = {}
    for r in gaps:
        by[r.severity] = by.get(r.severity, 0) + 1
    return {
        "org": org,
        "repos_assessed": repos_assessed,
        "total_results": len(results),
        "gaps": len(gaps),
        "gaps_by_severity": dict(sorted(by.items(), key=lambda kv: SEVERITY_ORDER.get(kv[0], 9))),
    }


def main(argv=None):
    ap = argparse.ArgumentParser(prog="ghas-assess",
                                 description="Read-only GHAS posture assessment.")
    ap.add_argument("--org", help="GitHub organisation login (e.g. my-org)")
    ap.add_argument("--api-url", default=os.environ.get("GITHUB_API_URL",
                    "https://api.github.com"), help="API base (GHES: https://HOST/api/v3)")
    ap.add_argument("--token", default=os.environ.get("GITHUB_TOKEN"),
                    help="PAT (or set GITHUB_TOKEN)")
    ap.add_argument("--formats", default="terminal",
                    help="comma list: terminal,json,html,docx")
    ap.add_argument("--out", default="./ghas-assessment", help="output path prefix")
    ap.add_argument("--max-repos", type=int, default=None, help="limit repos (testing)")
    ap.add_argument("--demo", action="store_true", help="offline sample output, no token")
    ap.add_argument("--emit-checklist", metavar="FILE",
                    help="write a manual-evaluation checklist (for API-invisible settings) and exit")
    ap.add_argument("--manual-answers", metavar="FILE",
                    help="merge a filled-in manual checklist into the results")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args(argv)

    formats = [f.strip() for f in args.formats.split(",") if f.strip()]

    if args.demo:
        results = demo_results()
        summary = demo_summary(results)
    else:
        if not args.org:
            ap.error("--org is required (or use --demo)")
        if not args.token:
            ap.error("no token: set GITHUB_TOKEN or pass --token (or use --demo)")
        client = GitHubClient(args.token, api_url=args.api_url, verbose=args.verbose)
        try:
            login = client.check_token()
            if args.verbose:
                print(f"Authenticated as {login}")
        except Exception as e:
            print(f"ERROR: token check failed: {e}", file=sys.stderr)
            return 2
        assessor = Assessor(client, args.org, max_repos=args.max_repos, verbose=args.verbose)
        # emit checklist: needs the repo list but not a full assessment
        if args.emit_checklist:
            try:
                repos = assessor.load_repos()
            except RuntimeError as e:
                print(f"ERROR: {e}", file=sys.stderr)
                return 2
            text = manual.emit_template(args.org, [r["name"] for r in repos])
            with open(args.emit_checklist, "w") as f:
                f.write(text)
            print(f"wrote checklist template to {args.emit_checklist}")
            print("Fill in each 'unknown' with gap/ok/na, then re-run with "
                  "--manual-answers <file>.")
            return 0
        try:
            results = assessor.run()
        except RuntimeError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 2
        summary = assessor.summary()

    # merge manual answers, if provided, and recompute the summary
    if args.manual_answers:
        try:
            answers = manual.load_answers(args.manual_answers)
            n = manual.apply_answers(results, answers)
            print(f"merged {n} manual answer(s) from {args.manual_answers}")
        except Exception as e:
            print(f"WARNING: could not apply manual answers: {e}", file=sys.stderr)
        summary = _recompute_summary(results, summary.get("org"), summary.get("repos_assessed"))

    # outputs
    if "terminal" in formats:
        print(reporters.to_terminal(results, summary))
    written = []
    if "json" in formats:
        written.append(reporters.to_json(results, summary, args.out + ".json"))
    if "html" in formats:
        written.append(reporters.to_html(results, summary, args.out + ".html"))
    if "docx" in formats:
        written.append(reporters.to_docx(results, summary, args.out + ".docx"))
    for w in written:
        print(f"wrote {w}")

    # exit non-zero if any High/Critical gap (useful in CI)
    hi = summary["gaps_by_severity"].get("High", 0) + summary["gaps_by_severity"].get("Critical", 0)
    return 1 if hi else 0


if __name__ == "__main__":
    sys.exit(main())
