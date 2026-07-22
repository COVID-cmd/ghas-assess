"""Smoke tests that run offline (no network, no token)."""
import subprocess, sys, json, os, tempfile


def test_demo_terminal_runs():
    # demo mode returns exit 1 (High gaps present) and prints the org line
    r = subprocess.run([sys.executable, "-m", "ghas_assess", "--demo", "--formats", "terminal"],
                       capture_output=True, text=True)
    assert r.returncode == 1
    assert "GHAS Security Assessment" in r.stdout


def test_demo_json_shape():
    with tempfile.TemporaryDirectory() as d:
        out = os.path.join(d, "r")
        subprocess.run([sys.executable, "-m", "ghas_assess", "--demo",
                        "--formats", "json", "--out", out], capture_output=True, text=True)
        data = json.load(open(out + ".json"))
        assert "summary" in data and "results" in data
        assert data["summary"]["gaps"] > 0
        assert all("finding_id" in r for r in data["results"])


def test_no_client_references():
    # guard against reintroducing client-specific names into shipped code
    import pathlib
    banned = ["e470", "expresstoll", "e470psmodule", "actionandrunner"]
    for p in pathlib.Path("ghas_assess").glob("*.py"):
        txt = p.read_text().lower()
        for b in banned:
            assert b not in txt, f"{b} found in {p}"


def test_manual_answers_merge():
    """Manual answers convert UNKNOWN items into OK/GAP verdicts."""
    import tempfile, os
    from ghas_assess.demo import demo_results
    from ghas_assess import manual
    from ghas_assess.findings import UNKNOWN, GAP, OK
    results = demo_results()
    # baseline: GOV-DISMISSAL-CONTROL is UNKNOWN in demo
    assert any(r.finding_id == "GOV-DISMISSAL-CONTROL" and r.status == UNKNOWN for r in results)
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "a.ini")
        open(p, "w").write("[repo:default]\nGOV-DISMISSAL-CONTROL = gap\nDEP-AUTO-SUBMISSION = ok\n[org]\nDEP-ACCESS-SCOPE = gap\n")
        answers = manual.load_answers(p)
        n = manual.apply_answers(results, answers)
        assert n >= 3
    assert any(r.finding_id == "GOV-DISMISSAL-CONTROL" and r.status == GAP for r in results)
    assert any(r.finding_id == "DEP-AUTO-SUBMISSION" and r.status == OK for r in results)


def test_checklist_template_covers_manual_findings():
    from ghas_assess import manual
    t = manual.emit_template("acme-corp", ["repo-a", "repo-b"])
    for fid in manual.CHECKLIST:
        assert fid in t
    assert "[org]" in t and "[repo:default]" in t
