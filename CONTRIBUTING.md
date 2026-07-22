# Contributing to ghas-assess

Thanks for helping improve GHAS posture assessment for everyone.

## Ground rules
- The tool is **strictly read-only**. PRs must not introduce any write/delete/patch
  API calls. This is a hard rule.
- Never commit tokens, org names, or real assessment output. Use the fictional
  `acme-corp` demo data for examples.
- Keep dependencies minimal (standard library + `python-docx` for the Word export).

## Good first issues
- Add a new check to the F-taxonomy (`findings.py` + a method in `assessor.py`).
- Promote a `MANUAL` check to `AUTO` when GitHub exposes a supporting endpoint.
- Add an output format (e.g. SARIF, CSV, Markdown) in `reporters.py`.
- Improve GitHub Enterprise Server compatibility.

## Dev setup
```bash
git clone https://github.com/<you>/ghas-assess && cd ghas-assess
pip install -r requirements.txt
python -m ghas_assess --demo          # should print a table and exit 1
```

## Adding a check
1. Add/extend the entry in `ghas_assess/findings.py` (id, title, scope, automation, severity).
2. Emit a `Result` via `self._add(...)` in the relevant `assess_*` method.
3. Add a representative row to `ghas_assess/demo.py` so `--demo` shows it.
4. Update the checks table in `README.md`.

## PR checklist
- [ ] Read-only preserved (no write calls)
- [ ] `python -m ghas_assess --demo` runs clean
- [ ] `python -m py_compile ghas_assess/*.py` passes
- [ ] No secrets, tokens or real org data in the diff
- [ ] README table updated if a check changed
