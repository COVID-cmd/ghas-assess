# Security Policy

## Reporting a vulnerability
Please report security issues **privately** via GitHub's "Report a vulnerability"
(Security > Advisories) on this repository, rather than opening a public issue.
We aim to acknowledge within a few days.

## Scope & design
- `ghas-assess` is **strictly read-only**: it issues only HTTP `GET` requests and has no
  code path that writes, deletes or modifies any GitHub resource.
- Tokens are read from the environment (`GITHUB_TOKEN`) or `--token` and are **never logged**
  or written to any output file.
- Output reports may contain repository names and alert counts — treat generated reports as
  sensitive and share them accordingly.

## User responsibilities
- Use a **fine-grained, read-only** token scoped to the minimum permissions in the README.
- Do not commit tokens or generated reports. Rotate any token that is exposed.
