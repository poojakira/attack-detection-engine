# Remediation report

Branch codex/local-workbench-20261116. Local fixing source 76aa71afcb1ba4d940952b4e41d04298452795b5. Review baseline d3d745f14ed8211b96f4da0a0c6d90947878d291.

- **ADE-01** Main pip install piped its output to tail in a non-pipefail shell. PR #58 removed the pipe. Explicit Bash adds pipefail to run steps.
- **ADE-02** The old collection pipeline could mask failure and the draft had dropped its minimum. The patch checks pytest status and preserves the five-test minimum.
- **ADE-03** An incomplete Bandit or pip-audit report could be interpreted as clean. The patch rejects scan errors and malformed or missing report fields, checks pip-audit status consistency, and preserves dependency allowlist handling.
- **ADE-06** Both files referenced a missing branch-cleanup.json in the evidence archive. HTTP returned 404 and the named object was absent from Git. The links now point to the existing immutable manifest or cleanup record.
- **ADE-04** The workflow set ATTACK_DATA_DIR for the loader, but the pinned downloader CLI installed into its independent home-directory default. The workflow now passes the same directory explicitly.
- **ADE-05** An unavailable database could include the connection URI in pytest skip output. The generic skip reason now avoids rendering that URI.
- **ADE-07** The line-size check ran after unrestricted stream iteration had already allocated a full line. The CLI now bounds reads before validating UTF-8 byte size, including blank records. Both oversized-line regressions failed on the baseline and passed after the fix.

Read [documentation parity](DOCUMENTATION_PARITY.md) for the evidence pins. Historical poster figures and images retain their original date and provenance.
