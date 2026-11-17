# Evidence contract

Final evidence is generated outside the source checkout after a clean candidate commit is frozen. The manifest records exact repository/branch/SHA/clean status; UTC command intervals/exits; OS/Python/Node and dependency versions; input/config/source hashes; JUnit testcase pass/fail/skip and separate native subtest counts; coverage settings; browser checks, logs, screenshots and actual export; package/build/security results; artifact SHA-256s; retained resources/cleanup; remaining limitations and an honest decision.

Reports contain the original input hash (UTF-8 file text), canonical config hash, Python source-content hash, exact-source Git status or UNKNOWN, app/rule/core revisions and package versions. Per-run UUIDs, timestamps, finding IDs and incident IDs vary; semantic findings and input/config hashes can be reproduced. Reports themselves are checksummed but are not signed or externally tamper-proof.

Health/report evidence is allowlisted and must never capture bearer/sessionStorage tokens, bootstrap passwords, provider credentials, browser storage dumps or actual PHI. Synthetic identifiers and test-only local database credentials are not production credentials. Server logs must not include authorization headers or request bodies. Export source data can contain arbitrary uploaded fields; only synthetic fixtures are permitted in public evidence.

The expected immutable non-release screenshot archive URL is documented in README. Publishing that archive and approving any report publication are separate parent tasks. A clean test run is not a production signoff. Review [WORKBENCH.md](WORKBENCH.md) for test commands, boundaries and unresolved master-contract gaps.
