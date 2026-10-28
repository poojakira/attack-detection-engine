# Milestone D — Phase 9 Supply-Chain Security (2026-10-27)

Reproducible scans of the Aegis platform's own runtime dependencies (not the
polluted system/ROS environment). Artifacts in `security_scans/`.

## Tools & commands

```bash
. .venv/bin/activate
# Python SAST
bandit -r detection_engine -ll            # gating: medium/high
# Python dependency audit (platform runtime deps only)
pip-audit -r <aegis runtime reqs>
# SBOM
cyclonedx-py requirements <reqs> -o security_scans/sbom-aegis.json
# Frontend
cd dashboard-ui && npm audit --omit=dev
# Secret scan (tracked files)
git grep -nIE "(AKIA[0-9A-Z]{16}|BEGIN .*PRIVATE KEY|password=...)"
```

## Results

### Bandit (Python SAST) — PASS
0 medium, 0 high. 3 low (high-confidence, benign try/except patterns). Gate
(medium/high) is clean. Full report: `security_scans/bandit.txt`.

### pip-audit — remediated the actionable items
Initial audit of the platform runtime found vulnerabilities in **starlette**,
**python-jose**, and **ecdsa**. Remediation performed this milestone:

| Package | Before | Action | After |
|---|---|---|---|
| python-jose + ecdsa | 3.5.0 / 0.19.2 (PYSEC-2026-4298, PYSEC-2026-1325) | **Replaced with PyJWT** (maintained, no ecdsa dep) | **resolved** |
| starlette (via FastAPI 0.111→0.116.2) | 0.37.2 (many CVEs) | upgraded to **0.48.0** | most fixed; residuals below |
| FastAPI | 0.111.0 | 0.116.2 | — |

**Verified compatible** with the pinned `attack-v19-core` (pydantic 2.7.4) and
the full test suite (274 passed) + real-Docker e2e.

### Residual Python vulnerabilities (documented, constrained)
`starlette 0.48.0` retains a few advisories fixed only in `starlette >=0.49 / 1.x`:
`PYSEC-2026-248/249/2280/2281/1942`. These cannot be taken without FastAPI
≥0.120, which requires **pydantic ≥2.9** — a hard conflict with the pinned
`attack-v19-core` (pydantic 2.7.4). Per the milestone rule not to break the
pinned ATT&CK integration, these are accepted residuals for this release.
Applicability note: several relate to multipart/form-data and large-upload DoS;
the Aegis API accepts JSON only and enforces an application-level body-size
limit (Phase 5), reducing practical exposure. **Tracked for a future core
bump.** This is a documented BLOCKER for a fully clean dependency audit.

### Frontend (npm audit) — documented residual
`react-router-dom` has 2 moderate advisories (GHSA-wrjc-x8rr-h8h6 open-redirect
in `<Link>`/`useNavigate`; GHSA-337j-9hxr-rhxg SSR-hydration constructor
injection). The fix is a **breaking major (react-router 7)**. The dashboard is a
**client-side-only SPA with no SSR**, so the SSR-hydration advisory does not
apply; the open-redirect is low practical risk behind authenticated,
same-origin usage. Deferred to avoid destabilizing the verified build; tracked
for a planned react-router 7 migration.

### SBOM
`security_scans/sbom-aegis.json` (CycloneDX) enumerates the runtime component
tree for the platform.

### Secret scan — PASS
No real credentials in tracked files. The only matches are clearly-synthetic
test fixture passwords (e.g. `pw-strong-aaaa`) used to seed test users; these
are not usable credentials and are confined to test modules.

## Verdict for Phase 9
Actionable high-value items (python-jose/ecdsa) **resolved**; starlette
materially improved. Remaining residuals are **version-pin-constrained** and
documented with applicability. Clean-audit status is **BLOCKED** by the
pinned-core pydantic constraint, not by unaddressed negligence.
