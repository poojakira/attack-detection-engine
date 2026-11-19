# Release and deployment governance

**Decision: PARTIAL. No production deployment is approved.** Candidate software/API 1.1.0 and rule version `clinical-access-1.1` describe a functioning synthetic-data local workflow, not an operational certification.

## Promotion evidence

Freeze the exact code and documentation commit, then run complete applicable regression with real disposable PostgreSQL and ATT&CK prerequisites, browser E2E, negative/boundary/recovery checks, lint/type/security/dependency analysis, builds, migrations/package startup and documentation/example checks. Record real source/clean state, commands, UTC intervals, environment/dependencies, pass/fail/skip counts, coverage settings and artifact hashes outside the checkout. Preserve the 53% coverage gate and existing security thresholds; skipped, queued or unexecuted checks are not passes.

[Evidence status](docs/EVIDENCE.md) separates the published 8ae implementation proof, its independent review and blocked hosted state from pending later-head checks. The generic name Production Gate does not confer production approval. Dated October reports/scans are historical; their dependency-constraint explanations and Actions settings observations must not be assumed current.

## Outstanding properties

Full FHIR validation, real-patient privacy/use approval, clinical authorization context, representative efficacy/performance, parser/detector isolation and hard execution deadline, coordinated multiprocess quotas, externally anchored audit integrity, tested production backup/restore, clean-machine/container/runtime attestation and operational signoff remain missing or unverified. The input retains source JSON and can contain identifiers. No anonymization, HIPAA, enterprise deployment or field detection-rate claim is permitted.

The optional Compose stack and ASGI deployment entrypoint require operator-owned secrets, reviewed image digests, migrations/storage permissions, appropriate TLS/ingress and trusted identity policy. These are separate from the local launcher, which uses a named local volume and ephemeral signing secret. Production recovery and rollback need an exercised, compatible backup plan; normal container restart is not that proof. See [operations](RUNBOOK.md).

## Branches and publication

The owner-selected remote branch set is `main` and `codex/local-workbench-20261116`. Additional dependency and unique-work branches were retired only after exact-tip annotated recovery tags and verified private backups; unreviewed changes were not merged. See [selected branches and recovery](docs/BRANCHES.md). Earlier branch counts/dispositions remain historical. Security automation and protected-main checks remain enabled.

Use immutable non-release evidence tags for generated, hash-verified records. They are not software release tags. Review/merge, package/container publication, cloud resources and deployment are separate actions. No current documentation commit inherits an earlier commit's passing results.
