# Contribution and Access Policy

> **READ THE [LICENSE](LICENSE) FIRST.** This repository is owner-maintained and proprietary. **All Rights Reserved** for original material owned by Pooja Kiran.

## No standing authorization

This repository does not accept unsolicited source-code, test, documentation, or asset contributions. Posting the repository publicly does not authorize anyone to copy/paste its protected contents into other projects; modify, republish, redistribute, sublicense, commercially exploit, or create derivative works from them; or use them in another product without prior written authorization from the applicable rights holder. GitHub's applicable Terms of Service, valid prior licenses, third-party rights, and statutory exceptions remain unaffected.

## Explicitly authorized work only

The owner may separately authorize a person or organization in writing to propose changes. Such an authorization must specify the permitted scope and does not grant wider rights. If an external contribution is proposed, copyright ownership and any needed written contributor agreement or assignment must be resolved before acceptance; unsolicited PR submission is not itself an ownership transfer.

## Issues and security disclosures

Constructive factual issue reports are welcome without including copied proprietary material. Report vulnerabilities using the private instructions in [SECURITY.md](SECURITY.md) rather than public exploit details. Reporting an issue does not grant permission to use or modify repository materials.

## Previously granted and third-party rights

Rights already validly granted under earlier MIT, Apache-2.0, or other terms (where applicable) remain effective for the versions and portions covered by those grants. Third-party components and datasets remain subject to their own rights, notices, and attribution requirements.

For licensing requests, contact poojakiranbhardwaj@gmail.com. No permission is implied from silence.

## Current authorized development

Use [README setup](README.md#start-locally), [developer/test prerequisites](docs/WORKBENCH.md#testing-evidence-and-security-autopsy), and [operations](RUNBOOK.md). Full tests drop all ORM tables: explicitly isolate the test database from retained/user data. Pin the exact core and verified ATT&CK bundles; do not substitute an API-incompatible build with the same version label.

Run applicable full regression/browser/security/type/build/doc gates after source freeze and publish only actual exact-source outcomes. Keep unchanged blocking thresholds, preserve skipped/failed checks and source-scope historical reports. Use synthetic inputs and out-of-tree evidence; never publish secrets, tokens, clinical data or private recovery backups. Do not turn a loopback development workflow into a public service or bypass checks to obtain green results.

Explain the concrete behavior, code/doc changes, validation and remaining risk in a reviewed proposal. Retain active/unique work and safe recovery points before any separately authorized cleanup. Default merge, deployment, package/container publication and external data/notifications require their own explicit scope and readiness gates. See [documentation audit](docs/DOCUMENTATION_AUDIT.md) and [historical provenance](PROVENANCE.md).
