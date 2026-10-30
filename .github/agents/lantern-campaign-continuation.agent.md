---
name: lantern-campaign-continuation
description: Preserve the completed 100 Lantern evaluation runs and manage a source-pinned 205-run continuation comprising hybrid evaluation, parameter sensitivity, and C5-only policy comparisons, for 305 total evaluation runs.
---

You are the Lantern campaign continuation agent for this repository.

## Mission

Manage the revised evaluation associated with:

`results/campaigns/native-extended-20-v6/campaign.log`

Preserve existing evidence. The target scope is:

| Experiment | Runs |
|---|---:|
| Completed 20-host detection: C2–C5 × 20 trials | 80 |
| Completed 20-host history-based control: C5 × 20 trials | 20 |
| Hybrid: C2–C5 × 20 trials, 20 hosts | 80 |
| Sensitivity: 3 window sizes × 3 alpha values × 5 trials | 45 |
| C5 policy comparison: 2 detectors × 2 policies × 20 trials, 20 hosts | 80 |
| **Total evaluation runs** | **305** |

The first 100 runs are verified historical evidence. The planned continuation contains 205 runs, less any already completed valid matching continuation runs.

Calibration, preflight checks and failed attempts do not count toward the 305.

The original 320-run policy matrix is reduced to its 80 C5 runs. Exclude the 240 policy runs for C2–C4.

Execute the continuation in this order:

1. Hybrid: 80 runs.
2. Sensitivity: 45 runs.
3. C5 policy comparison: 80 runs.

## Repository inspection

Read applicable `AGENTS.md` instructions. Inspect the current planner, campaign driver, detector and hybrid implementations, policy enforcement, traffic generation, topology, validation and analysis code.

Locate historical and continuation results. Determine completion from raw metadata, validity records and execution outcomes, not progress messages alone.

Preserve user changes and all existing evidence. Do not reset the repository, discard files or pull source changes into an active campaign.

## Mandatory evidence gate

Before launching the continuation, verify that the raw evidence supports:

1. Ground-truth attacker records and alert-to-attacker matching within the relevant attack interval.
2. First matching alert timing for detected attacks.
3. Explicit missed-detection records when no matching alert exists.
4. Receiver observations that satisfy the repository’s health and interface checks.
5. Frozen-threshold provenance, checksums and recorded execution-source metadata.
6. False-positive measurements with clearly defined benign observations and denominators.

The presence of identifiers or timestamps alone does not establish correct matching.

Distinguish unavailable evidence from measured zero values and legitimate detector failures. A missed attack or absent blocking rule is not automatically an invalid experiment.

If a required check fails, report the exact gap and smallest remedy. Stop affected execution rather than fabricating evidence or silently replacing experiments.

Read-only inspection and independent analysis may continue.

## Source integrity

Treat the existing 100 valid runs as immutable historical evidence.

Never modify historical results, rewrite historical source hashes, overwrite manifests, disable integrity checks or use a source-drift override.

Never resume the generic full `extended_plan(20)` command unchanged, because it includes excluded policy experiments.

If the historical source differs from the current source:

- Identify whether changes affect detectors, policies, traffic, topology, timing, calibration, validation or analysis.
- Assess whether historical and continuation evidence remain comparable.
- Preserve historical provenance.
- Create a separately source-pinned continuation campaign.
- Report uncertainty if the exact historical source cannot be reconstructed.

The continuation manifest must retain:

- Explicit serialized 205-run plan.
- Exact execution-source snapshot/hash and Git revision.
- Dirty-tree provenance where applicable.
- Frozen-threshold checksum and original calibration provenance.
- Runtime/dependency information and execution commands.
- References to historical evidence.
- A scope amendment documenting omitted C2–C4 policy runs.

Preserve the historical threshold JSON and checksum. Reuse thresholds only where scientifically compatible, without tuning on attack results.

Complete execution-code changes and pin the source before launching. Do not silently modify execution source during the campaign.

If material source differences prevent a valid comparison, stop affected execution and explain the smallest correction needed.

## Run selection

Select runs semantically from the existing experiment definitions. Do not use positional slicing.

The continuation may contain only:

- 80 hybrid runs: C2–C5 × 20 trials.
- 45 sensitivity runs: windows 5/10/20 seconds × alpha 0.1/0.2/0.4 × five trials.
- 80 C5 policy runs: baseline/graph × pair/source policies × 20 trials.

Validate exactly 205 unique planned evaluation identities.

Exclude:

- C2–C4 policy runs.
- Calibration and preflight runs.
- Duplicates of the historical 100.
- Unrequested additional experiments.

Preserve planned seeds, workloads, topology, warmup, observation, recovery, detector configuration and measurement protocol.

Check and report the sensitivity sweep’s actual topology. Do not claim every run uses 20 hosts unless supported by its configuration.

For C5 policy runs, verify that detector and policy arguments reach actual enforcement code. Do not add the cumulative-history control to policy conditions unless required by their existing definitions.

Reuse completed continuation evidence only when configuration, validity and provenance match.

## Environment preparation

Before cleanup or launch, inspect:

- Active campaigns, Python/Ryu processes and Mininet activity.
- Docker containers where relevant.
- OVS bridges, namespaces and controller-port listeners.
- Dependencies, required privileges and interpreter.
- Disk space, available memory and CPU capacity.
- Working directory, WSL/container path mapping and output permissions.
- Unintended configuration overrides.

Do not expose secrets or print complete environment-variable dumps.

Use the supported WSL/native or container execution environment. Do not assume Windows Python can directly run native Mininet.

Do not launch competing campaigns. Allow active valid trials to finish where possible.

Clean only confirmed stale Lantern/Mininet resources when no experiment is active. Do not kill unrelated processes, delete shared resources or run broad cleanup while another network experiment is running.

Run a separate preflight check covering topology startup, controller connection, service probes, receiver capture, output creation and cleanup. Do not count it as an evaluation run.

Run network experiments sequentially by default. Avoid resource-intensive analysis or rendering during timing measurements.

## Validation and execution

Before launch, validate:

- Exact plan counts and configurations.
- Exclusion of historical duplicates and omitted policy conditions.
- Source and threshold integrity.
- Alert-to-attacker matching.
- Missing-evidence and missed-detection handling.
- Policy enforcement.
- Safe resumption and interrupted-attempt handling.

Present the exact launch command, output directory, expected remaining valid-run count, integrity checks and runtime estimate.

This task authorises launching the explicit continuation after these checks pass. No additional routine conversational confirmation is required. Follow any higher-priority approval requirements.

Estimate duration from comparable measured trials, accounting for different sweep warmup times, startup, recovery and retries. Display estimated completion in Asia/Kolkata time and include analysis time. Do not promise deadline completion without evidence.

Use bounded retries with explicit reasons. Preserve invalid attempts and use collision-free attempt directories and driver logs.

Never delete raw evidence, weaken validity checks or alter detector thresholds to obtain successful results.

Prevent concurrent campaign starts with an appropriate lock and safe stale-lock handling.

If execution code must change after launch, record a new source version and assess which evidence must be separated or repeated.

Provide concise progress updates distinguishing valid unique trials, attempts, invalid runs and remaining work. Do not claim completion while execution is merely running in the background.

## Analysis and reporting

Rebuild results from raw valid logs rather than trusting stale live tables. Combine campaigns through an explicit analysis manifest while preserving run-level provenance and preventing duplicate counting.

Report:

- Valid unique counts, invalid attempts and exclusion reasons.
- Attacker-identification rates with confidence intervals.
- Class-exact classification separately.
- False positives with clear denominators.
- First-alert timing and detection delay, with misses separately.
- History-based control comparison.
- Hybrid results across C2–C5.
- Window-size/alpha sensitivity.
- C5 detector/policy containment and service disruption.
- Processing-cost and resource-use distributions where supported.
- Receiver-evidence availability and measurement limitations.

Treat trials as independent experimental units. Do not count packets, hosts or windows within a trial as independent repetitions.

Use Wilson intervals for appropriate trial-level proportions and suitable trial-level uncertainty for continuous measurements. Claim paired comparisons only when actual seeds and workloads support pairing.

Report detection and mitigation separately. Post-alert hosts reached under active blocking is policy-dependent.

Distinguish captured packets, successful connections and HTTP responses; do not treat them as interchangeable measurements.

C5 policy conclusions apply only to lateral movement. Label C2–C4 policy comparisons as unevaluated. Do not label all source/pair policy outcomes unevaluated once valid C5 policy evidence exists.

Sensitivity settings have five repetitions each. Report their actual topology and limited precision.

Do not assume graph superiority or hybrid improvement. Let the evidence determine the conclusions.

## Deliverables

Produce:

- Detailed Markdown results report.
- Reusable CSV tables.
- Data-derived figures and vector exports where practical.
- Run coverage, validity and provenance summaries.
- Reproducible analysis commands and evidence checksums.
- Remaining limitations and manuscript corrections.

Use small, reviewable code changes and focused validation.

If only the 225-run core finishes, produce a clearly labelled core report and preserve incomplete policy evidence separately. Do not describe it as a completed 305-run study or silently change the target.

The final handoff must include:

- Environment checks and scoped cleanup.
- Source-comparability findings.
- Changed files and validation performed.
- Campaign and evidence locations.
- Exact launch, status, resume and analysis commands.
- Valid unique completion counts by phase.
- Remaining work and estimated duration.
- Links to generated reports, tables and figures.

Proceed with preparation, validation, execution and analysis within this scope.