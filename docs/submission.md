# Submission and reproduction checklist

1. Build the pinned container and run `make validate`, `make datapath-check`, and
   `make integration`. Keep the gate output with the final evaluation notes.
2. Create a new campaign, run its pilot, freeze normal-only calibration, and
   execute the evaluation matrix. Never combine final and legacy runs.
3. Analyze the selected campaign. Inspect `validity.csv` and all failed attempts.
   Confirm all 95 conditions have a valid trial and keep unsuccessful attempts.
4. Curate using `experiments.package`. The curation gate rejects incomplete
   matrices. It copies allowlisted raw evidence and regenerates tables.
5. Run `make verify`: checksums must match and every CSV must reproduce exactly.
   Coverage has an explicit evidence map; other tables retain per-run IDs.
6. Run `make package`. Inspect the archive inventory; source and curated evidence
   are included, while Git internals, caches, scratch data, and unrelated files
   are excluded. Credential/local-path pattern scanning must report no findings.
7. Extract the archive into a clean directory and run the documented build,
   validation, and evidence verification commands. There is no install-time
   dependency on the original user's filesystem path.

`make clean` removes Python caches only. Deleting a disposable campaign requires
an explicit path under `results/campaigns/`; curated `submission/` evidence is
never deleted by cleanup commands. Source changes, commits, and pushes remain
under the team's control. No repository license has been assigned by automation.

## Repaired campaign

Run `bash scripts/run_repaired_campaign.sh` after `make build`, `make validate`,
`make datapath-check`, and `make integration`. It imports the historical
normal-only calibration with its checksum and provenance, runs 12 live pilots,
and freezes a separate evaluation campaign before running all 95 conditions.
The source and image must remain unchanged while a campaign runs. Detector
misses and observed leakage are results; unhealthy capture and insufficient
post-confirmation pilot traffic stop execution for inspection.

Outputs are separate: `submission-repaired-20261012/`, its generated Markdown
results report, and `output/lantern-repaired-20261012-replay.zip`. The original
`submission/` is preserved. Resuming repeats neither successful trials nor
invalid attempts; the existing two-attempt policy still applies. If pilot
repairs change source, supply fresh pilot and campaign directory names.
