# Lantern Core Evaluation Report

**Status:** complete for the requested 225-run core boundary. Generated 2026-10-30 (Asia/Kolkata).

## Scope and completion

| Phase | Planned | Valid unique | Included |
|---|---:|---:|---|
| Historical 20-host detection | 80 | 80 | Yes |
| Historical history-based control | 20 | 20 | Yes |
| Hybrid C2–C5 | 80 | 80 | Yes; C5 trial 10 completed by preserved repair run |
| Sensitivity sweep | 45 | 45 | Yes |
| C5 policy comparison | 80 | 0 | Intentionally not started in the core campaign |
| **Core total** | **225** | **225** | **Complete** |

The core contains 225 valid, unique evaluation identities: 100 immutable historical runs, 80 hybrid runs, and 45 sensitivity runs. Failed attempts and calibration/preflight activity are not counted as trials. The 80-run C5 policy phase remains separate and was not launched under the time-limited core decision.

## Evidence handling

Analysis was rebuilt from the deduplicated valid evidence staged in `evidence/`, rather than from progress messages. The staging selection uses validity records and semantic run identity, preserves the original run bundles, and includes the repaired C5 hybrid trial 10 only because its repair validity record is true. Earlier invalid attempts remain in their original campaign directories and are excluded from the tables.

The sensitivity runs use the recorded topology metadata; the staged runs report a 20-host topology. Threshold files and historical evidence were preserved. No thresholds were changed and no validity check was bypassed.

## Analysis outputs

The generated CSV tables include coverage, detections, attacks, timing, containment, disruption, overhead, detector cost, installation, evidence mapping, and validity. `coverage.csv` reports trial-level Wilson intervals where applicable; missed detections are represented separately from unavailable evidence by the analysis pipeline.

Figures are generated from the staged evidence and are retained alongside the tables. Conclusions about C5 policy containment, source-versus-pair policy comparison, and C2–C4 policy behavior are not available because that phase was deliberately excluded from this core report.

## Reproduction commands

Rebuild the core tables with:

```powershell
python -m experiments.analyze --raw results/reports/native-core-20261030-final/evidence --output results/reports/native-core-20261030-final/tables
```

Check the completed supervisor record with:

```powershell
Get-Content results/campaigns/native-extended-20-v6-continuation-20261029-r9-core/supervisor.stdout.log -Tail 20
```

The r9-core supervisor ends with `supervisor complete`; no continuation process is required for the completed core. The policy phase must not be inferred from this report.

## Limitations

- This is a clearly labelled 225-run core report, not a completed 305-run evaluation.
- Policy results are pending and preserved separately; C5 policy conclusions cannot be reported here.
- One hybrid identity required a valid repair after earlier invalid attempts. Those invalid attempts remain preserved and are not counted.
- Sensitivity precision is five trials per setting; uncertainty should be interpreted accordingly.
- Historical and continuation provenance should be cited from their campaign manifests and source metadata when preparing the manuscript.
