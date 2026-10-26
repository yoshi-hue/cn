# Submission-complete evaluation matrix

The requested experiments are implemented in the existing campaign runner. A
run is valid evidence only when its raw JSONL, validity file, truth markers,
and timing samples are retained.

## Large topology and 20 trials

```bash
python3 -m experiments.run_all --extended > results/extended-plan.json
```

For execution after a normal-only calibration:

```bash
python3 -m experiments.campaign extended --campaign results/campaigns/extended-20
```

The extended plan contains four attack classes (port scan, DoS, brute force,
and lateral movement), 20 trials per class on a 20-host topology, a 3x3
window/alpha sweep, and 20 hybrid trials per attack class. Execute the plan
through the normal Docker campaign driver after calibration; do not treat the
plan itself as measured results.

Each run records `topology_size`, `window_seconds`, `profile_alpha`, detector
mode, and the common `class-equivalent-v1` mitigation policy in `run_start`.

## Control and hybrid conditions

`--cumulative-lateral` enables the control rule in
`lantern.detector_baseline.BaselineDetector`: it accumulates distinct initiated
destinations across windows and emits a `lateral` label once the configured
threshold is crossed. `--detector-mode hybrid` combines threshold and graph
alerts on the same window and records corroboration evidence when both agree.

## Figures and timing

`scripts/generate_figures.py` writes the vector architecture diagram and a
timeline derived from an actual trial JSONL. For example:

```bash
python3 scripts/generate_figures.py \
  --raw submission/evidence/benign/attempt-1/raw/benign-C1-none_trial01.jsonl
```

Detector processing cost is emitted per closed window as
`baseline_seconds`, `graph_total_seconds`, `graph_build_seconds`,
`betweenness_seconds`, and (for hybrid runs) `hybrid_total_seconds`.
