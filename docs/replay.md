# Recorded experiment replay

The replay reads the repaired campaign (`submission-repaired-20261012/`) by
default, where every receiver passed a capture health check, so the receiver
chart shows attack packets that actually arrived. To replay the historical
22 September campaign, whose receivers listened on loopback and counted nothing,
add `--submission submission`. The viewer then hides receiver counts and labels
its blocking outcomes as unavailable.

From the repository root, run `python3 -m replay serve --port 8000`, then open
http://localhost:8000. Stop the server with Ctrl+C. If the port is occupied,
choose another port, such as `--port 8001`. Python 3 is the only playback
dependency; no Docker, Node, network emulation, or internet connection is needed.

## Views

- **Results** (`#results`): a verdict and five questions (attacks
  caught, false alarms, did blocking work, innocent users, cost), each with one
  visual and a plain answer, plus collapsible definitions and Review 1 objectives.
  The numbers come from `replay/summary.py`, which reads the published tables
  (the PDF report uses the same module). Click a coverage row to replay that case.
- **Guided replay** (`#replay`): five chapters, each with "what to watch" and the
  five-trial result. The pipeline strip shows each stage as the run reaches it:
  Algorithm A collection, B/C candidates, decision, D rule confirmation, and the
  retrospective blocking verdict. Detector cards show source/class verdict chips
  and the score against its threshold; graph cards also list the top feature
  contributions. **Focus on attack** (on by default) zooms the timeline and
  charts to the attack and its response instead of the 135 s warmup.

## Present the project

Each chapter shows one recorded trial as an example; the "campaign results" line
beside it is computed from the published tables across all trials:

1. **Source versus class** (C5 detection, trial 1): both detectors flag h4 in the
   same window; only the graph labels it lateral movement.
2. **Baseline mitigation** (C5, baseline blocking, trial 1): the baseline's
   login-retry label produces a narrow h4 → h1:22 rule. Both switches confirm it,
   and the receiver chart then shows h2, h3 and h5 still receiving attack packets.
3. **Graph mitigation** (C5, graph blocking, trial 2): the graph blocks all of h4
   about 4.5 s in and the receiver chart stays flat. Trial 2 is used because it
   is typical; trial 1 is the one lateral record where the graph's block came
   late (14.6 s) and could not be verified.
4. **Legitimate change** (C1 benign, trial 1): scheduled legitimate changes
   produce false-alarm candidates. Cooldown can suppress operational alerts but
   not those candidates.
5. **Attack order** (reversed C7, trial 1): the online profiles make detection
   depend on attack order.

Use **Event →** to explain
milestones one at a time, or Play at 2× or 5× for a continuous walkthrough.
The slider supports backward scrubbing; each position is reconstructed from
observations up to that point. Changing chapters or trials resets to a paused
start. Expand **Browse all trials** to filter by phase, case, actuator, and trial. Pilot and calibration
remain labelled supplementary.

Deep links open a chapter at a moment: `#replay&chapter=2&at=confirm` jumps to
the block being confirmed, `at=detect` to the first detector flag, and `t=150` to
a given second. `#results` opens the results view.

Keyboard: Space toggles playback, Left/Right step milestones, Home restarts.
Native buttons, selects, and the slider retain their normal keyboard controls
when focused. Reduced-motion preferences disable decorative moving dashes.

## Read the visuals accurately

- Grey lines are fixed physical links. Dashed communication overlays represent
  recorded HTTP observations or receiver-count increases, not packet trajectories.
- Attack intervals and target rings come from experiment truth, not detector
  inference. Total sends are available; exact per-send timestamps are not.
- Receiver curves contain cumulative marked-traffic samples. Lines connect
  samples for readability; they do not supply missing packet arrival times.
- HTTP circles show successful request latency; crosses show failed requests.
  Innocent clients and the attack source are counted separately. In normal-only
  runs, the configured h4 source role is used for that display grouping.
- Detector candidates precede cooldown; operational alerts are separate. An
  unmatched candidate is not automatically labelled a false positive: consult
  the eligible-benign-window denominator in the published summary.
- An operational decision may be observation-only. A complete confirmation
  requires the same actuating decision's full targeted switch set. No block
  is inferred simply because a switch acknowledged a rule.
- Historical verified/unverified values are retained published assessments, not evidence of receiver delivery.
  It appears as a timeline event at run end and is always labelled retrospective
  in the results panel. Missing confirmation times stay unavailable.
- Expiry notifications and switch occupancy snapshots are separate measurements;
  stale or differing counts must not be treated as proof of forwarding recovery.

Expand **Trial results & event log** to inspect published outcomes and milestones.
Click an event in the trail to inspect its full JSON, actual/recorded clock,
stable identifiers, attribution, source filename, and line number. Evidence
links open the original allowlisted logs and CSV tables. The full historical
communication graph was not logged, so the replay does not reconstruct it.

## Export and validate

```sh
python3 -m unittest discover -s replay/tests -v
python3 -m replay export --output output/lantern-replay.zip
```

Export refuses to overwrite an existing ZIP. Extract into a fresh directory,
enter `lantern-replay/`, and run `python3 serve.py --port 8000`. The ZIP includes
the static viewer, deterministic data, referenced evidence, and checksums.
Both servers verify their inventory before starting and bind only to
`127.0.0.1`; unknown paths and directory listings are not served.

For optional developer checks of the pure browser state model, run
`node replay/tests/model.test.mjs`. Node is not a user-facing dependency.

This module and its tests live outside the frozen experiment source inventory.
Preparation verifies every curated checksum, refuses invalid or incomplete runs,
and writes only generated output. No experiment source, curated evidence, or
original submission archive is modified.

## Results documents

`python3 -m replay.report` verifies the curated checksums of the repaired
evidence, then prints two documents to `output/pdf/` with headless Chrome:
`results-summary.pdf` (the conclusion and the five evaluations) and
`results-report.pdf` (the same summary plus per-trial and per-record
appendices, timing, cost, the measurement repair and provenance). Pass
`--submission DIR` to build from another curated evidence set.
