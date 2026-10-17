# Results and conclusion

These are the results of the repaired campaign
`results/campaigns/submission-20261012-measurement-v3`, whose curated evidence is
in [`submission-repaired-20261012/`](../submission-repaired-20261012/). It ran all
95 evaluation conditions with no invalid attempts, and every one of its 570
receiver logs passed a capture health check, so blocking outcomes rest on
attack packets actually counted (or not) at each target. The same numbers,
with figures, are in `output/pdf/results-summary.pdf` and `results-report.pdf`
(`python3 -m replay.report`).

## Conclusion

In controlled SDN simulations, the graph detector improved lateral-movement
classification and blocking compared with the calibrated threshold baseline.
Both detectors identified the attacker in all five primary lateral trials, but
only the graph classified the attack correctly (5/5 vs 0/5). That label decided
the block. Across the ten lateral blocking records, the baseline's narrow rule
let attack packets reach other hosts in all ten, while the graph's source-wide
block was verified in nine and leaked in none.

This does not establish overall graph superiority. The baseline detected and
correctly classified scans, floods and SYN retries, and its blocks against them
held; the graph missed floods and SYN retries and gave scans a generic label.
The detectors have complementary strengths. Running both, with the graph's label
choosing the block scope, is the recommended design, but that combined policy
was not itself evaluated.

## Detection

Five mitigation-disabled trials per attack. "Found" means an unambiguous flag
on the attacker in a window overlapping the attack; "named" additionally
requires the correct attack class. Wilson 95% intervals: 5/5 → 57–100%,
0/5 → 0–43%.

| Attack (case) | Baseline found / named | Graph found / named | Mean delay (s), baseline / graph |
| --- | ---: | ---: | ---: |
| Port scan (C2) | 5/5 / 5/5 | 5/5 / 0/5 | 4.55 / 4.55 |
| Flood (C3) | 5/5 / 5/5 | 0/5 / 0/5 | 14.48 / — |
| SYN retry (C4) | 5/5 / 5/5 | 0/5 / 0/5 | 4.50 / — |
| Lateral movement (C5) | 5/5 / 0/5 | 5/5 / 5/5 | 4.52 / 4.52 |

- The baseline misnamed lateral movement because one contact was a SYN to
  h1:22, which tripped its SYN-retry rule (threshold: more than one attempt)
  first, in all five trials.
- Floods and SYN retries target one host the attacker already talks to, so the
  structural features barely change. Packet volume is one of the graph's
  features, but with its fixed weight (0.3) these workloads did not produce
  scores above the threshold.
- The graph flagged scans as a generic graph anomaly: many ports, few hosts.
- Detection delay is the wait for the current 10-second window to close. The
  flood rule needs two windows, hence about 14.5 s.

## False alarms

| Workload | Baseline | Graph |
| --- | ---: | ---: |
| Scheduled legitimate changes in who talks to whom | 31/297 windows (10.44%) | 16/297 (5.39%) |
| Ordinary traffic in the detection runs | 4/1,868 | 0/1,868 |
| Reversed attack order runs | 0/390 | 0/390 |

Rates use detector candidates before cooldown suppression. Both detectors
produce false alarms when legitimate traffic changes.

With the C7 attack order reversed, the baseline still found every attack
(5/5 each). The graph found the lateral movement in 5/5, the scan in 1/5 (with a
wrong label) and the SYN retries in 0/5. Both detectors keep learning during
evaluation, so detection depends on attack order.

## Blocking

A block is **verified** when every targeted switch confirmed the rule, the
attacker kept sending for at least 3 s afterwards, the rule's drop counter
rose, and receiver counts stayed flat at every target for at least two samples
after a one-second settling allowance. **Leakage** means attack packets reached
a target after confirmation. Every attack stays in the denominator.

| Attack | Baseline | Graph |
| --- | ---: | ---: |
| Port scan (primary and mixed) | 5/10 verified (no rule in 5 mixed) | no rule 0/10 |
| Flood | 5/5 verified | no rule 0/5 |
| SYN retry | 5/5 verified | no rule 0/5 |
| Lateral movement (C5 and C6) | **leaked 10/10** | **9/10 verified**, 0 leaked |
| All records | 15/30 verified (15/25 testable) | 9/30 verified (9/10 testable) |

In nine of the ten lateral records, both detectors confirmed their block about
4.5 s after the first attack packet, when only the first host had been
contacted. The baseline acted on its SYN-retry label and blocked only
`h4 → h1:22`, so the attack went on to reach three or four more hosts each time.
The graph blocked all traffic from h4, and nothing more arrived. The remaining
graph record (C5 trial 1) confirmed late, at 14.6 s, and its drop counter did not
rise, so it is unverified rather than verified or leaked.

C6 runs contain two attacks (lateral movement, then a scan), so each actuator
has 30 attack records across its 25 blocking runs.

## Innocent users and the attacker

| Blocking detector | Innocent, during attacks | Innocent, recovery | Attacker's own requests, during attack |
| --- | ---: | ---: | ---: |
| Baseline | 1,476/1,476 | 1,691/1,692 | 225/492 |
| Graph | 1,476/1,476 | 1,687/1,690 | 325/492 |

Every innocent request during attacks succeeded. The four recovery-period
failures remain in the results; their cause was not established. The attacker's
legitimate requests also fail, because source-wide blocks cover all of its
traffic.

## Timing and cost

| Measure | Baseline | Graph |
| --- | ---: | ---: |
| Detector compute per 10 s window | 0.15 ms | 1.64 ms |
| Alert → block decision (C5) | 2.87 ms | 3.04 ms |
| Decision → both switches confirm (C5) | 12.81 ms | 10.37 ms |

Detection-only runs averaged 3.84% controller CPU and 73.7 MiB RSS for the whole
application. These values describe this test environment, not deployment
capacity. Under the C3 flood, the baseline's decision-to-confirmation took about
463 ms.

## Limits

- Five trials per condition and one six-host, two-switch topology.
- Lateral movement is a sequential-contact pattern, not real compromise; SYN
  retries are repeated connection attempts, not password guessing.
- The baseline's lateral mislabel comes from its rule order and thresholds; a
  different rule priority might fix it without a graph, which was not tested.
- Verification covers the sampled interval; it is not a lossless wire capture,
  and source-wide drop counters can include the attacker's legitimate traffic.
- The comparison uses this calibrated baseline and graph configuration only;
  the combined policy is a proposal, not a measured result.

## Validation

Before the pilots, the research suite, 30/30 datapath pings and 13 live
integration checks passed. Afterwards, independent checks confirmed all 95
matrix conditions, their seeds and warmup, the frozen source and image
provenance, the imported calibration, 570 healthy receiver logs, every curated
checksum, and byte-for-byte regeneration of every published table. The research
suite now has 90 tests. Commands to repeat the verification are in the
[README](../README.md#evidence-and-verification).

- Frozen source content hash:
  `a77f8f748cabe612a6dea20801bd2146083f802452122d24119bd92d2c0e68d8`
- Container image:
  `sha256:42e24c106f14aae617598b849bbc1870c0021ec659c92fbe6d5df62fb8b34daf`

The raw-table summary that the campaign's analysis produced can be regenerated
with `experiments/report.py`.

## Historical campaign (22 September 2026)

The earlier campaign, kept in [`submission/`](../submission/), measured blocking
with receivers that did not name a network interface. Inside the Mininet hosts,
which have no default route, Scapy fell back to loopback, so every receiver
counted zero attack packets, even with mitigation disabled. Its short scans and
SYN retries also ended before a block could be tested. Its blocking verdicts are
therefore counter-based only and are superseded by this campaign.

Its detection results showed the same pattern: the baseline found every primary
attack, the graph missed floods and SYN retries, and only the graph named
lateral movement correctly (5/5 vs 0/5). Its changed-traffic false-alarm rates
were 30/273 (11.0%) for the baseline and 14/273 (5.1%) for the graph. Those
tables are kept unchanged for the record.
