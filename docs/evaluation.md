# Evaluation protocol

## Frozen experimental design

Six hosts, two OpenFlow 1.3 switches, a ten-second window, a five-second statistics
poll, and rolling per-host profiles. Warmup lasts 135 seconds: two minutes of
profiling plus a 15-second scheduling/closed-window allowance. This buffer is
used consistently, including calibration.

The detector weights, variance floors, profile update policy, and workload
parameters are design choices fixed before calibration. Three calibration runs
each observe ten minutes of normal traffic after warmup. The background rate
changes from 1.5 to 3 exchanges/second halfway through observation. Real HTTP
probes run every two seconds throughout. For each decision threshold, choose
`ceil(1.25 * maximum observed normal-only value + 1)`. Save every calibration
observation, maxima, and the resulting thresholds. Attack outcomes never select
thresholds. This conservative calibration may reduce attack coverage; report it.

The experiment contains 95 evaluation trials, not 105: five repeats of C1–C7
without mitigation, five repeats of C2–C6 with each detector actuating separately,
five benign peer-communication variations, and five reversed C7 sequences. C7
contains sequential contact, port scan, and SYN retry; DoS is in C3. The fixed
attack workload is independent of calibrated thresholds. Baseline detections
are valid outcomes even in the sequential-contact case.

Use C2–C5 as the primary per-class comparison, and mixed C6/C7 as secondary
results. Online profiles keep learning, including during attacks. The reversed
sequence explicitly tests this order dependence. Benign peer communication is
an intentionally changed workload, not additional calibration data.

## Integrity and provenance

A manifest captures Git revision, content hash of implementation/build/tests,
working-tree status, image ID, dependency inventory, configuration, platform,
seeds, and matrix. The uncommitted content hash matters because the experiment
may precede a user-created commit. One fresh container executes each trial.
Source changes stop campaign resumption; use a new campaign after changes.

All background processes remain alive until the attack sequence and 45-second
drain finish. A nonzero attack exit, missing/aborted truth, controller failure,
incomplete switch connections, missing receiver logs, absent successful HTTP
probes, or insufficient profiling invalidates a run. Failed attempts are
retained, excluded, and retried once with the same seed. No validity rule checks
whether a detector won or whether a false positive occurred.

## Detection metrics

Candidates are logged before cooldown suppression. Attacker identification is
an unambiguous candidate from the attack source whose observed window overlaps
the first-to-last malicious-send interval. More than one matching attack is
ambiguous and is not credited to either. Class-exact detection additionally
requires the correct attack category. All attack misses remain in denominators.

Precision uses unambiguously matched candidates divided by non-ambiguous
candidates; ambiguous and unmatched counts are also shown. Operational alert
counts are separately reported after cooldown. Eligible benign source-host/windows
have a ready profile, are outside warmup, and do not overlap that source's attack.
False-positive rate is the proportion of these pairs with at least one candidate.
Repeated candidates cannot inflate that numerator. Completed windows alone are
used; legacy logs without this information cannot provide this rate.

Headline coverage excludes mitigation, calibration, pilot, and invalid runs.
Report primary, mixed, and pooled detection cohorts separately. Wilson 95%
intervals describe uncertainty in the observed proportions; pooled multi-attack
trials contain dependent observations, so those intervals are descriptive rather
than evidence of independent replication.

## Timing, blocking, and disruption

Version 2 events carry absolute monotonic and wall clocks plus stable alert,
decision, and rule identifiers. MTTD uses actual alert creation minus the first
malicious send, only for detected attacks. A timestamp brackets a Scapy send
call; it is a sender observation, not a hardware wire timestamp.

Alert-to-decision, decision-to-all-target-switch-confirmation, and per-rule
FlowMod-to-barrier latency are distinct. Missing timestamps are unavailable.
The complete targeted switch set must confirm the same decision; an unrelated
later barrier cannot establish containment. Per-trial timing summaries receive
equal weight, with count, mean, median, minimum, and maximum.

Attack packets carry an IP TOS marker used only by independent receiver
observation, never as a detector feature. Blocking verification requires at
least three seconds of subsequent malicious sending, positive matching drop
counters, and stable receiver counts over at least two samples at every target
after confirmation. Otherwise blocking is unverified, even if rules were
confirmed. Report rule confirmation delay separately from observed blocking.

HTTP clients record success, failure, and response latency. Compare the final
30 seconds before evaluation, attack intervals, and recovery. Report innocent
clients separately from legitimate service requests on the compromised host.
The service is deterministic and independent of fabricated TCP background
payloads. Idle-timeout blocks need not expire under continuing source traffic;
recovery failures are meaningful observations, not reasons to discard a run.

## Resources and limitations

Resource and detector-compute measurements separate warmup and evaluation.
Export CPU, RSS, PacketIn, flow-statistics requests/replies, graph construction,
betweenness, and detector timing. Report current sampled forwarding/mitigation
entry counts per switch and peak total occupancy; retired mitigation rules are
removed from active tracking. Software OVS occupancy is not hardware TCAM.

The collector records OpenFlow observations, not a lossless packet capture.
Cross-switch observations and controller/switch reporting can affect apparent
volume; thresholds and comparisons refer to this shared observation pipeline.
Synthetic brute force and lateral movement model communication patterns only.
The normal workload is narrow, and robustness checks do not establish production
accuracy, multi-controller scalability, or adversarial robustness.

## Repaired measurement protocol (version 2)

New runs explicitly bind each receiver to its host interface, record sniffer
readiness, and require five separately marked diagnostic packets at every host
before warmup. Diagnostics do not enter attack counts or ground truth. Missing
capture readiness or health invalidates a run regardless of detector outcomes.

Scan and authentication-port SYN generators optionally repeat for a fixed
send duration. Evaluation uses 40 seconds for scan, SYN retry, and flood in
all conditions; lateral pacing remains unchanged. Detector settings and the
existing normal-only calibration are reused with recorded checksums and origin.
Longer workloads can change detection outcomes; report this as a new campaign.

Blocking analysis requires healthy receiver evidence, correlated switch
confirmation, at least three seconds of remaining malicious sending, matching
counter increases, and stable attack counts at all targets across two or more
samples after a one-second settling allowance. Report observed leakage, absent
confirmation, insufficient ongoing traffic, unavailable capture, and absent
counter increases explicitly. All attacks remain in overall denominators;
report testable records separately. Source-wide counters include legitimate
source traffic; counter increases alone cannot prove attack containment.

Historical CSV regeneration keeps its original protocol unchanged. Its
"verified" records must be presented as counter-based outcomes with receiver
delivery unavailable, because every historical capture selected loopback.
