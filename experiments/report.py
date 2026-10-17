"""Generate a measured results report from a separately curated campaign."""
import argparse
import csv
import json
from pathlib import Path
from experiments.package import verify


def report(submission, output):
    verify(submission)
    manifest = json.loads((submission / 'manifest.json').read_text())
    def rows(name):
        with (submission / 'tables' / (name + '.csv')).open() as stream:
            return list(csv.DictReader(stream))
    text = ['# Repaired campaign results', '',
            'Measurement protocol 2: receivers explicitly select host interfaces and pass independent capture health checks.', '',
            'Thresholds reuse the historical normal-only calibration. Detector logic, weights, mitigation policy, seeds, warmup, and recovery are unchanged. Scan, SYN-retry, and flood workloads send for 40 seconds; longer workloads can change detection results.', '',
            '## Primary detection comparison', '',
            '| Workload | Detector | Source identification | Correct label | Mean detection delay (s) |',
            '| --- | --- | --- | --- | --- |']
    for row in rows('coverage'):
        if row['phase'] == 'detection' and row['cohort'] == 'primary':
            text.append('| %s | %s | %s/%s | %s/%s | %s |' % (
                row['attack_class'], row['detector'], row['detected'], row['instances'],
                row['class_exact'], row['instances'], row['mttd_mean'] or 'unavailable'))
    text += ['', '## Blocking evidence', '',
             '| Actuator | Workload | All records | Testable | Verified | Leakage | No confirmation | Too short | Receiver unavailable | Insufficient drops |',
             '| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |']
    for row in rows('blocking_summary'):
        text.append('| ' + ' | '.join(str(row[k]) for k in (
            'mitigator','attack_class','records','testable','verified','observed_leakage',
            'no_confirmation','insufficient_post_confirmation_traffic',
            'unavailable_receiver_evidence','insufficient_drop_evidence')) + ' |')
    text += ['', 'All attacks remain in the overall denominator. Testable records require sufficient ongoing sending and healthy receiver samples. Verification concerns the sampled interval after a one-second settling allowance; it is not a lossless wire capture. Source-wide drop counters also include legitimate source traffic.', '',
             '## Innocent HTTP delivery', '', '| Actuator | Period | Successful requests |', '| --- | --- | --- |']
    delivery = rows('disruption')
    for mode in ('baseline','graph'):
        for period in ('attack','recovery'):
            selected = [r for r in delivery if r['phase']=='mitigation' and r['mitigator']==mode and r['group']=='innocent' and r['period']==period]
            text.append('| %s | %s | %d/%d |' % (mode,period,sum(int(r['successes']) for r in selected),sum(int(r['attempts']) for r in selected)))
    validity = rows('validity')
    text += ['', '## Candidate precision and false alarms', '',
             '| Phase | Detector | Matched candidates | Unmatched | Ambiguous | Flagged benign windows |',
             '| --- | --- | --- | --- | --- | --- |']
    detections = rows('detections')
    for phase in ('detection','benign','order'):
        for detector in ('baseline','graph'):
            selected = [r for r in detections if r['phase']==phase and r['detector']==detector]
            total = lambda k: sum(int(r[k]) for r in selected)
            text.append('| %s | %s | %d | %d | %d | %d/%d |' % (
                phase,detector,total('matched_candidates'),total('unmatched_candidates'),
                total('ambiguous_candidates'),total('false_positive_host_windows'),total('benign_host_windows')))
    text += ['', 'Precision uses matched/(matched + unmatched); ambiguous candidates are reported separately. False-positive rates count unique eligible benign source-host/windows, before cooldown suppression.', '',
             '## Controller resources', '',
             '| Detection-only evaluation | Mean across trials |', '| --- | --- |']
    import statistics
    overhead = [r for r in rows('overhead') if r['phase']=='detection' and r['period']=='evaluation']
    for key,label,scale in [('cpu_percent_mean','CPU percent',1),('rss_bytes_mean','RSS MiB',1/1048576),
                            ('baseline_seconds_mean','Baseline compute ms',1000),('graph_total_seconds_mean','Graph compute ms',1000)]:
        values = [float(r[key])*scale for r in overhead if r[key]]
        text.append('| %s | %s |' % (label, '%.3f' % statistics.mean(values) if values else 'unavailable'))
    text += ['', '## Mitigation timing', '',
             '| Case | Actuator | Metric | Trials | Mean seconds |', '| --- | --- | --- | --- | --- |']
    for row in rows('timing_summary'):
        if row['phase']=='mitigation':
            text.append('| ' + ' | '.join(row[k] or 'unavailable' for k in ('case','mitigator','metric','n','mean')) + ' |')
    text += ['', '## Provenance and limits', '',
             '%d of %d retained runs passed validity checks. Failed attempts remain available and are excluded from measured aggregates.' % (sum(r['valid']=='True' for r in validity),len(validity)), '',
             'Source content hash: `%s`.' % manifest['source_hash'], '',
             'Calibration provenance: `%s`.' % json.dumps(manifest.get('calibration_provenance', {}),sort_keys=True), '',
             'Historical CSVs are preserved separately; their old verified blocking values are counter-based outcomes with receiver delivery unavailable. The lateral workload models sequential contacts, not host compromise; SYN retries do not perform authentication. Five trials per condition and this six-host topology limit generalization.', '']
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text('\n'.join(text))
    return output


if __name__ == '__main__':
    parser=argparse.ArgumentParser(__doc__)
    parser.add_argument('--submission',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    print(report(args.submission,args.output))
