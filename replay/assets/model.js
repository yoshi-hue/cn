// Pure reconstruction makes scrubbing and playback yield identical state.
export const milestones = new Set(['attack_started','attack_ended','detector_candidate','alert','mitigation_decided','flowmod_sent','barrier_reply','all_switches_confirmed','mitigation_expired','blocking_assessment']);
export function snapshot(run, time) {
  const events = run.events.filter(e => e.time !== null && e.time <= time);
  const byKind = kind => events.filter(e => e.kind === kind);
  const detectors = {};
  for (const name of ['baseline','graph']) {
    const candidates = byKind('detector_candidate').filter(e => e.data.detector === name);
    const alerts = byKind('alert').filter(e => e.data.detector === name);
    detectors[name] = {candidates, alerts, latest: candidates.at(-1) || alerts.at(-1) || null};
  }
  const receivers = {};
  for (const e of byKind('receiver')) receivers[e.data.dst] = e;
  const resources = byKind('resource_sample');
  return {events, detectors, receivers, resource:resources.at(-1) || null,
    trail:events.filter(e => milestones.has(e.kind)), probes:byKind('probe'),
    activeAttacks:run.truths.filter(a => a.first_send != null && a.last_send != null &&
      a.first_send-run.start_wall <= time && a.last_send-run.start_wall >= time),
    period:run.evaluation_start == null ? 'Evaluation boundary unavailable' :
      time < run.evaluation_start ? 'Warmup / pre-evaluation' :
      run.recovery_start != null && time >= run.recovery_start ? 'Recovery' : 'Evaluation'};
}
export function eventStep(run, time, direction) {
  const values = [...new Set(run.events.filter(e => e.time !== null && milestones.has(e.kind)).map(e=>e.time))].sort((a,b)=>a-b);
  return direction > 0 ? values.find(t=>t>time+0.000001) ?? run.duration : values.reverse().find(t=>t<time-0.000001) ?? 0;
}
export function receiverSeries(run, events) {
  if (run.metadata?.measurement_protocol_version !== 2) return {};
  const groups = {};
  const sources = new Set(run.truths.map(t => t.src).filter(Boolean));
  for (const event of events.filter(e => e.kind === 'receiver')) {
    const counts = event.data.counts || {};
    // Only attack sources: replies from targets inherit the marking but are not attack traffic.
    for (const src of sources) {
      const key = `${src}|${event.data.dst}`;
      (groups[key] ||= []).push([event.time, counts[src] || 0]);
    }
  }
  return groups;
}
// Window around recorded attack activity, so short attacks are not a sliver of a long warmup.
export function focusWindow(run) {
  const rel = t => t == null ? null : t - run.start_wall;
  const sends = run.truths.flatMap(a => [rel(a.first_send), rel(a.last_send)]).filter(t => t != null);
  const marks = run.events.filter(e => e.time !== null && milestones.has(e.kind) && e.kind !== 'blocking_assessment').map(e => e.time);
  const from = sends.length ? Math.min(...sends) : (run.evaluation_start ?? 0);
  const to = Math.max(from, ...sends, ...marks.filter(t => t >= from));
  return {start: Math.max(0, from - 12), end: Math.min(run.duration, to + 15)};
}
// Drop rules a switch has confirmed and not yet reported expired, keyed by switch id.
export function activeRules(events) {
  const rules = {};
  for (const e of events) {
    const key = `${e.data.dpid}|${e.data.cookie}`;
    if (e.kind === 'barrier_reply') rules[key] = e;
    if (e.kind === 'mitigation_expired') delete rules[key];
  }
  const bySwitch = {};
  for (const e of Object.values(rules)) (bySwitch[String(e.data.dpid)] ||= []).push(e);
  return bySwitch;
}
// Review 1 pipeline: A collection, B/C detection, decision, D installation, retrospective verification.
export function pipeline(run, state) {
  const decisions = state.events.filter(e => e.kind === 'mitigation_decided');
  const actuating = decisions.filter(e => e.data.actuate);
  const confirmed = state.events.filter(e => e.kind === 'all_switches_confirmed');
  const assessment = state.events.filter(e => e.kind === 'blocking_assessment');
  const mitigation = run.metadata.mitigator !== 'none';
  return {
    collect: state.period.startsWith('Warmup') ? 'warmup' : 'active',
    baseline: state.detectors.baseline.candidates.length ? 'flagged' : 'idle',
    graph: state.detectors.graph.candidates.length ? 'flagged' : 'idle',
    decide: actuating.length ? 'actuating' : decisions.length ? 'observe' : 'idle',
    install: !mitigation ? 'disabled' : confirmed.length ? 'confirmed' : actuating.length ? 'pending' : 'idle',
    verify: !mitigation ? 'disabled' : !assessment.length ? 'pending' :
      run.metadata.measurement_protocol_version !== 2 ? 'unavailable' :
      assessment.some(e => e.data.observed_blocking === 'verified') ? 'verified' : 'unverified'};
}
