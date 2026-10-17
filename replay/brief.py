"""Narrative of the results documents, built by `python3 -m replay.report`.

sections(R) is the results summary: the conclusion and the five evaluations.
appendices(R) adds the detail for the full report. R is the loaded report
module, which holds the verified tables and the shared figures and helpers.
"""

import statistics as st

from .summary import ATTACKS, NAMES


def sections(R):
    O, P, FP, DL, BK, pct, table, chip = R.O, R.P, R.FP, R.DL, R.BK, R.pct, R.table, R.chip
    fb, fg = FP("benign", "baseline"), FP("benign", "graph")
    fdb, fdg = FP("detection", "baseline"), FP("detection", "graph")
    bl, gl = BK("baseline|lateral"), BK("graph|lateral")
    cost = O["cost"]
    inn = {d: [DL("%s|innocent|%s" % (d, p)) for p in ("attack", "recovery")] for d in ("baseline", "graph")}
    lead_b, lead_g = R.arrivals("C5", "baseline", 1), R.arrivals("C5", "graph", 2)
    graph_delays = sorted(float(r["rule_confirmation_delay"]) for r in R.T["containment"]
                          if r["phase"] == "mitigation" and r["mitigator"] == "graph" and r["attack_class"] == "lateral" and r["rule_confirmation_delay"])
    typical = st.median(graph_delays)
    S = []

    S.append('''<section class="cover">
<p class="kicker">Final report</p>
<h1>Graph-Based SDN Controller-Integrated Intrusion Detection and Automated Mitigation</h1>
<p class="sub">Does a network-wide “who talks to whom” graph detect and stop internal lateral movement better than conventional threshold rules?</p>
<div class="answer"><p class="kicker">Conclusion</p>
<p><b>For lateral movement, yes. Overall, the two detectors are complementary.</b> Both detectors found the attacker in all five lateral-movement trials, but only the graph named the attack correctly (%d/5 vs %d/5). That label decided the block. In the ten lateral blocking tests, the baseline’s narrow rule let attack packets reach other hosts every time (%d/%d), while the graph’s block on all of the attacker’s traffic was verified in %d/%d with no leakage. The baseline covered more ground: it caught and blocked the scan, flood and login-retry attacks, which the graph missed or mislabelled.</p>
<p><b>Recommendation:</b> run both detectors, and let the graph’s label decide how wide the block should be. This combined policy is a proposal; it was not itself evaluated.</p></div>
<div class="kpis">
<div><b>%d/5 vs %d/5</b><span>lateral movement named correctly, graph vs baseline</span></div>
<div><b>%d/%d vs %d/%d</b><span>lateral blocks verified, graph vs baseline (baseline leaked in %d/%d)</span></div>
<div><b>4/4 vs 2/4</b><span>attack types detected, baseline vs graph</span></div>
<div><b>%s vs %s</b><span>false alarms when normal traffic changed, graph vs baseline</span></div>
<div><b>%s</b><span>innocent web requests served during attacks, under both detectors</span></div>
<div><b>%.2f ms</b><span>graph computation per 10 s window (baseline %.2f ms)</span></div>
</div>
<table class="meta"><tr><td>Team</td><td>Vatsala Rai (24BCE2803) · Yoshita Vanapalli (24BCE2812) · Jahnavi Sharma (24BCE2707) · Hasini (24BCE0342)</td></tr>
<tr><td>Evaluation</td><td>%d trials across seven scenarios, all valid</td></tr>
<tr><td>Date</td><td>12 October 2026</td></tr></table>
</section>''' % (P("lateral", "graph")["class_exact"], P("lateral", "baseline")["class_exact"], bl["leakage"], bl["records"], gl["verified"], gl["records"],
                 P("lateral", "graph")["class_exact"], P("lateral", "baseline")["class_exact"], gl["verified"], gl["records"], bl["verified"], bl["records"], bl["leakage"], bl["records"],
                 pct(fg["flagged"], fg["eligible"]), pct(fb["flagged"], fb["eligible"]),
                 pct(inn["graph"][0]["successes"], inn["graph"][0]["attempts"], 0),
                 cost["graph_ms"]["mean"], cost["baseline_ms"]["mean"], len(R.T["validity"])))

    S.append('''<section class="pb"><h2>The problem</h2>
<p>Attackers who get inside a network rarely stop at one machine. They move laterally: from the first compromised host they contact other internal machines one by one, looking for the next way in. Each of those connections looks ordinary on its own, so detectors that judge one flow at a time can miss the pattern or misread it as something else. And in most networks, detection and response are separate, so an alert waits for a person before anything is blocked.</p>
<p>Software-defined networking (SDN) offers a way to address both problems. Its central controller sees traffic statistics from every switch, so it can build a network-wide picture of who talks to whom, and it can push blocking rules into the switches directly. This project builds two detectors into one SDN controller and asks whether network-wide graph analysis detects, classifies and stops lateral movement better than conventional threshold rules, at acceptable cost and without disrupting legitimate users.</p>
<h2>How it was tested</h2>
%s<p class="cap">Emulated network: six hosts, two OpenFlow switches, one Ryu controller. h4 is the attacker.</p>
<ul>
<li><b>Two detectors, same traffic.</b> Both run inside the SDN controller and look at identical 10-second windows.
<ul><li><b>Threshold baseline:</b> fixed thresholds over per-source and per-pair statistics in each window, such as “more than %d ports”, “more than %d packets/s” or “more than %d login retry”.</li>
<li><b>Graph detector:</b> builds a who-talks-to-whom map each window and flags hosts whose connections change sharply from their own normal, for example many new neighbours at once.</li></ul></li>
<li><b>Automatic blocking.</b> When a detector raises an alert, the controller installs a drop rule on the switches. Its width depends on the attack label: one conversation for a login or flood attack, all of the host’s traffic for lateral movement or a scan. In each blocking trial only one detector may block.</li>
<li><b>Attacks (simulated):</b> port scan, flood (DoS), repeated login attempts (SYN retry), and lateral movement (one host contacting five internal hosts in sequence), plus mixed and reversed-order runs. Scans, floods and login retries send for 40 seconds.</li>
<li><b>Scale:</b> 35 detection-only trials, 50 blocking trials, 5 trials with legitimate traffic changes, 5 reversed-order trials. Thresholds were fixed from attack-free calibration before any attack was run.</li>
<li><b>Measurement:</b> a receiver bound to each host’s network interface counts the marked attack packets that arrive. Before every run, each receiver must count five separately marked diagnostic packets, or the run is invalid. A block is judged by what got through, not just by whether a rule was installed.</li>
</ul>
<div class="keep"><h3>How results were judged</h3>%s</div></section>''' % (R.svg_topology(), R.TH["PORTSCAN_PORTS"], R.TH["DOS_PPS"], R.TH["BRUTEFORCE_ATTEMPTS"], table(["Measure", "Meaning"], [
        ["Caught", "The detector flagged the attacking host during the attack."],
        ["Named correctly", "It also reported the right attack type."],
        ["False alarm", "A 10-second window in which a non-attacking host was flagged."],
        ["Rule installed", "Every switch targeted by the same blocking decision confirmed the drop rule."],
        ["Block verified", "After the rule was installed, the attacker kept sending for at least 3 s, the rule’s drop counter rose, and, after a one-second settling allowance, attack counts stayed flat at every target across at least two samples."],
        ["Leaked", "Attack counts rose at a target after the rule was installed and the settling allowance had passed."],
        ["Uncertainty", "Five trials per condition: a 5/5 result has a 95% interval of 57–100%, and 0/5 has 0–43%."]])))

    rows = []
    for a in ATTACKS:
        cell = lambda r: (chip(False, "missed") if not r["detected"] else chip(r["class_exact"] == r["instances"], "caught %d/5" % r["detected"] + ("" if r["class_exact"] == r["instances"] else ", wrong type")))
        rows.append(["<b>%s</b>" % NAMES[a], cell(P(a, "baseline")), cell(P(a, "graph"))])
    order = O["order"]
    ordtxt = lambda d: ", ".join("%s %d/%d" % (NAMES[a].lower(), order["%s|%s" % (a, d)]["detected"], order["%s|%s" % (a, d)]["instances"]) for a in ATTACKS if "%s|%s" % (a, d) in order)
    S.append('''<section><h2>Evaluation 1 · Detection</h2>
<p class="lead">The baseline caught every attack type. The graph caught the scan and the lateral movement, and it was the only detector that named lateral movement correctly.</p>%s%s
<p class="cap">Share of trials in which the attacker was caught, with 95%% intervals (grey: baseline, blue: graph). Five trials per attack, blocking switched off.</p>
<ul><li><b>Why the baseline misnamed lateral movement:</b> one of h4’s contacts was a connection to h1’s SSH port (22). That tripped the login-retry rule first in all five trials (“2 connection attempts to an authentication port”), so the baseline called the attack a login attack.</li>
<li><b>Why the graph missed floods and login retries:</b> both attacks hammer one host the attacker already talks to, so the structural features barely change. Packet volume is one of the graph’s features, but with its fixed weight (0.3) these workloads did not produce scores above the threshold.</li>
<li><b>Why the graph’s scan label was generic:</b> a scan touches many ports on one host, so the graph flagged it as a general anomaly rather than lateral movement. That label only logs; it does not trigger a block.</li>
<li><b>Speed:</b> the baseline detected scans, SYN retries and lateral movement about %.1f s after the attack began, and the graph detected scans and lateral movement at about the same time. That delay is the wait for the current 10-second window to close. The baseline took about %.1f s to detect floods, because that rule needs two windows.</li></ul>
<h2>Evaluation 2 · False alarms</h2>
<p class="lead">When normal traffic patterns changed legitimately, the graph raised about half as many false alarms as the baseline. Neither was alarm-free.</p>%s
<p>With ordinary traffic in the 35 detection runs, the baseline flagged %d of %s windows and the graph %d. When the attack order was reversed, the baseline still caught everything (%s). The graph caught the lateral movement but mostly missed the rest (%s), because both detectors keep learning as traffic arrives.</p></section>''' % (
        table(["Attack", "Threshold baseline", "Graph detector"], rows), R.svg_coverage(),
        P("lateral", "baseline")["mttd_mean"], P("dos", "baseline")["mttd_mean"],
        R.svg_bars([("Threshold baseline", fb["flagged"] / fb["eligible"], "base", "%s (%d of %d windows)" % (pct(fb["flagged"], fb["eligible"], 2), fb["flagged"], fb["eligible"])),
                    ("Graph detector", fg["flagged"] / fg["eligible"], "graph", "%s (%d of %d windows)" % (pct(fg["flagged"], fg["eligible"], 2), fg["flagged"], fg["eligible"]))], 0.15, lambda v: "15%"),
        fdb["flagged"], "{:,}".format(fdb["eligible"]), fdg["flagged"], ordtxt("baseline"), ordtxt("graph")))

    brow = []
    for a in ATTACKS:
        cells = []
        for d in ("baseline", "graph"):
            r = BK("%s|%s" % (d, a))
            if r["leakage"]:
                cell = chip(False, "✗ leaked %d/%d" % (r["leakage"], r["records"]))
            elif r["verified"]:
                cell = chip(True, "✓ verified %d/%d" % (r["verified"], r["records"]))
                if r["no_confirmation"]:
                    cell += ' <span class="small-note">no rule in %d mixed-run records</span>' % r["no_confirmation"]
            elif P(a, d)["detected"]:
                cell = '<span class="chip">no confirmed rule 0/%d</span> <span class="small-note">detected; label only logs</span>' % r["records"]
            else:
                cell = '<span class="chip">no confirmed rule 0/%d</span> <span class="small-note">not detected</span>' % r["records"]
            cells.append(cell)
        brow.append(["<b>%s</b>" % NAMES[a]] + cells)
    ab, ag = BK("baseline|all"), BK("graph|all")
    brow.append(["<b>All records</b>", "<b>%d/%d</b> verified (%d/%d testable)" % (ab["verified"], ab["records"], ab["verified"], ab["testable"]),
                 "<b>%d/%d</b> verified (%d/%d testable)" % (ag["verified"], ag["records"], ag["verified"], ag["testable"])])
    S.append('''<section><h2>Evaluation 3 · Did blocking stop the attack?</h2>
<p class="lead">Against lateral movement, the graph’s block held and the baseline’s leaked. Against the other attacks, only the baseline blocked, and its blocks held.</p>%s
<p>Both detectors installed their lateral-movement block quickly, about %.1f s after the first attack packet, when only the first host had been contacted. What differed was the rule. The baseline acted on its login-attack label and blocked one conversation (<code>%s</code>), so the attack went on to reach %s. The graph acted on its lateral-movement label and blocked all of h4 (<code>%s</code>), and no further attack packets were counted at any target during the measured interval.</p>
<div class="pair">%s%s</div>
<p class="cap">Attack packets from h4 counted at each target over time (C5, baseline trial 1 and graph trial 2). Red lines are targets reached after the block was confirmed.</p>
<p>The one graph record that was not verified (C5 trial 1) is an exception: its block came %.1f s in, after four hosts had been contacted, and its drop counter did not rise, so it is counted as unverified rather than as verified or leaked. Of the baseline’s 30 records, %d had no confirmed rule (scans inside the mixed runs); every other non-lateral block verified. Every attack stays in the denominator: overall, %d of %d baseline records and %d of %d graph records verified (%d of %d and %d of %d among records with enough traffic after the block to test).</p>
<h2>Evaluation 4 · Did innocent users notice?</h2>
<p class="lead">Every innocent web request during the attacks succeeded, under both detectors. A handful failed afterwards.</p>%s
<p>The cause of the %d recovery-period failures was not established. The attacker’s own legitimate requests also failed, because a source-wide block covers everything h4 sends.</p></section>''' % (
        table(["Attack", "Threshold baseline", "Graph detector"], brow), typical, lead_b["match"], ", ".join(lead_b["reached_after"]) or "no other host",
        lead_g["match"], R.svg_arrivals(lead_b, "Baseline blocks h4 → h1:22 only", "base"), R.svg_arrivals(lead_g, "Graph blocks all of h4", "graph"),
        graph_delays[-1], BK("baseline|all")["no_confirmation"],
        BK("baseline|all")["verified"], BK("baseline|all")["records"], BK("graph|all")["verified"], BK("graph|all")["records"],
        BK("baseline|all")["verified"], BK("baseline|all")["testable"], BK("graph|all")["verified"], BK("graph|all")["testable"],
        table(["Detector blocking", "Innocent, during attacks", "Innocent, recovery", "Attacker’s own requests, during attack"],
              [["<b>%s</b>" % ("Threshold baseline" if d == "baseline" else "Graph detector"),
                chip(inn[d][0]["successes"] == inn[d][0]["attempts"], pct(inn[d][0]["successes"], inn[d][0]["attempts"], 2)) + " %s of %s" % ("{:,}".format(inn[d][0]["successes"]), "{:,}".format(inn[d][0]["attempts"])),
                "%s of %s (%d failed)" % ("{:,}".format(inn[d][1]["successes"]), "{:,}".format(inn[d][1]["attempts"]), inn[d][1]["attempts"] - inn[d][1]["successes"]),
                "%s (%d of %d)" % (pct(DL("%s|compromised|attack" % d)["successes"], DL("%s|compromised|attack" % d)["attempts"]), DL("%s|compromised|attack" % d)["successes"], DL("%s|compromised|attack" % d)["attempts"])]
               for d in ("baseline", "graph")]),
        sum(inn[d][1]["attempts"] - inn[d][1]["successes"] for d in ("baseline", "graph"))))

    S.append('''<section class="pb"><h2>Evaluation 5 · Cost and speed</h2>
<p class="lead">The graph is about ten times slower than the baseline, but both are negligible next to the 10-second window.</p>%s%s
<h2>Conclusion</h2>
<ol class="concl">
<li><b>Graph structure identifies lateral movement.</b> Only the graph named it correctly (%d/5 vs %d/5), which was the core question of the project. Both detectors found the attacker; the difference is the label.</li>
<li><b>The label decides whether blocking works.</b> The graph’s source-wide block was verified in %d of %d lateral records with no leakage. The baseline’s narrower, mislabelled block leaked in %d of %d.</li>
<li><b>Simple thresholds still cover more ground.</b> The baseline detected all four attack types and its blocks held against the primary scan, flood and login-retry attacks. Floods and login retries, which don’t change who talks to whom, did not reach the graph’s threshold under its fixed configuration.</li>
<li><b>Safe and cheap.</b> Every innocent request during attacks succeeded. Computation is under 2 ms per window, and blocks reach both switches in about 10–13 ms.</li>
<li><b>Not perfect.</b> Both detectors raised false alarms when normal traffic changed (%s and %s), and the graph was sensitive to attack order.</li></ol>
<div class="answer"><p><b>Bottom line:</b> neither detector is enough on its own. Run both: the baseline for breadth, and the graph to recognise lateral movement and choose a block that actually contains it.</p></div>
<h3>Limits of these results</h3>
<p>One small emulated network (6 hosts, 2 switches), five trials per condition, and simulated attacks: the login attempts don’t authenticate, and the lateral movement is a contact pattern, not a real compromise. The baseline’s mislabel comes from its rule order and thresholds; a different rule priority might fix it without a graph, which this study did not test. The combined policy above was not evaluated. The results show the trade-off in this testbed; they do not prove production accuracy or scalability.</p>
</section>''' % (
        R.svg_bars([("Threshold baseline", cost["baseline_ms"]["mean"], "base", "%.2f ms" % cost["baseline_ms"]["mean"]), ("Graph detector", cost["graph_ms"]["mean"], "graph", "%.2f ms" % cost["graph_ms"]["mean"])],
                   2.0, lambda v: "2 ms per 10 s window"),
        table(["Measure", "Result"], [["Controller CPU (whole application)", "%.1f%% on average" % cost["cpu_percent"]["mean"]],
                                      ["Controller memory", "%.0f MiB on average" % cost["rss_mib"]["mean"]],
                                      ["Alert → block decision (C5)", "baseline %.1f ms · graph %.1f ms" % (R.tm("C5|baseline|alert_to_decision"), R.tm("C5|graph|alert_to_decision"))],
                                      ["Decision → both switches confirm (C5)", "baseline %.1f ms · graph %.1f ms" % (R.tm("C5|baseline|decision_to_confirmation"), R.tm("C5|graph|decision_to_confirmation"))],
                                      ["Attack start → alert", "≈ %.1f s (waiting for the 10 s window to close); floods ≈ %.1f s" % (P("lateral", "baseline")["mttd_mean"], P("dos", "baseline")["mttd_mean"])]]),
        P("lateral", "graph")["class_exact"], P("lateral", "baseline")["class_exact"], gl["verified"], gl["records"], bl["leakage"], bl["records"],
        pct(fg["flagged"], fg["eligible"], 2), pct(fb["flagged"], fb["eligible"], 2)))
    return S


def appendices(R):
    T, f, table, chip = R.T, R.f, R.table, R.chip
    S = []
    mark = lambda ok, text: chip(ok, ("✓ " if ok else "✗ ") + text)
    rows = [[r["case"], r["trial"], mark(r["baseline_detected"] == "True", "found") + mark(r["baseline_class_exact"] == "True", "named"), f(r["baseline_mttd"]),
             (mark(r["graph_detected"] == "True", "found") + mark(r["graph_class_exact"] == "True", "named")) if r["graph_detected"] == "True" else chip(False, "✗ missed"), f(r["graph_mttd"])]
            for r in T["attacks"] if r["phase"] == "detection" and r["case"] in ("C2", "C3", "C4", "C5")]
    S.append('<section class="appendix pb"><h2>Appendix A · Detection, per trial</h2><p>All 20 primary detection-only attack instances. “Found” means the attacker was flagged; “named” means the attack type was also correct. “—” means the attack was missed, not zero delay. Source: attacks.csv.</p>%s</section>' %
             table(["Case", "Trial", "Baseline", "Delay s", "Graph", "Delay s"], rows, "dense"))

    label = {"verified": chip(True, "✓ verified"), "observed_leakage": chip(False, "✗ leaked"), "no_confirmation": '<span class="chip">no rule</span>',
             "insufficient_drop_evidence": chip(None, "unverified: counter flat")}
    rows = [[r["case"], r["trial"], NAMES[r["attack_class"]], r["mitigator"], f(r["rule_confirmation_delay"], 1, 1), f(r["post_confirmation_seconds"], 1, 1), label.get(r["blocking_outcome"], r["blocking_outcome"])]
            for r in sorted(T["containment"], key=lambda r: (r["case"], r["mitigator"], int(r["trial"]), r["attack_class"])) if r["phase"] == "mitigation"]
    S.append('<section class="appendix pb"><h2>Appendix B · Blocking, per attack record</h2><p>Every attack in the 50 blocking runs. C6 runs contain two attacks (lateral movement, then a scan), so each detector has 30 records across 25 runs. “Block at” is seconds from the first attack packet to confirmation on every targeted switch; “Sending after” is how long the attacker kept sending once the rule was in place. Source: containment.csv.</p>%s</section>' %
             table(["Case", "Trial", "Attack", "Blocking", "Block at s", "Sending after s", "Outcome"], rows, "dense"))

    lrow = []
    for d in ("baseline", "graph"):
        for g in ("compromised", "innocent"):
            for p in ("pre_attack", "attack", "recovery"):
                vals = [float(r["mean_success_latency"]) * 1000 for r in T["disruption"] if r["phase"] == "mitigation" and r["mitigator"] == d and r["group"] == g and r["period"] == p and r["mean_success_latency"]]
                lrow.append([d, "Attack source" if g == "compromised" else "Innocent", p.replace("_", " "), len(vals), f(st.mean(vals)) if vals else "—", "%s–%s" % (f(min(vals)), f(max(vals))) if vals else "—"])
    orow = []
    for case in ["C%d" % i for i in range(1, 8)]:
        rr = [r for r in T["overhead"] if r["phase"] == "detection" and r["case"] == case and r["period"] == "evaluation"]
        mean = lambda k: st.mean(float(r[k]) for r in rr)
        orow.append([case, f(mean("cpu_percent_mean")), f(mean("rss_bytes_mean") / 1048576), f(mean("baseline_seconds_mean") * 1000), f(mean("graph_total_seconds_mean") * 1000), f(mean("graph_cost_ratio"))])
    ts = {(r["case"], r["mitigator"], r["metric"]): r for r in T["timing_summary"] if r["phase"] == "mitigation"}
    cols = [("C3", "baseline"), ("C5", "baseline"), ("C5", "graph")]
    trow = [[name] + [f(ts[(c, d, metric)]["mean"], 1000) if (c, d, metric) in ts and ts[(c, d, metric)]["n"] != "0" else "—" for c, d in cols]
            for metric, name in (("alert_to_decision", "Alert → decision"), ("decision_to_confirmation", "Decision → all switches"), ("flowmod_to_confirmation", "FlowMod → barrier"))]
    S.append('<section class="appendix pb"><h2>Appendix C · Delivery, cost and timing</h2><h3>HTTP success latency (ms)</h3><p>Means of per-trial mean successful-response latency, with failed requests excluded.</p>%s<h3>Detection computation by condition</h3>%s<p>Five run means per row. The cost ratio is the mean of per-run graph/baseline ratios.</p><h3>Rule timing</h3>%s<p>The graph made no blocking decision in C3, which it did not detect. All conditions are in timing_summary.csv.</p></section>' % (
        table(["Blocking", "Clients", "Period", "Trials", "Mean ms", "Range ms"], lrow, "dense"),
        table(["Case", "CPU %", "RSS MiB", "Baseline ms", "Graph ms", "Cost ratio"], orow, "dense"),
        table(["Mean ms (5 trials)", "C3 flood · baseline", "C5 lateral · baseline", "C5 lateral · graph"], trow, "dense")))

    return S
