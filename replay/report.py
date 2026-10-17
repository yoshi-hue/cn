"""Build the results PDFs (HTML, then PDF via headless Chrome).

Run from the repository root:  python3 -m replay.report
Writes two documents from the repaired evidence:
  output/pdf/results-summary.pdf  conclusion and the five evaluations
  output/pdf/results-report.pdf   the same summary plus detailed appendices
Pass --submission DIR to build from another curated evidence set.
Lives outside the frozen experiment source inventory, like the replay viewer.
Every number comes from the published tables after their checksums are verified.
No experiment is re-run and no detector is re-tuned.
"""

import argparse
import csv
import glob
import hashlib
import json
import shutil
import statistics as st
import subprocess
import sys
from pathlib import Path

from .data import DEFAULT_SUBMISSION
from .summary import overview, NAMES, ATTACKS

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "output/pdf"
CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
HOST = {"10.0.0.1": "h1", "10.0.0.2": "h2", "10.0.0.3": "h3", "10.0.0.4": "h4", "10.0.0.5": "h5", "10.0.0.10": "server"}


def load(submission):
    """Verify every curated checksum, then read the published tables."""
    global E, checks, T, M, TH, O
    E = Path(submission).resolve()
    checks = json.loads((E / "checksums.json").read_text())
    for name, sha in checks.items():
        assert hashlib.sha256((E / name).read_bytes()).hexdigest() == sha, name
    T = {p.stem: list(csv.DictReader(p.open())) for p in sorted((E / "tables").glob("*.csv"))}
    assert T["validity"] and all(r["valid"] == "True" for r in T["validity"])
    M = json.loads((E / "manifest.json").read_text())
    TH = json.loads((E / "thresholds.json").read_text())
    O = overview(T, TH)


P = lambda a, d: O["primary"]["%s|%s" % (a, d)]
FP = lambda p, d: O["false_positives"]["%s|%s" % (p, d)]
DL = lambda k: O["delivery"][k]
BK = lambda k: O["blocking"][k]
tm = lambda k: O["timing"][k]["mean_ms"]


def f(x, scale=1, nd=2):
    return "—" if x in ("", None) else "%.*f" % (nd, float(x) * scale)


def pct(n, d, nd=1):
    return "%.*f%%" % (nd, 100 * n / d) if d else "n/a"


def table(headers, rows, cls=""):
    head = "".join("<th>%s</th>" % h for h in headers)
    body = "".join("<tr>%s</tr>" % "".join("<td>%s</td>" % c for c in r) for r in rows)
    return '<table class="%s"><thead><tr>%s</tr></thead><tbody>%s</tbody></table>' % (cls, head, body)


def chip(ok, text):
    return '<span class="chip %s">%s</span>' % ({True: "ok", False: "no", None: "mid"}[ok], text)


def run_log(case, mitigator, trial):
    return glob.glob(str(E / ("evidence/**/mitigation-%s-%s_trial%02d.jsonl" % (case, mitigator, trial))), recursive=True)[0]


def arrivals(case, mitigator, trial):
    """Attack packets from the attacker counted at each target, from the receiver logs."""
    log = run_log(case, mitigator, trial)
    truth = json.loads(open(log.replace(".jsonl", "_truth.jsonl")).readline())
    first = truth["first_send"]
    ev = [json.loads(l) for l in open(log)]
    dec = next(d for d in ev if d["kind"] == "mitigation_decided" and d.get("actuate") and d.get("detector") == mitigator)
    replies = [d["wall"] for d in ev if d["kind"] == "barrier_reply" and d.get("decision_id") == dec["decision_id"]]
    match = next(d["match"] for d in ev if d["kind"] == "flowmod_sent" and d.get("decision_id") == dec["decision_id"])
    series = {}
    for tgt in truth["targets"]:
        name = HOST[tgt]
        rows = [json.loads(l) for l in open(log.replace(".jsonl", "_receiver_%s.jsonl" % name))]
        series[name] = [(r["wall"] - first, r["counts"].get(truth["src"], 0)) for r in rows
                        if 0 <= r["wall"] - first <= truth["last_send"] - first + 4]
    confirm = max(replies) - first
    reached_after = [n for n, pts in series.items()
                     if max([v for t, v in pts if t <= confirm] or [0]) < max([v for t, v in pts] or [0])]
    return {"confirm": confirm, "last": truth["last_send"] - first, "series": series, "match": match,
            "label": dec["attack_class"], "action": dec["action"], "reached_after": reached_after}


def svg_arrivals(a, title, cls):
    """One small panel: cumulative attack packets at each target over time, with the block marked."""
    span = max(a["last"] + 3, 22)
    x = lambda t: 40 + t / span * 270
    ymax = max([v for pts in a["series"].values() for _, v in pts] or [1])
    y = lambda v: 120 - v / ymax * 90
    s = '<svg viewBox="0 0 330 160" class="fig half"><text x="40" y="14" class="lt">%s</text>' % title
    s += '<path d="M40 30 V120 H310" class="ln" fill="none"/>'
    s += '<rect x="%.1f" y="30" width="%.1f" height="90" class="blk"/>' % (x(a["confirm"]), x(span) - x(a["confirm"]))
    s += '<line x1="%.1f" x2="%.1f" y1="26" y2="120" class="mk"/><text x="%.1f" y="115" class="ls">block confirmed %.1f s</text>' % (x(a["confirm"]), x(a["confirm"]), x(a["confirm"]) + 3, a["confirm"])
    for name, pts in a["series"].items():
        if not any(v for _, v in pts):
            continue
        d = " ".join("%.1f,%.1f" % (x(t), y(v)) for t, v in pts)
        late = name in a["reached_after"]
        color = "#c23a3a" if late else ("#6b7680" if cls == "base" else "#2a78d6")
        s += '<polyline points="%s" fill="none" stroke="%s" stroke-width="%s"/>' % (d, color, "2.4" if late else "1.8")
        t_rise = next(t for t, v in pts if v > 0)  # label where the line rises: the attacker's contact order
        s += '<text x="%.1f" y="%.1f" class="ls">%s</text>' % (x(t_rise) + 2, y(ymax) - 4, name)
    s += '<text x="40" y="136" class="ls">0 s</text><text x="310" y="136" class="ls" text-anchor="end">%d s after first attack packet</text>' % span
    s += '<text x="36" y="34" class="ls" text-anchor="end">%d</text><text x="36" y="122" class="ls" text-anchor="end">0</text>' % ymax
    return s + "</svg>"


def svg_pipeline():
    boxes = [("Mininet hosts", "h1–h5, server", 10), ("OVS switches", "s1, s2 · OF 1.3", 140),
             ("A · Collect", "PacketIn + stats → windows", 270)]
    s = '<svg viewBox="0 0 700 190" class="fig">'
    for title, sub, x in boxes:
        s += '<rect x="%d" y="20" width="118" height="54" rx="8" class="bx"/><text x="%d" y="43" class="bt">%s</text><text x="%d" y="60" class="bs">%s</text>' % (x, x + 59, title, x + 59, sub)
    s += '<rect x="410" y="6" width="118" height="38" rx="8" class="bx base"/><text x="469" y="22" class="bt">B · Baseline</text><text x="469" y="36" class="bs">thresholds</text>'
    s += '<rect x="410" y="52" width="118" height="38" rx="8" class="bx graph"/><text x="469" y="68" class="bt">C · Graph</text><text x="469" y="82" class="bs">host graph</text>'
    s += '<rect x="560" y="20" width="130" height="54" rx="8" class="bx"/><text x="625" y="43" class="bt">Decision</text><text x="625" y="60" class="bs">cooldown · act / observe</text>'
    s += '<rect x="560" y="116" width="130" height="54" rx="8" class="bx act"/><text x="625" y="139" class="bt">D · Mitigate</text><text x="625" y="156" class="bs">drop rule · 30 s idle</text>'
    s += '<rect x="270" y="116" width="258" height="54" rx="8" class="bx dim"/><text x="399" y="139" class="bt">Evaluation module</text><text x="399" y="156" class="bs">truth · receivers · HTTP · CPU · timing</text>'
    for x1, x2, y in [(128, 140, 47), (258, 270, 47), (528, 560, 25), (528, 560, 71)]:
        s += '<path d="M%d %d H%d" class="ar"/>' % (x1, y, x2)
    s += '<path d="M388 47 H398 V25 H410 M398 47 V71 H410" class="ar"/>'
    s += '<path d="M625 74 V116" class="ar"/><path d="M560 143 H528" class="ar dash"/>'
    s += '<path d="M625 170 V182 H199 V74" class="ar"/><text x="412" y="186" class="bs">FlowMod + barrier → switches</text>'
    return s + "</svg>"


def svg_topology():
    pos = {"h1": (60, 40), "h2": (60, 100), "h3": (60, 160), "s1": (230, 100), "s2": (420, 100),
           "h4": (590, 40), "h5": (590, 100), "server": (590, 160)}
    role = {"h1": "workstation", "h2": "workstation", "h3": "workstation", "h4": "attack source",
            "h5": "auth-service role", "server": "real HTTP service"}
    s = '<svg viewBox="0 0 660 200" class="fig topo">'
    for a, b in [("h1", "s1"), ("h2", "s1"), ("h3", "s1"), ("s1", "s2"), ("s2", "h4"), ("s2", "h5"), ("s2", "server")]:
        s += '<line x1="%d" y1="%d" x2="%d" y2="%d" class="ln"/>' % (*pos[a], *pos[b])
    for n, (x, y) in pos.items():
        if n.startswith("s") and n != "server":
            s += '<rect x="%d" y="%d" width="70" height="36" rx="7" class="bx"/><text x="%d" y="%d" class="bt">%s</text>' % (x - 35, y - 18, x, y + 4, n)
        else:
            s += '<circle cx="%d" cy="%d" r="19" class="nd %s"/><text x="%d" y="%d" class="bt">%s</text><text x="%d" y="%d" class="bs">%s</text>' % (x, y, "atk" if n == "h4" else "", x, y + 4, n, x, y + 32, role[n])
    s += '<text x="325" y="190" class="bs">Both switches connect to one Ryu controller (out-of-band)</text>'
    return s + "</svg>"


def svg_coverage():
    s = '<svg viewBox="0 0 660 230" class="fig cov">'
    x = lambda v: 200 + 360 * v
    for i, a in enumerate(ATTACKS):
        y = 30 + i * 48
        s += '<text x="0" y="%d" class="lt">%s</text>' % (y + 10, NAMES[a])
        for j, d in enumerate(["baseline", "graph"]):
            r, yy = P(a, d), y + j * 16
            cls = "base" if d == "baseline" else "graph"
            s += '<line x1="%.1f" x2="%.1f" y1="%d" y2="%d" class="ci %s"/>' % (x(r["wilson_low"]), x(r["wilson_high"]), yy, yy, cls)
            s += '<circle cx="%.1f" cy="%d" r="5" class="pt %s"/>' % (x(r["detected"] / r["instances"]), yy, cls)
            mark = "✓" if r["class_exact"] == r["instances"] else ("✗" if r["detected"] else "–")
            s += '<text x="580" y="%d" class="ls">%d/5 · class %s</text>' % (yy + 4, r["detected"], mark)
    for v in (0, .5, 1):
        s += '<line x1="%.1f" x2="%.1f" y1="18" y2="212" class="grid"/><text x="%.1f" y="226" class="ls" text-anchor="middle">%d%%</text>' % (x(v), x(v), x(v), v * 100)
    s += '<circle cx="8" cy="221" r="4" class="pt base"/><text x="16" y="225" class="ls">baseline</text><circle cx="86" cy="221" r="4" class="pt graph"/><text x="94" y="225" class="ls">graph</text>'
    return s + "</svg>"


def svg_bars(rows, vmax, unit_fmt, width=660):
    """rows: (label, value, class, annotation). One shared scale, labelled ends."""
    h = 34 * len(rows) + 24
    s = '<svg viewBox="0 0 %d %d" class="fig">' % (width, h)
    x = lambda v: 200 + v / vmax * 360
    for i, (lab, v, cls, note) in enumerate(rows):
        y = 8 + i * 34
        s += '<text x="0" y="%d" class="lt">%s</text><rect x="200" y="%d" width="360" height="18" rx="4" class="trk"/>' % (y + 13, lab, y)
        if v:
            s += '<rect x="200" y="%d" width="%.1f" height="18" rx="4" class="%s"/>' % (y, max(2, x(v) - 200), cls)
        s += '<text x="%.1f" y="%d" class="lv">%s</text>' % (x(v) + 6, y + 13, note)
    s += '<text x="200" y="%d" class="ls">0</text><text x="560" y="%d" class="ls" text-anchor="end">%s</text>' % (h - 4, h - 4, unit_fmt(vmax))
    return s + "</svg>"


CSS = """
@page{size:A4;margin:16mm 15mm 18mm;@bottom-left{content:"Lantern · Graph-based SDN IDS · Final results";font:8pt system-ui;color:#7a838a}@bottom-right{content:counter(page);font:8pt system-ui;color:#7a838a}}
@page:first{@bottom-left{content:none}@bottom-right{content:none}}
:root{--ink:#1d2328;--muted:#5f6870;--line:#dfe2e4;--soft:#f3f4f2;--base:#6b7680;--graph:#2a78d6;--good:#1f7a4d;--goodbg:#e4f3ea;--bad:#c23a3a;--badbg:#fbe5e3;--warn:#a36200;--warnbg:#fbefd9;--atk:#d97a2b}
*{box-sizing:border-box}body{margin:0;color:var(--ink);font:9.6pt/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;-webkit-print-color-adjust:exact;print-color-adjust:exact}
section{margin-top:9mm}section.pb{break-before:page;margin-top:0}h2,h3{break-after:avoid}svg.fig,.findings,.cols,.ladder{break-inside:avoid}
h1{font-size:25pt;line-height:1.15;letter-spacing:-.4px;margin:6mm 0 4mm}h2{font-size:15pt;margin:0 0 3mm;letter-spacing:-.2px}h3{font-size:10.5pt;margin:5mm 0 1.5mm;color:#204d80}
p{margin:0 0 2.6mm}ul,ol{margin:0 0 3mm;padding-left:5mm}li{margin-bottom:1mm}code,pre{font:8.3pt ui-monospace,SFMono-Regular,Menlo,monospace}pre{background:var(--soft);padding:3mm;border-radius:2mm;white-space:pre-wrap}
.kicker{font-size:8.5pt;letter-spacing:.8px;text-transform:uppercase;color:var(--muted);margin-top:18mm}.sub{font-size:11.5pt;color:var(--muted);max-width:165mm}
.kpis{display:grid;grid-template-columns:repeat(3,1fr);gap:3mm;margin:9mm 0}.kpis div{border:1px solid var(--line);border-radius:3mm;padding:3.5mm 4mm}.kpis b{display:block;font-size:17pt;letter-spacing:-.3px}.kpis span{font-size:8.3pt;color:var(--muted)}
.meta{width:100%;border-collapse:collapse;margin-top:4mm}.meta td{padding:2mm 0;border-bottom:1px solid var(--line);vertical-align:top}.meta td:first-child{width:30mm;color:var(--muted)}
.toc{margin-top:8mm;font-size:8.8pt;color:var(--muted)}
.lead{font-size:10.5pt}.findings{display:grid;grid-template-columns:1fr 1fr;gap:3mm;margin:4mm 0}.f{border:1px solid var(--line);border-left:3px solid var(--base);border-radius:2mm;padding:3mm 3.5mm;break-inside:avoid}.f.good{border-left-color:var(--good)}.f.warn{border-left-color:var(--warn)}.f b{display:block;margin-bottom:1mm}.f p{margin:0;font-size:9pt}
.note{font-size:8.6pt;color:var(--muted);border-top:1px solid var(--line);padding-top:2mm}
table{width:100%;border-collapse:collapse;margin:2mm 0 4mm;font-size:8.8pt;break-inside:auto}th{text-align:left;font-weight:600;font-size:8pt;color:var(--muted);border-bottom:1.2px solid #204d80;padding:1.6mm 1.8mm}td{border-bottom:1px solid var(--line);padding:1.6mm 1.8mm;vertical-align:top}tr{break-inside:avoid}
.trace td{padding:1mm 1.5mm;font-size:8.2pt;line-height:1.35}table.dense td{padding:1mm 1.8mm}table.trace td:first-child{width:52mm;font-weight:500}table.trace td:nth-child(2){width:24mm}table.ids code{word-break:break-all}
.chip{display:inline-block;font-size:7.8pt;font-weight:600;border-radius:9pt;padding:.3mm 2mm;margin:0 1mm .5mm 0;white-space:nowrap}.chip.ok{background:var(--goodbg);color:var(--good)}.chip.no{background:var(--badbg);color:var(--bad)}.chip.mid{background:var(--warnbg);color:var(--warn)}
.cols{display:grid;grid-template-columns:1fr 1fr;gap:6mm}.formula{font:10pt "Times New Roman",serif;background:var(--soft);padding:2mm 3mm;border-radius:2mm;text-align:center}
.cap{font-size:8.2pt;color:var(--muted);margin-top:-1mm}
.ladder{list-style:none;padding:0;counter-reset:l;display:grid;gap:2.5mm}.ladder li{counter-increment:l;display:grid;grid-template-columns:42mm 1fr;gap:3mm;border:1px solid var(--line);border-radius:2mm;padding:2.5mm 3mm}.ladder b:before{content:counter(l) " · ";color:var(--graph)}.ladder span{font-size:9pt;color:var(--muted)}
.qa{border:1px solid var(--line);border-radius:2mm;padding:3mm 4mm;margin-bottom:3mm;break-inside:avoid}.qa .q{font-weight:600;color:#204d80;margin-bottom:1mm}.qa p:last-child{margin:0}
svg.fig{width:100%;height:auto;display:block;margin:2mm 0 3mm}
.fig text{font-family:system-ui,-apple-system,sans-serif}.bt{font-size:11px;font-weight:600;fill:var(--ink);text-anchor:middle}.bs{font-size:9px;fill:var(--muted);text-anchor:middle}
.bx{fill:#fff;stroke:#a9b1b8}.bx.base{fill:#eef0f2;stroke:var(--base)}.bx.graph{fill:#e6f0fb;stroke:var(--graph)}.bx.act{fill:#fbe5e3;stroke:var(--bad)}.bx.dim{fill:var(--soft);stroke:var(--line)}
.ar{stroke:#7a838a;stroke-width:1.3;fill:none;marker-end:none}.ar.dash{stroke-dasharray:4 3}.ln{stroke:#c9ced2;stroke-width:1.6}.nd{fill:#fff;stroke:#a9b1b8;stroke-width:1.4}.nd.atk{fill:#fdf1e6;stroke:var(--atk)}
.lt{font-size:11px;fill:var(--ink)}.ls{font-size:9.5px;fill:var(--muted)}.lv{font-size:10.5px;font-weight:600;fill:var(--ink)}.grid{stroke:#e8eaeb;stroke-width:1}
.ci{stroke-width:2.2}.ci.base{stroke:var(--base)}.ci.graph{stroke:var(--graph)}.pt.base{fill:var(--base)}.pt.graph{fill:var(--graph)}.pt.dim{fill:#a9b1b8}
.trk{fill:var(--soft)}rect.base{fill:var(--base)}rect.graph{fill:var(--graph)}rect.graph.lite{fill:#86b6ef}rect.good{fill:var(--good)}rect.atk{fill:#fbe3cc;stroke:var(--atk)}
.appendix h2{font-size:13pt}
.answer{border-left:3px solid var(--graph);background:#f4f8fc;padding:3mm 4mm;margin:5mm 0;border-radius:0 2mm 2mm 0}.answer p{margin:0 0 2mm}.answer p:last-child{margin:0}.answer .kicker{margin:0 0 1.5mm}.concl li{margin-bottom:2mm}ul ul{margin-top:1mm}
svg.fig.cov{width:70%}svg.fig.topo{width:72%}.keep{break-inside:avoid}.small-note{font-size:7.5pt;color:var(--muted)}.pair{break-inside:avoid}.pair{display:grid;grid-template-columns:1fr 1fr;gap:4mm}svg.fig.half{margin:0}.blk{fill:#fbe5e3;opacity:.45}.mk{stroke:var(--bad);stroke-width:1.2;stroke-dasharray:3 2}.ser{fill:none;stroke-width:1.8}.ser.base{stroke:var(--base)}.ser.graph{stroke:var(--graph)}.ser.leak{stroke:var(--bad);stroke-width:2.4}
"""

def build(sections, name, title, footer):
    """Write the sections as one HTML page and print it to PDF with headless Chrome."""
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    html, pdf = OUT_DIR / (name + ".html"), OUT_DIR / (name + ".pdf")
    css = CSS.replace('"Lantern · Graph-based SDN IDS · Final results"', '"%s"' % footer)
    html.write_text('<!doctype html><html lang="en"><head><meta charset="utf-8"><title>%s</title><style>%s</style></head><body>%s</body></html>' % (title, css, "\n".join(sections)))
    chrome = CHROME if Path(CHROME).exists() else shutil.which("google-chrome") or shutil.which("chromium")
    if not chrome:
        sys.exit("HTML written to %s; install Chrome/Chromium to print the PDF." % html)
    subprocess.run([chrome, "--headless", "--disable-gpu", "--no-pdf-header-footer", "--print-to-pdf=%s" % pdf, html.as_uri()],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(pdf)


def main():
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument("--submission", type=Path, default=ROOT / DEFAULT_SUBMISSION)
    args = parser.parse_args()
    load(args.submission)
    from . import brief
    summary = brief.sections(sys.modules[__name__])
    build(summary, "results-summary", "Results summary · Graph-based SDN intrusion detection",
          "Graph-based SDN intrusion detection · Results summary")
    build(summary + brief.appendices(sys.modules[__name__]), "results-report",
          "Results report · Graph-based SDN intrusion detection", "Graph-based SDN intrusion detection · Results report")


if __name__ == "__main__":
    main()
