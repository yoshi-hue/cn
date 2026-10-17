import {snapshot, eventStep, receiverSeries, focusWindow, activeRules, pipeline} from './model.js'

const $ = id => document.getElementById(id)
const esc = value => String(value ?? 'unavailable').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))
const label = kind => String(kind).replaceAll('_',' ')
const fmt = value => value == null || value === '' ? 'unavailable' : Number(value).toFixed(2)
const host = ip => catalog?.topology.hosts.find(h=>h.ip===ip)?.id || ip
const pct = (n,d) => d ? (100*n/d).toFixed(2)+'%' : 'n/a'
let catalog, run, time=0, playing=false, lastFrame=null, lastPaint=0, generation=0, view={start:0,end:1}
const positions={h1:[80,62],h2:[80,165],h3:[80,268],s1:[290,165],s2:[490,165],h4:[700,62],h5:[700,165],server:[700,268]}
const className=c=>catalog?.overview?.names?.[c] || (c==='graph_anomaly'?'generic graph anomaly':label(c))

// Chapter copy: what to watch in trial 1, and the published result across all five trials.
// Chapter copy. "watch" describes the chapter's own trial; "takeaway" is computed from the published tables.
let chapters={}
function chapterCopy(o){
 const P=(a,d)=>o.primary[`${a}|${d}`],FP=(p,d)=>o.false_positives[`${p}|${d}`],B=k=>o.blocking?.[k],OR=(a,d)=>o.order?.[`${a}|${d}`]
 const bl=B('baseline|lateral'),gl=B('graph|lateral'),fb=FP('benign','baseline'),fg=FP('benign','graph')
 const measured=o.mitigation?.graph?.receiver_evidence_available,unmeasured='Blocking outcomes were not measurable in this campaign: its receivers could not observe traffic.'
 const inn=d=>['attack','recovery'].map(p=>o.delivery[`${d}|innocent|${p}`]).reduce((a,r)=>[a[0]+r.successes,a[1]+r.attempts],[0,0])
 const [gi,gn]=inn('graph')
 const ord=d=>o.attacks.filter(a=>OR(a,d)).map(a=>`${o.names[a].toLowerCase()} ${OR(a,d).detected}/${OR(a,d).instances}`).join(', ')
 chapters={
 'Source versus class':{case:'C5 · detection',q:'Both flag h4, but as what?',
  watch:'A few seconds into the attack, both detectors flag h4 in the same window. Compare the attack type each one reports.',
  takeaway:`Both found the attacker in ${P('lateral','baseline').detected}/5 trials. Only the graph named it lateral movement (${P('lateral','graph').class_exact}/5 vs ${P('lateral','baseline').class_exact}/5). The baseline's login-retry rule fired first because one contact hit SSH port 22.`},
 'Baseline mitigation':{case:'C5 · baseline acts',q:'Does its block stop the attack?',
  watch:'The baseline acts on its login-retry label with a narrow h4→h1:22 rule. Both switches confirm it, but watch the receiver chart: h2, h3 and h5 still receive attack packets afterwards.',
  takeaway:!measured?unmeasured:bl&&bl.records?`Attack packets kept arriving after the block in ${bl.leakage}/${bl.records} lateral-movement records. Against the other attacks, its blocks held (${B('baseline|all').verified} verified overall).`:''},
 'Graph mitigation':{case:'C5 · graph acts',q:'Does its block stop the attack?',
  watch:'Trial 2 (typical). The graph blocks all of h4 about 4.5 s in, after the first host. The receiver chart stays flat for every other target, and innocent HTTP keeps flowing.',
  takeaway:!measured?unmeasured:gl&&gl.records?`Block verified in ${gl.verified}/${gl.records} lateral records, with no leakage in any. The exception is trial 1, where the block came late. Innocent requests served: ${gi.toLocaleString()} of ${gn.toLocaleString()}.`:''},
 'Legitimate change':{case:'C1 · benign',q:'What happens when normal traffic shifts?',
  watch:'There is no attack here, only scheduled legitimate changes in who talks to whom. Every flag is a false alarm.',
  takeaway:`Flagged windows: baseline ${fb.flagged}/${fb.eligible} (${pct(fb.flagged,fb.eligible)}), graph ${fg.flagged}/${fg.eligible} (${pct(fg.flagged,fg.eligible)}). Both produce false alarms.`},
 'Attack order':{case:'C7 · reversed',q:'Does attack order matter?',
  watch:'The order is now login retries, then scan, then lateral movement. Both detectors keep learning as traffic arrives, so earlier attacks shape later scores.',
  takeaway:o.order?`Attacks caught in reversed order. Baseline: ${ord('baseline')}. Graph: ${ord('graph')}.`:''}}
}

async function json(path){const r=await fetch(path);if(!r.ok)throw new Error(`Unable to load ${path}: HTTP ${r.status}`);return r.json()}
function fail(error){$('error').hidden=false;$('error').textContent=error.message;playing=false}

/* ---------- views ---------- */
function route(){const results=location.hash.startsWith('#results');$('view-results').hidden=!results;$('view-replay').hidden=results;$('tab-results').classList.toggle('active',results);$('tab-replay').classList.toggle('active',!results);if(results)playing=false}
addEventListener('hashchange',route)

/* ---------- results overview ---------- */
function renderOverview(){
 const o=catalog.overview;if(!o)return
 const P=(a,d)=>o.primary[`${a}|${d}`],FP=(p,d)=>o.false_positives[`${p}|${d}`],D=k=>o.delivery[k],B=k=>o.blocking?.[k]
 const caseFor={portscan:'C2',dos:'C3',bruteforce:'C4',lateral:'C5'}
 const q=(id,question,answer,visual,cta)=>{$(id).innerHTML=`<div class="q-text"><h2>${question}</h2><p>${answer}</p>${cta||''}</div><div class="q-visual">${visual}</div>`}
 const link=(chapter,at,text)=>`<a class="cta" href="#replay&chapter=${chapter}${at?'&at='+at:''}">${text} →</a>`
 const legend=items=>`<p class="legend-line">${items.map(([c,s,t])=>`<span class="mark ${c}">${s}</span> ${t}`).join(' ')}</p>`
 const head=`<thead><tr><th></th><th><i class="sw-base"></i>Baseline</th><th><i class="sw-graph"></i>Graph</th></tr></thead>`
 // 1. Detection.
 const mark=r=>r.detected===0?['miss','✗','missed']:r.class_exact===r.instances?['hit','✓','caught']:['part','!','caught, wrong type']
 q('q-detect','Which attacks did each detector catch?',
  `The baseline caught all four attack types. The graph is the only one that named <b>lateral movement</b> (the sequential-contact attack) correctly (${P('lateral','graph').class_exact}/5 vs ${P('lateral','baseline').class_exact}/5). It missed floods and login retries, which don't change who talks to whom.`,
  `<table class="hits">${head}<tbody>${o.attacks.map(a=>`<tr data-case="${caseFor[a]}" tabindex="0" title="Replay ${caseFor[a]} trial 1"><th>${o.names[a]}</th>${['baseline','graph'].map(d=>{const r=P(a,d),[c,sym,t]=mark(r);return `<td><span class="mark ${c}">${sym}</span><span class="mark-t">${t}<small>${r.detected}/${r.instances}</small></span></td>`}).join('')}</tr>`).join('')}</tbody></table>`+legend([['hit','✓','caught and named correctly'],['part','!','caught, wrong attack type'],['miss','✗','missed']]),
  link(1,'detect','See both detectors flag the same host'))
 // 2. False alarms.
 const fb=FP('benign','baseline'),fg=FP('benign','graph'),fdb=FP('detection','baseline'),fdg=FP('detection','graph')
 const bar=(v,max,cls,label,sub)=>`<div class="hbar"><span class="hbar-name"><i class="sw-${cls}"></i>${cls==='base'?'Baseline':'Graph'}</span><div class="hbar-track"><div class="hbar-fill ${cls}" data-w="${Math.max(1.5,v/max*100)}"></div></div><b>${label}</b><small>${sub}</small></div>`
 const fmax=Math.max(fb.flagged/fb.eligible,fg.flagged/fg.eligible)*1.25
 q('q-false','How often did normal traffic trigger a false alarm?',
  `When legitimate traffic patterns changed, the graph raised about <b>half as many</b> false alarms as the baseline. Neither was perfect. With ordinary traffic, the baseline flagged ${fdb.flagged} of ${fdb.eligible.toLocaleString()} windows and the graph ${fdg.flagged}.`,
  bar(fb.flagged/fb.eligible,fmax,'base',pct(fb.flagged,fb.eligible),`${fb.flagged} of ${fb.eligible} windows`)+bar(fg.flagged/fg.eligible,fmax,'graph',pct(fg.flagged,fg.eligible),`${fg.flagged} of ${fg.eligible} windows`),
  link(4,'','Watch a false alarm'))
 // 3. Blocking, per attack type: verified / all records, with leakage called out.
 const cell=r=>!r||!r.records?'<td>—</td>':r.leakage?`<td><span class="mark miss">✗</span><span class="mark-t">leaked<small>${r.leakage}/${r.records}</small></span></td>`
  :r.verified?`<td><span class="mark hit">✓</span><span class="mark-t">blocked<small>${r.verified}/${r.records}</small></span></td>`
  :`<td><span class="mark none">–</span><span class="mark-t">no block<small>0/${r.records}</small></span></td>`
 const bl=B('baseline|lateral'),gl=B('graph|lateral')
 const measured=o.blocking&&o.mitigation.graph.receiver_evidence_available
 $('results-title').textContent=measured?'The graph detector recognised and stopped lateral movement that the baseline misread. The baseline covered more kinds of attack.':'The graph detector recognised lateral movement that the baseline misread. The baseline covered more kinds of attack.'
 q('q-block','When a detector blocked the attacker, did it actually stop the attack?',measured?
  `Against <b>lateral movement</b>, both blocked about 4.5 s in. The baseline’s narrow rule (h4 → h1:22 only) let attack packets reach other hosts afterwards in ${bl.leakage}/${bl.records} cases. The graph blocked all of h4: verified in ${gl.verified}/${gl.records}, with no leakage in any. Against the other attacks only the baseline blocked, and its blocks held.`
  :'Not measurable in this campaign: its receivers could not observe traffic, so whether attack packets still arrived after a block is unknown. Use the repaired campaign for blocking results.',
  measured?`<table class="hits">${head}<tbody>${o.attacks.map(a=>`<tr><th>${o.names[a]}</th>${cell(B('baseline|'+a))}${cell(B('graph|'+a))}</tr>`).join('')}</tbody></table>`+legend([['hit','✓','block verified'],['miss','✗','attack packets got through'],['none','–','no rule installed (attack not detected)']]):'',
  measured?link(2,'confirm','Watch the baseline’s block leak')+' &nbsp; '+link(3,'confirm','Watch the graph’s block hold'):'')
 // 4. Collateral damage.
 const inn=(d,p)=>D(`${d}|innocent|${p}`),src=d=>D(`${d}|compromised|attack`)
 q('q-users','Did innocent users notice?',
  `Almost never. Every innocent web request during the attacks succeeded under both detectors. Afterwards, ${inn('baseline','recovery').attempts-inn('baseline','recovery').successes} (baseline) and ${inn('graph','recovery').attempts-inn('graph','recovery').successes} (graph) recovery-period requests failed out of about ${Math.round(inn('graph','recovery').attempts/10)*10}. The attacker’s own requests failed too, which is expected with a block on all of its traffic.`,
  `<div class="split">${['baseline','graph'].map(d=>{const a=inn(d,'attack'),r=inn(d,'recovery'),s=src(d);return `<div><p class="who"><i class="sw-${d==='baseline'?'base':'graph'}"></i>${d==='baseline'?'Baseline':'Graph'} blocking</p><div class="big-pair"><div><b class="num good">${pct(a.successes,a.attempts)}</b><span>innocent requests served during attacks<br><small>${a.successes.toLocaleString()} of ${a.attempts.toLocaleString()} · recovery ${r.successes.toLocaleString()} of ${r.attempts.toLocaleString()}</small></span></div><div><b class="num dim">${pct(s.successes,s.attempts)}</b><span>attacker’s requests served<br><small>during the attack</small></span></div></div></div>`}).join('')}</div>`)
 // 5. Cost.
 const c=o.cost,scale=Math.max(c.graph_ms.mean,c.baseline_ms.mean)*1.2
 q('q-cost','Is the graph detector expensive to run?',
  `It is slower than the baseline, but both are tiny. The graph needs ${c.graph_ms.mean.toFixed(2)} ms of work in each 10-second window, about ${(c.graph_ms.mean/100).toFixed(3)}% of the time available. The whole controller averaged ${c.cpu_percent.mean.toFixed(1)}% CPU.`,
  bar(c.baseline_ms.mean,scale,'base',`${c.baseline_ms.mean.toFixed(2)} ms`,'per 10 s window')+bar(c.graph_ms.mean,scale,'graph',`${c.graph_ms.mean.toFixed(2)} ms`,'per 10 s window')+`<p class="legend-line">A 10 s window is 10,000 ms.</p>`)
 document.querySelectorAll('.hbar-fill').forEach(el=>{el.style.width=el.dataset.w+'%'})
 document.querySelectorAll('#q-detect .hits tbody tr').forEach(tr=>{const go=()=>{const r=catalog.runs.find(x=>x.metadata.phase==='detection'&&x.metadata.case===tr.dataset.case&&x.metadata.trial===1);if(r){location.hash='#replay';load(r.id)}};tr.onclick=go;tr.onkeydown=e=>{if(e.key==='Enter')go()}})
 $('definitions').innerHTML=[
  ['Caught','The detector flagged the attacking host (h4) in a window that overlaps the attack. Five trials per attack, with blocking switched off.'],
  ['Named correctly','The flag also gave the right attack type.'],
  ['False alarm','A 10-second window in which a host that was not attacking got flagged.'],
  ['Block verified','After the rule was confirmed on every switch, the attacker kept sending for at least 3 s, the rule’s drop counter rose, and no more attack packets arrived at any target. The receivers pass a capture health check before each run.'],
  ['Leaked','Attack packets reached a target after the rule was confirmed.'],
  ['Uncertainty','Five trials per condition. A 5/5 result has a 95% interval of 57–100%, and 0/5 has 0–43%.']].map(([t,d])=>`<dt>${t}</dt><dd>${d}</dd>`).join('')
 const t=k=>o.timing[k]?.mean_ms
 $('objectives').innerHTML=[
  ['O1','Ryu IDS collecting PacketIn and flow statistics (Algorithm A)',`Delivered: 10 s windows, stats polled every 5 s. ${o.validity.valid}/${o.validity.runs} runs passed validity checks.`],
  ['O2','Detect port scan, DoS, brute force and lateral movement','Baseline: all four. Graph: scan and lateral movement only. Brute force is simulated as repeated SYN attempts.'],
  ['O3','Automatic OpenFlow mitigation (Algorithm D)',`Drop rules delivered. Both switches confirm ${(t('C5|graph|decision_to_confirmation')?.toFixed(1) ?? '—')} ms after the decision (C5, graph). Redirection was not implemented.`],
  ['O4','Compare both detectors on identical traffic','Delivered across detection, false alarms, blocking, delay, rule latency, cost and disruption.']]
  .map(([n,t,d])=>`<li><b class="o">${n}</b><div><b>${t}</b><p>${d}</p></div></li>`).join('')
}

/* ---------- replay ---------- */
function choices(id, values, selected){$(id).replaceChildren(...values.map(value=>{const o=document.createElement('option');o.value=value;o.textContent=id==='phase'&&['calibration','pilot'].includes(value)?`${value} · supplementary`:value;return o}));$(id).value=selected}
function filters(){const m=run.metadata;choices('phase',[...new Set(catalog.runs.map(r=>r.metadata.phase))],m.phase);let rows=catalog.runs.filter(r=>r.metadata.phase===m.phase);choices('case',[...new Set(rows.map(r=>r.metadata.case))],m.case);rows=rows.filter(r=>r.metadata.case===m.case);choices('mitigator',[...new Set(rows.map(r=>r.metadata.mitigator))],m.mitigator);rows=rows.filter(r=>r.metadata.mitigator===m.mitigator);choices('trial',[...new Set(rows.map(r=>String(r.metadata.trial)))],String(m.trial))}
function setView(){view=$('focus').checked?focusWindow(run):{start:0,end:run.duration};$('scrubber').min=view.start;$('scrubber').max=view.end;time=Math.max(view.start,Math.min(view.end,time))}
async function load(id){const entry=catalog.runs.find(r=>r.id===id);const ticket=++generation;playing=false
 try{const next=await json(entry.file);if(ticket!==generation)return
  run=next;lastFrame=null;$('error').hidden=true;$('raw-event').textContent='Select an event in the trail.';filters()
  time=0;setView();time=view.start
  const chapter=catalog.chapters.find(c=>c.id===id),copy=chapter&&chapters[chapter.title]
  document.querySelectorAll('#chapters button').forEach(b=>b.classList.toggle('active',b.dataset.id===id))
  $('brief').innerHTML=copy?`<div><b>What to watch in trial ${chapter.trial??1}</b>${esc(copy.watch)}</div><div><b>Campaign results</b>${esc(copy.takeaway)}</div>`:''
  const m=run.metadata
  $('run-title').textContent=`${m.case} · ${m.phase} · trial ${m.trial}`
  $('run-subtitle').textContent=`${m.mitigator==='none'?'Mitigation disabled (both detectors observe only)':`Actuator: ${m.mitigator} detector installs rules; the other observes`} · seed ${m.seed} · ${run.run}`
  $('phase-badge').textContent=['pilot','calibration'].includes(m.phase)?'Supplementary · valid':'Evaluation · valid'
  renderResults();renderEvidence();render()
 }catch(error){fail(error)}}
function selectFilter(key){let rows=catalog.runs;const keys=['phase','case','mitigator','trial'];for(const k of keys){if(keys.indexOf(k)>keys.indexOf(key))break;rows=rows.filter(r=>String(r.metadata[k])===$(k).value)}if(rows.length)load(rows[0].id)}

function network(state){
 let svg=''
 for(const h of catalog.topology.hosts)svg+=`<path class="physical" d="M${positions[h.id]} L${positions[h.switch]}"/>`
 svg+='<path class="physical" d="M290,165 L490,165"/>'
 for(const e of state.probes.filter(e=>time-e.time<2.5)){const a=positions[host(e.data.src)],b=positions[host(e.data.dst)];if(a&&b)svg+=`<path class="observation ${e.data.success?'obs-http':'obs-fail'}" d="M${a} Q390,20 ${b}"/>`}
 for(const [dst,e] of Object.entries(state.receivers)){if(time-e.time>2.5)continue
  const previous=state.events.filter(x=>x.kind==='receiver'&&x.data.dst===dst&&x.id!==e.id).at(-1)
  for(const [src,count] of Object.entries(e.data.counts||{})){if(!previous||count<=(previous.data.counts?.[src]||0))continue;const a=positions[host(src)],b=positions[host(dst)];if(a&&b)svg+=`<path class="observation obs-recv" d="M${a} Q390,310 ${b}"/>`}}
 const targets=new Set(state.activeAttacks.flatMap(a=>a.targets||[]))
 const rules=activeRules(state.events)
 for(const id of ['s1','s2']){const [x,y]=positions[id],r=rules[id.slice(1)]
  svg+=`<rect x="${x-44}" y="${y-28}" width="88" height="56" rx="10" class="sw ${r?'rule':''}"/><text x="${x}" y="${y-3}" text-anchor="middle" class="node-title">${id}</text><text x="${x}" y="${y+14}" text-anchor="middle" class="node-role">OpenFlow 1.3</text>`
  if(r)svg+=`<g><title>${r.map(e=>e.data.match).join('\n')}</title><rect x="${x-40}" y="${y+34}" width="80" height="20" rx="10" class="rule-tag"/><text x="${x}" y="${y+48}" text-anchor="middle" class="rule-text">⛔ drop ${r.some(e=>String(e.data.match).includes('ipv4_dst'))?'pair':'source'}</text></g>`}
 const flagged=new Set(['baseline','graph'].flatMap(d=>state.detectors[d].candidates.filter(e=>time-e.time<12).map(e=>e.data.src_ip)))
 for(const h of catalog.topology.hosts){const [x,y]=positions[h.id]
  if(targets.has(h.ip))svg+=`<circle cx="${x}" cy="${y-8}" r="36" class="target-ring"/>`
  svg+=`<circle cx="${x}" cy="${y-8}" r="26" class="node ${h.id==='h4'?'attacker':''} ${flagged.has(h.ip)?'flagged':''}"/><text x="${x}" y="${y-3}" text-anchor="middle" class="node-title">${h.id}</text><text x="${x}" y="${y+44}" text-anchor="middle" class="node-role">${esc(h.role)}</text>`
  if(flagged.has(h.ip))svg+=`<text x="${x+22}" y="${y-30}" class="node-title">⚠</text>`}
 $('network').innerHTML=svg
 $('period').textContent=state.period
 $('annotation').innerHTML=state.activeAttacks.length?`<b>Attack in progress:</b> ${state.activeAttacks.map(a=>`${esc(className(a.attack_class))} from ${esc(host(a.src))} → ${(a.targets||[]).map(host).join(', ')} (${a.sent ?? '?'} sends in total)`).join(' · ')}`:'No malicious traffic is being sent at this position.'
 $('switches').innerHTML=['1','2'].map(id=>{const table=state.resource?.data.flow_tables?.[id];const expiry=state.events.filter(e=>e.kind==='mitigation_expired'&&String(e.data.dpid)===id);return `<div class="switch-card"><b>s${id} · sampled occupancy</b><p>${table?`${table.forwarding} forwarding / ${table.mitigation} mitigation / ${table.total} total`:'Unavailable at this position'}</p><p>Sample: ${table?fmt(table.observed_at)+' s':'unavailable'} · expiry notifications: ${expiry.length}</p></div>`}).join('')
}

function verdict(e){
 if(e.attribution==='unmatched')return `<span class="chip mid">⚠ no attack running: false-alarm candidate</span>`
 if(e.attribution==='ambiguous')return `<span class="chip off">overlaps several attacks: not credited</span>`
 if(e.attribution!=='matched')return `<span class="chip off">attribution unavailable</span>`
 const truth=run.truths.find(t=>t.attack_id===e.attack_ids?.[0])
 const exact=truth&&truth.attack_class===e.data.attack_class
 return `<span class="chip ok">✓ source ${esc(host(e.data.src_ip))}</span>`+(truth?`<span class="chip ${exact?'ok':'no'}">${exact?'✓':'✗'} class ${esc(className(e.data.attack_class))}</span>${exact?'':`<span class="eyebrow">actual: ${esc(className(truth.attack_class))}</span>`}`:'')
}
function meter(value,threshold,cls){const max=Math.max(threshold*2.2,value*1.1),x=v=>Math.min(300,v/max*300)
 return `<div class="meter"><svg viewBox="0 0 320 30" aria-label="score ${value} against threshold ${threshold}"><rect x="0" y="6" width="300" height="10" rx="5" class="bar-track"/><rect x="0" y="6" width="${x(value)}" height="10" rx="5" class="${cls}"/><line x1="${x(threshold)}" x2="${x(threshold)}" y1="2" y2="20" class="tl-cursor"/><text x="${x(threshold)+4}" y="29" class="t-muted">threshold ${threshold}</text><text x="0" y="29" class="t-muted">score ${Number(value).toFixed(2)}</text></svg></div>`}
function detectorPanels(state){
 const algo={baseline:['Threshold baseline','Algorithm B'],graph:['Graph detector','Algorithm C']}
 const thr=catalog.overview?.thresholds||{}
 for(const name of ['baseline','graph']){const s=state.detectors[name],e=s.latest,acts=run.metadata.mitigator===name
  let body=`<p class="waiting">${state.period.startsWith('Warmup')?'Profiling normal traffic during warmup. No decisions yet.':'Watching the current 10 s window. Nothing exceeds a threshold yet.'}</p>`
  if(e){const d=e.data,ev=d.evidence||{}
   body=`<div>${verdict(e)}</div><p class="reason">${esc(d.reason||label(d.attack_class))}</p>`
   if(name==='graph'&&d.score!=null){body+=meter(d.score,thr.GRAPH_SCORE_THRESHOLD??6,'bar-graph')
    const c=ev.contributions||{},max=Math.max(...Object.values(c).map(Number),1)
    body+=`<div class="contrib">${Object.entries(c).sort((a,b)=>b[1]-a[1]).slice(0,4).map(([k,v])=>`<span>${esc(label(k))}</span><svg viewBox="0 0 100 8" preserveAspectRatio="none"><rect width="100" height="8" rx="4" class="bar-track"/><rect width="${Math.max(2,v/max*100)}" height="8" rx="4" class="bar-graph"/></svg><span>${Number(v).toFixed(1)}</span>`).join('')}</div>`}
   else if(d.score!=null){const m=/\(> ?([\d.]+)\)/.exec(d.reason||'');if(m)body+=meter(d.score,Number(m[1]),'bar-base')}}
  $(name).innerHTML=`<h2>${algo[name][0]} <small>${algo[name][1]} · ${acts?'⚡ can act':'observes only'}</small></h2>${body}<div class="stats"><span><b>${s.candidates.length}</b> candidates</span><span><b>${s.alerts.length}</b> alerts after cooldown</span></div>`}}

function stageStrip(state){const p=pipeline(run,state),D=state.detectors
 const dec=state.events.filter(e=>e.kind==='mitigation_decided'&&e.data.actuate).at(-1)
 const replies=state.events.filter(e=>e.kind==='barrier_reply'&&(!dec||e.data.decision_id===dec.data.decision_id))
 const items=[
  ['A','Collect',p.collect==='warmup'?'warmup profiling':'10 s windows','on'],
  ['B','Baseline',p.baseline==='flagged'?className(D.baseline.latest.data.attack_class):'no candidate',p.baseline==='flagged'?'alarm':''],
  ['C','Graph',p.graph==='flagged'?className(D.graph.latest.data.attack_class):'no candidate',p.graph==='flagged'?'alarm':''],
  ['','Decide',p.decide==='actuating'?`${dec.data.detector}: ${label(dec.data.action)}`:p.decide==='observe'?'observe only':'waiting',p.decide==='actuating'?'on':''],
  ['D','Install rule',p.install==='disabled'?'mitigation off':p.install==='confirmed'?`all switches ✓ (${replies.length} replies)`:p.install==='pending'?`${replies.length} switch replies`:'waiting',p.install==='confirmed'?'on':p.install==='disabled'?'off':''],
  ['','Verify block',p.verify==='disabled'?'not assessed':p.verify==='pending'?'assessed at run end':p.verify==='unavailable'?'receiver evidence unavailable':p.verify==='verified'?'✓ verified':'✗ unverified',p.verify==='verified'?'good':p.verify==='unverified'?'bad':p.verify==='disabled'?'off':'']]
 $('pipeline').innerHTML=items.map(([a,s,d,c])=>`<li class="${c}"><span class="a">${a?'Algorithm '+a:'&nbsp;'}</span><span class="s">${s}</span><span class="d" title="${esc(d)}">${esc(d)}</span></li>`).join('')}

function description(e){const d=e.data
 if(e.kind==='attack_started')return ['🚩',`${className(d.attack_class)} starts from ${host(d.src)}. It targets ${(d.targets||[]).map(host).join(', ')||'the declared hosts'}.`]
 if(e.kind==='attack_ended')return ['🏁',`The ${className(d.attack_class)} generator sent its last packet (${d.sent ?? '?'} sends in total).`]
 if(e.kind==='mitigation_decided')return [d.actuate?'⚡':'👁',`${d.detector} decides on a ${label(d.action)}${d.actuate?' and installs it.':', but it only observes in this run.'} ${d.reason?'('+d.reason+')':''}`]
 if(e.kind==='all_switches_confirmed')return ['✅','Every targeted switch has confirmed the rule. Blocking still needs independent evidence.']
 if(e.kind==='blocking_assessment')return [d.observed_blocking==='verified'?'🛡':'❔',`Retrospective assessment for ${className(d.attack_class)}: blocking ${d.blocking_outcome || d.observed_blocking}.`]
 if(['alert','detector_candidate'].includes(e.kind))return ['⚠',`${d.detector} ${e.kind==='alert'?'raises an alert':'flags a candidate'}: ${className(d.attack_class)} from ${host(d.src_ip)} (${e.attribution}).`]
 if(e.kind==='barrier_reply')return ['🔒',`s${d.dpid} confirms rule ${d.cookie} (${d.match}) in ${d.install_latency!=null?(d.install_latency*1000).toFixed(1)+' ms':'unknown time'}.`]
 if(e.kind==='flowmod_sent')return ['📤',`FlowMod sent to s${d.dpid}: ${d.match}`]
 if(e.kind==='mitigation_expired')return ['⌛',`Rule ${d.cookie} on s${d.dpid} expired after 30 s idle.`]
 return ['•',`${label(e.kind)}${d.attack_class?': '+className(d.attack_class):''}`]}
function trail(state){$('events').replaceChildren()
 for(const e of state.trail.slice(-14).reverse()){const b=document.createElement('button');b.className='event';b.innerHTML=`<time>${fmt(e.time)} s</time><span>${esc(description(e)[1])}</span>`;b.onclick=()=>{$('raw-event').textContent=JSON.stringify(e,null,2);document.querySelector('.evidence').open=true};$('events').append(b)}
 if(!state.trail.length)$('events').textContent='No attack or detector milestones yet. Press Event → to step to the first one.'
 const last=state.trail.at(-1),chapter=catalog.chapters.find(c=>c.id===run.id)
 const text=last?description(last)[1]:chapter?chapters[chapter.title].watch:'Press Play or Event → to step through this recorded trial.'
 $('explanation').innerHTML=`<span>${esc(text)}</span>`}

function renderResults(){const rows=run.summary.detections||[]
 let html=`<table class="results-table"><thead><tr><th>Detector</th><th>Identified</th><th>Class exact</th><th>Benign windows flagged</th></tr></thead><tbody>${rows.map(r=>`<tr><td>${esc(r.detector)}</td><td>${Number(r.attacks)?r.detected+'/'+r.attacks:'No attacks'}</td><td>${Number(r.attacks)?r.class_exact+'/'+r.attacks:'—'}</td><td>${r.false_positive_host_windows}/${r.benign_host_windows}</td></tr>`).join('')}</tbody></table>`
 if(run.metadata.mitigator==='none')html+='<div class="assessment">Mitigation disabled · no containment claim.</div>'
 else html+=(run.summary.containment||[]).map(r=>`<div class="assessment">${esc(className(r.attack_class))}: <b>${esc(run.metadata.measurement_protocol_version === 2 ? r.blocking_outcome : "receiver evidence unavailable (historical counter-based result)")}</b> blocking · rule-confirmation delay ${fmt(r.rule_confirmation_delay)} s</div>`).join('')
 const delivery=(run.summary.disruption||[]).filter(r=>['attack','recovery'].includes(r.period)&&Number(r.attempts)>0)
 if(delivery.length)html+=`<table class="results-table"><thead><tr><th>HTTP client group</th><th>Period</th><th>Success / attempts</th></tr></thead><tbody>${delivery.map(r=>`<tr><td>${r.group==='innocent'?'Innocent':'Attack source'}</td><td>${esc(r.period)}</td><td>${r.successes}/${r.attempts}</td></tr>`).join('')}</tbody></table>`
 $('trial-results').innerHTML=rows.length?html:'Published detector summary unavailable.'}
function renderEvidence(){$('evidence-links').replaceChildren()
 for(const ref of run.evidence){const a=document.createElement('a');a.href='evidence/'+ref;a.target='_blank';a.rel='noopener';a.textContent=ref.split('/').at(-1);$('evidence-links').append(a)}
 $('unavailable').textContent=`Events with unavailable timestamps: ${run.events.filter(e=>e.time===null).length}. Those events are kept in the replay JSON but not placed on the timeline.`}

const X=(t,w=590,o=40)=>o+(t-view.start)/(view.end-view.start)*w
const inView=t=>t>=view.start&&t<=view.end
function chartBase(maxY,unit=''){return `<path d="M40,12 V145 H630" class="axis"/><text x="4" y="20" class="chart-label">${maxY.toFixed(maxY<10?1:0)}${unit}</text><text x="26" y="145" class="chart-label">0</text><text x="40" y="167" class="chart-label">${view.start.toFixed(0)} s</text><text x="630" y="167" text-anchor="end" class="chart-label">${view.end.toFixed(0)} s</text>${inView(time)?`<line x1="${X(time)}" x2="${X(time)}" y1="12" y2="145" class="cursor"/>`:''}`}
function charts(state){
 const groups=receiverSeries(run,state.events),entries=Object.entries(groups).filter(([,p])=>p.some(([,v])=>v>0))
 const max=Math.max(1,...entries.flatMap(([,p])=>p.map(q=>q[1])))
 let svg=chartBase(max)
 entries.forEach(([key,points],i)=>{const pts=points.filter(([t])=>inView(t));if(pts.length)svg+=`<polyline points="${pts.map(([t,v])=>`${X(t)},${145-v/max*125}`).join(' ')}" class="ser-${i%6}" stroke-width="2" fill="none"><title>${key.split('|').map(host).join(' → ')}</title></polyline>`})
 if(!entries.length)svg+=`<text x="335" y="80" text-anchor="middle" class="chart-label">${run.truths.length?'No marked attack packets counted at receivers yet':'No attack in this run'}</text>`
 const block=state.events.find(e=>e.kind==='all_switches_confirmed')  // mark the block, so later rises read as leakage
 if(block&&inView(block.time))svg+=`<line x1="${X(block.time)}" x2="${X(block.time)}" y1="12" y2="145" class="block-mark"/><text x="${X(block.time)+4}" y="22" class="chart-label">block confirmed</text>`
 $('receiver-chart').innerHTML=svg
 $('receiver-legend').innerHTML=entries.map(([key,points],i)=>`<span><i class="lg-${i%6}"></i>${esc(key.split('|').map(host).join(' → '))}: <b>${points.at(-1)[1]}</b></span>`).join('')
 const sources=new Set(run.truths.map(t=>t.src));if(!sources.size)sources.add('10.0.0.4')
 const probes=state.probes.filter(e=>inView(e.time))
 const latencyMax=Math.max(.02,...probes.filter(e=>e.data.success).map(e=>e.data.latency||0))
 svg=chartBase(latencyMax*1000,' ms');const totals={innocent:[0,0],source:[0,0]}
 for(const e of state.probes){const d=e.data,g=sources.has(d.src)?'source':'innocent';totals[g][d.success?0:1]++
  if(!inView(e.time))continue;const x=X(e.time)
  if(d.success&&d.latency!=null)svg+=`<circle cx="${x}" cy="${145-d.latency/latencyMax*125}" r="3.5" class="${g==='source'?'dot-src':'dot-in'}"><title>${host(d.src)} · ${(d.latency*1000).toFixed(1)} ms</title></circle>`
  else if(!d.success)svg+=`<path d="M${x-3.5},18.5 l7,7 m-7,0 l7,-7" class="x-fail"><title>${host(d.src)} · failed</title></path>`}
 $('http-chart').innerHTML=svg
 $('http-counts').innerHTML=`<span>Innocent: <b>${totals.innocent[0]}</b> ok / <b>${totals.innocent[1]}</b> failed</span><span>Attack source h4: <b>${totals.source[0]}</b> ok / <b>${totals.source[1]}</b> failed</span><span class="eyebrow">counts up to this position</span>`}
function timeline(){let svg=''
 for(const a of run.truths){if(a.first_send==null||a.last_send==null)continue;const s=a.first_send-run.start_wall,e=a.last_send-run.start_wall;if(e<view.start||s>view.end)continue
  const x=X(Math.max(s,view.start),1000,0),w=Math.max(3,X(Math.min(e,view.end),1000,0)-x);svg+=`<rect x="${x}" y="4" width="${w}" height="14" rx="4" class="tl-attack"><title>${esc(className(a.attack_class))}</title></rect><text x="${x}" y="42" class="tl-label">${esc(className(a.attack_class))}</text>`}
 for(const e of run.events.filter(e=>e.time!==null&&inView(e.time)&&['detector_candidate','all_switches_confirmed'].includes(e.kind))){const cand=e.kind==='detector_candidate';svg+=`<circle cx="${X(e.time,1000,0)}" cy="${cand?11:28}" r="4" class="${cand?(e.data.detector==='graph'?'tl-cand':'tl-alert'):'tl-confirm'}"><title>${esc(description(e)[1])}</title></circle>`}
 svg+=`<line x1="${X(time,1000,0)}" x2="${X(time,1000,0)}" y1="0" y2="34" class="tl-cursor"/>`
 $('timeline').innerHTML=svg}
function render(){if(!run)return;const state=snapshot(run,time)
 $('play').textContent=playing?'❚❚ Pause':'▶ Play';$('play').setAttribute('aria-label',playing?'Pause replay':'Play replay')
 $('clock').textContent=`${time.toFixed(1)} s · of ${run.duration.toFixed(0)} s`;$('scrubber').value=time
 stageStrip(state);network(state);detectorPanels(state);trail(state);charts(state);timeline()}
function seek(t){playing=false;time=Math.max(view.start,Math.min(view.end,t));render()}
function frame(now){if(lastFrame!==null&&playing&&run){time=Math.min(view.end,time+(now-lastFrame)/1000*Number($('speed').value));if(time>=view.end){playing=false;render()}}
 lastFrame=now;if(now-lastPaint>100&&playing){render();lastPaint=now}requestAnimationFrame(frame)}
$('play').onclick=()=>{if(!run)return;if(time>=view.end)time=view.start;playing=!playing;lastFrame=null;render()}
$('restart').onclick=()=>seek(view.start)
$('previous').onclick=()=>seek(eventStep(run,time,-1))
$('next').onclick=()=>seek(eventStep(run,time,1))
$('focus').onchange=()=>{setView();render()}
$('scrubber').oninput=()=>seek(Number($('scrubber').value))
for(const key of ['phase','case','mitigator','trial'])$(key).onchange=()=>selectFilter(key)
document.addEventListener('keydown',e=>{if(!run||$('view-replay').hidden||['INPUT','SELECT','TEXTAREA','BUTTON','SUMMARY','A'].includes(e.target.tagName))return
 if(e.code==='Space'){e.preventDefault();$('play').click()}else if(e.key==='ArrowRight'){e.preventDefault();$('next').click()}else if(e.key==='ArrowLeft'){e.preventDefault();$('previous').click()}else if(e.key==='Home'){e.preventDefault();$('restart').click()}})

try{catalog=await json('data/index.json')
 chapterCopy(catalog.overview)
 const n=catalog.runs.filter(r=>!['pilot','calibration'].includes(r.metadata.phase)).length
 $('inventory').textContent=`${n} evaluation runs + ${catalog.runs.length-n} supplementary`
 for(const [i,c] of catalog.chapters.entries()){const b=document.createElement('button'),copy=chapters[c.title]||{};b.dataset.id=c.id
  b.innerHTML=`<span class="n">${String(i+1).padStart(2,'0')} · ${esc(copy.case||'')}</span><span class="t">${esc(c.title)}</span><span class="cq">${esc(copy.q||'')}</span>`;b.onclick=()=>{location.hash='#replay';load(c.id)};$('chapters').append(b)}
 route();renderOverview()
 // Deep link: #replay&chapter=3&t=150 opens a chapter at a recorded position.
 const q=new URLSearchParams(location.hash.split('&').slice(1).join('&')),ch=catalog.chapters[Number(q.get('chapter'))-1]||catalog.chapters[0]
 await load(ch.id)
 const at=q.get('at'),first=k=>run.events.find(e=>e.time!==null&&e.kind===k)?.time
 if(at)seek((at==='confirm'?first('all_switches_confirmed'):first('detector_candidate'))??view.start);else if(q.get('t'))seek(Number(q.get('t')));requestAnimationFrame(frame)
}catch(error){fail(error)}
