// Optional developer test: node replay/tests/model.test.mjs (viewer needs no Node).
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
// Import as a data module so no package.json is required for plain browser assets.
const source = await readFile(new URL('../assets/model.js', import.meta.url), 'utf8');
const {snapshot,eventStep,receiverSeries} = await import('data:text/javascript;base64,'+Buffer.from(source).toString('base64'));
const run={duration:30,start_wall:100,evaluation_start:10,recovery_start:25,truths:[{first_send:111,last_send:119}],events:[
 {id:0,kind:'detector_candidate',time:15,data:{detector:'graph'}},
 {id:1,kind:'alert',time:16,data:{detector:'graph'}},
 {id:2,kind:'probe',time:17,data:{success:false}},
 {id:3,kind:'mitigation_expired',time:22,data:{cookie:42}},
 {id:4,kind:'alert',time:null,data:{detector:'baseline'}}]};
assert.equal(snapshot(run,0).period,'Warmup / pre-evaluation');
assert.equal(snapshot(run,12).activeAttacks.length,1);
assert.equal(snapshot(run,15).detectors.graph.candidates.length,1);
assert.equal(snapshot(run,15).detectors.graph.alerts.length,0);
assert.equal(snapshot(run,30).detectors.baseline.alerts.length,0);
assert.equal(snapshot(run,30).period,'Recovery');
const at15=snapshot(run,15); snapshot(run,30); assert.deepEqual(snapshot(run,15),at15);
assert.equal(eventStep(run,0,1),15);
assert.equal(eventStep(run,16,-1),15);
assert.equal(eventStep(run,30,1),30);
assert.equal(eventStep(run,0,-1),0);
assert.deepEqual(snapshot(run,0),snapshot(run,0));
assert.deepEqual(receiverSeries({metadata:{measurement_protocol_version:2},truths:[{src:'a'}]},[{kind:'receiver',time:1,data:{dst:'b',counts:{}}}]),{'a|b':[[1,0]]});
assert.deepEqual(receiverSeries({truths:[{src:'a'}]},[]),{});
console.log('Replay state: 14 assertions passed (including backward seek, missing timestamps, and sampled zeros).');
const {focusWindow,activeRules,pipeline} = await import('data:text/javascript;base64,'+Buffer.from(source).toString('base64'));
assert.deepEqual(focusWindow({...run,duration:60}),{start:0,end:37});
assert.deepEqual(focusWindow({start_wall:0,duration:200,evaluation_start:135,truths:[],events:[]}),{start:123,end:150});
const rules=[{kind:'barrier_reply',data:{dpid:1,cookie:7}},{kind:'barrier_reply',data:{dpid:2,cookie:8}},{kind:'mitigation_expired',data:{dpid:1,cookie:7}}];
assert.deepEqual(Object.keys(activeRules(rules)),['2']);
const mrun={...run,metadata:{mitigator:'graph'}};
assert.equal(pipeline(mrun,snapshot(mrun,15)).graph,'flagged');
assert.equal(pipeline(mrun,snapshot(mrun,15)).install,'idle');
assert.equal(pipeline({...run,metadata:{mitigator:'none'}},snapshot(run,30)).verify,'disabled');
// Replies from targets inherit the attack marking; they must not appear as attack series.
assert.deepEqual(receiverSeries({metadata:{measurement_protocol_version:2},truths:[{src:'a'}]},[{kind:'receiver',time:1,data:{dst:'a',counts:{t:3}}}]),{'a|a':[[1,0]]});
console.log('Replay focus and pipeline: 7 assertions passed.');

assert.deepEqual(receiverSeries({metadata:{},truths:[{src:'a'}]},[{kind:'receiver',time:1,data:{dst:'b',counts:{}}}]),{});
assert.equal(pipeline({...mrun,events:[{kind:'blocking_assessment',time:1,data:{observed_blocking:'verified'}}]},snapshot({...mrun,events:[{kind:'blocking_assessment',time:1,data:{observed_blocking:'verified'}}]},30)).verify,'unavailable');
