"""Regressions for capture health, duration-based sending, and containment evidence."""
import json
from types import SimpleNamespace
import pytest
from scapy.all import IP, UDP
from traffic.observe import count_packet, main
from experiments.validation import receiver_healthy
from experiments.analyze import blocking_assessment
from experiments.campaign import pilot_matrix, import_thresholds


def test_receiver_requires_interface():
    with pytest.raises(SystemExit):
        main(["--ip", "10.0.0.1", "--output", "unused"])


def test_health_is_separate_from_attack_counts():
    attack, health = {}, {}
    for marker in (16, 32, 0):
        count_packet(IP(src="10.0.0.2", dst="10.0.0.1", tos=marker)/UDP(),
                     "10.0.0.1", attack, health)
    assert attack == health == {"10.0.0.2": 1}
    count_packet(IP(dst="10.0.0.3", tos=16)/UDP(), "10.0.0.1", attack, health)
    assert sum(attack.values()) == 1


@pytest.mark.parametrize("ready,count,expected", [(True,5,True),(False,5,False),(True,4,False),(True,0,False)])
def test_receiver_health(ready,count,expected):
    assert receiver_healthy([dict(ready=ready,iface="h1-eth0",health_counts={"a":count})]) == expected


def test_capture_startup_failure(monkeypatch, tmp_path):
    import traffic.observe as module
    monkeypatch.setattr(module, "AsyncSniffer", lambda **kwargs: SimpleNamespace(start=lambda: None,running=False))
    monkeypatch.setattr(module.threading, "Event", lambda: SimpleNamespace(wait=lambda _: False, set=lambda: None))
    with pytest.raises(RuntimeError, match="did not become ready"):
        main(["--ip","10.0.0.1","--iface","missing","--output",str(tmp_path/'counts')])
    assert not (tmp_path/'counts').exists()


def evidence():
    truth=dict(src="a",targets=["b"],first_send=1,last_send=10)
    receivers=[dict(dst="b",wall=t,ready=True,iface="b-eth0",health_counts={"c":5},counts={"a":2}) for t in (1,6,9)]
    events=[dict(kind="resource_sample",wall=t,flow_tables={"1":dict(drops=[dict(cookie=7,packets=n)])}) for t,n in ((4,0),(7,3),(9,4))]
    return truth,receivers,events


def assess(confirm=5,cookies=None,edit=None):
    truth,receivers,events=evidence()
    if edit: edit(truth,receivers,events)
    return blocking_assessment(truth,confirm,{7} if cookies is None else cookies,events,receivers)


def test_healthy_correlated_block():
    r=assess()
    assert r['blocking_outcome']=='verified' and r['testable'] and r['drop_counter_increased']


def test_no_confirmation():
    assert assess(confirm=None)['blocking_outcome']=='no_confirmation'


def test_short_remaining_attack():
    assert assess(confirm=8)['blocking_outcome']=='insufficient_post_confirmation_traffic'


def test_silent_unhealthy_capture():
    def edit(t,r,e):
        for row in r: row['health_counts']={}
    assert assess(edit=edit)['blocking_outcome']=='unavailable_receiver_evidence'


def test_missing_samples():
    assert assess(edit=lambda t,r,e:r.pop())['blocking_outcome']=='unavailable_receiver_evidence'


def test_leakage():
    assert assess(edit=lambda t,r,e:r[-1]['counts'].update(a=3))['blocking_outcome']=='observed_leakage'


def test_unrelated_drop_cookie():
    assert assess(cookies={99})['blocking_outcome']=='insufficient_drop_evidence'


def test_stale_positive_drop_counter():
    def edit(t,r,e):
        for row in e: row['flow_tables']['1']['drops'][0]['packets']=5
    assert assess(edit=edit)['blocking_outcome']=='insufficient_drop_evidence'


@pytest.mark.parametrize('name',['portscan','bruteforce'])
def test_repeated_sending_uses_actual_time(name,monkeypatch):
    from importlib import import_module
    m=import_module('traffic.attacks.'+name)
    elapsed=[0.0]; timestamps=[]
    monkeypatch.setattr(m.time,'monotonic',lambda:elapsed[0])
    monkeypatch.setattr(m.time,'sleep',lambda seconds:elapsed.__setitem__(0,elapsed[0]+seconds))
    monkeypatch.setattr(m,'jitter',lambda delay:delay)
    monkeypatch.setattr(m,'send',lambda *args,**kwargs:timestamps.append(elapsed[0]))
    args=('10.0.0.1','10.0.0.2',[22,23]) if name=='portscan' else ('10.0.0.1','10.0.0.2',22,2)
    assert m.run(*args,delay=1)==2
    elapsed[0]=0; timestamps.clear()
    assert m.run(*args,delay=1,repeat_for=5)==5
    assert timestamps==[0,1,2,3,4]


def test_pilot_conditions_use_same_seed_and_all_actuators():
    rows=pilot_matrix()
    assert len(rows)==12
    assert {r['mitigator'] for r in rows}=={'none','baseline','graph'}
    assert {r['seed'] for r in rows}=={9101}


def test_import_threshold_provenance(tmp_path):
    from pathlib import Path
    import shutil
    source=Path(__file__).resolve().parents[1]/'submission'
    campaign=tmp_path/'campaign';campaign.mkdir()
    (campaign/'manifest.json').write_text('{}')
    import_thresholds(campaign,source)
    assert (campaign/'thresholds.json').read_bytes()==(source/'thresholds.json').read_bytes()
    assert json.loads((campaign/'manifest.json').read_text())['calibration_provenance']['mode']=='reused'


def test_truth_send_timestamp_excludes_later_idle_time(monkeypatch):
    import traffic.common as common
    import scapy.all as scapy
    elapsed=[100.0]
    truth=SimpleNamespace(first_send=None,last_send=None,sent=0)
    monkeypatch.setattr(common,'_active_truth',truth)
    monkeypatch.setattr(common.time,'time',lambda:elapsed[0])
    def actual_send(*args,**kwargs): elapsed[0]+=0.2
    monkeypatch.setattr(scapy,'send',actual_send)
    packet=IP(src='10.0.0.1',dst='10.0.0.2')/UDP()
    common.send(packet,verbose=False)
    elapsed[0]+=45
    assert truth.first_send==100 and truth.last_send==100.2 and truth.sent==1
    assert packet[IP].tos==16


def test_live_receiver_command_names_the_host_interface(monkeypatch,tmp_path):
    from experiments.runner import Workload
    from lantern import config
    commands=[]
    class Host:
        def defaultIntf(self): return 'h1-eth0'
        def popen(self,command,**kwargs):
            commands.append(command)
            return SimpleNamespace(poll=lambda:None)
    monkeypatch.setattr(config,'HOSTS',{'h1':('10.0.0.1','','','')})
    monkeypatch.setattr(config,'RESULTS_RAW_DIR',str(tmp_path))
    workload=Workload(SimpleNamespace(get=lambda name:Host()),'case',1)
    workload.DEFAULT_NORMAL_HOSTS=[]
    monkeypatch.setattr(workload,'check_receivers',lambda prefix:None)
    workload.start_measurements()
    receiver=next(c for c in commands if c[2]=='traffic.observe')
    assert receiver[receiver.index('--iface')+1]=='h1-eth0'
    for handle in workload._log_handles: handle.close()


def test_protocol_two_validation_rejects_missing_health(tmp_path,monkeypatch):
    from experiments.validation import validate_run
    from lantern import config
    monkeypatch.setattr(config,'HOSTS',{'h1':('10.0.0.1','','','')})
    monkeypatch.setattr(config,'WORKSTATIONS',[])
    monkeypatch.setattr(config,'ATTACKER','h1')
    monkeypatch.setattr(config,'SWITCHES',['s1'])
    log=tmp_path/'C1_trial01.jsonl'
    log.write_text('\n'.join(json.dumps(e) for e in [
        dict(kind='run_end'),dict(kind='switch_connected',dpid=1),
        dict(kind='detector_timing',warming_up=False,wall=20)])+'\n')
    log.with_suffix('.meta.json').write_text('{"measurement_protocol_version":2}')
    log.with_name(log.stem+'_probe_h1.jsonl').write_text('{"success":true}\n')
    receiver=log.with_name(log.stem+'_receiver_h1.jsonl')
    receiver.write_text(json.dumps(dict(ready=True,iface='h1-eth0',health_counts={}))+'\n')
    assert 'unhealthy receiver capture for h1' in validate_run(log)['reasons']
    receiver.write_text(json.dumps(dict(ready=True,iface='h1-eth0',health_counts={'b':5}))+'\n')
    assert validate_run(log)['valid']


def test_receiver_detects_crashed_capture_thread(monkeypatch,tmp_path):
    import traffic.observe as module
    class CrashedSniffer:
        running=True
        thread=SimpleNamespace(is_alive=lambda:False)
        def __init__(self,**kwargs): self.ready=kwargs['started_callback']
        def start(self): self.ready()
    monkeypatch.setattr(module,'AsyncSniffer',CrashedSniffer)
    with pytest.raises(RuntimeError,match='capture stopped'):
        main(['--ip','10.0.0.1','--iface','h1-eth0','--output',str(tmp_path/'counts')])
    assert (tmp_path/'counts').read_text()==''
