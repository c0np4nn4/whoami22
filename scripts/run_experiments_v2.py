#!/usr/bin/env python3
"""Run configurable experiments against the unchanged Rust/Anvil E2E harness."""
from pathlib import Path
import argparse, datetime, hashlib, json, os, platform, shutil, signal, subprocess, time

ROOT = Path(__file__).resolve().parents[2]
BIN = ROOT / 'benchmarks/target/release/vess-bench'
CAPACITY = 4094 * 31
ACTIVE = None

def digest(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

def payload(n, a, b, offline=1):
    # bincode Bundle: two State values, two Headers, keys, records and certificate.
    return 32*(n+2)*(a+b) + 432 + 232*n + offline*(8+856*n)

def matrix():
    rows = []
    def add(name, family, committee, thresholds, populations, repeats=3, faults=False, expected='complete', note=''):
        n=committee[0]
        sizes=[payload(n,a,b,int(e<=2)) for e,(a,b) in enumerate(zip(thresholds,thresholds[1:]),1)]
        rows.append(dict(name=name,family=family,committee=committee,thresholds=thresholds,populations=populations,repeats=repeats,fault_scenarios=faults,timeout_ms=180000,expected=expected,note=note,predicted_payload_bytes=sizes))
    for c in [[4,2,1],[7,3,2]]:
        n=c[0]
        add(f'reference-n{n}','reference',c,[16,32,64,32],[24,48,80,112],5,True)
    for t in [16,32,64,128]:
        for c in [[4,2,1],[7,3,2]]:
            add(f'threshold-t{t}-n{c[0]}','threshold',c,[t]*4,[160]*4,3,True)
    for population in [320,640]:
        for c in [[4,2,1],[7,3,2]]:
            add(f'population-p{population}-n{c[0]}','population',c,[32]*4,[population]*4)
    for c in [[4,2,1],[7,3,2]]:
        add(f'growth-p512-n{c[0]}','growth',c,[32]*4,[64,128,256,512])
    add('margin-n5','margin',[5,2,1],[16,32,64,32],[24,48,80,112],3,True,note='Positive publication margin m=1; fault/missing pattern remains the built-in pattern.')
    add('threshold-t256-n4','high_threshold',[4,2,1],[256]*4,[320]*4,3,True)
    add('capacity-t256-n7','capacity_probe',[7,3,2],[256]*4,[320]*4,1,False,'blob_capacity_failure','One actual attempt verifies the predicted single-blob boundary.')
    for population in [1024,2048]:
        add(f'population-p{population}-n4','population_probe',[4,2,1],[32]*4,[population]*4,1,False,note='Single-run feasibility observation, not a repeated performance estimate.')
    add('unsupported-n10','config_probe',[10,4,3],[16,32,64,32],[24,48,80,112],1,False,'config_rejection')
    add('blocked-t1024-n4','static_block',[4,2,1],[1024]*4,[2048]*4,1,False,'not_run','Current E2E publish serializes one whole bundle into one blob; no multi-blob E2E path.')
    return rows

def config_text(row):
    def array(x):return '['+', '.join(map(str,x))+']'
    return '\n'.join([f'name = "{row["name"]}"',f'repeats = {row["repeats"]}',f'committees = [{array(row["committee"])}]',f'thresholds = {array(row["thresholds"])}',f'populations = {array(row["populations"])}',f'fault_scenarios = {str(row["fault_scenarios"]).lower()}',f'timeout_ms = {row["timeout_ms"]}',''])

def save(path,value):
    path.write_text(json.dumps(value,indent=2)+'\n')

def validate_statuses(plan, statuses):
    """A finished loop is successful only if every planned outcome was observed."""
    expected_status = {'complete':'completed', 'blob_capacity_failure':'expected_capacity_failure',
                       'config_rejection':'expected_config_rejection', 'not_run':'not_run'}
    names = [p['name'] for p in plan]
    recorded = [s['name'] for s in statuses]
    if len(set(names)) != len(names) or len(set(recorded)) != len(recorded) or set(recorded) != set(names):
        raise ValueError('Missing, duplicate or unplanned profile status')
    by_name = {s['name']:s for s in statuses}
    for row in plan:
        s = by_name[row['name']]
        wanted = expected_status[row['expected']]
        if s['status'] != wanted or s.get('stop_reason'):
            raise ValueError(f'{row["name"]}: expected {wanted}, observed {s["status"]}')
        if wanted == 'completed':
            audit = s.get('audit') or {}
            if s.get('exit_code') != 0 or audit.get('passed') is not True or audit.get('trials') != row['repeats']+int(row['fault_scenarios']):
                raise ValueError(f'{row["name"]}: incomplete successful-run evidence')
        elif wanted != 'not_run' and (not isinstance(s.get('exit_code'),int) or s['exit_code'] == 0):
            raise ValueError(f'{row["name"]}: expected a nonzero process exit')

def process_group(pgid):
    rows=[]
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit():continue
        try:
            raw=(entry/'stat').read_text(); fields=raw[raw.rindex(')')+2:].split()
            if int(fields[2])!=pgid:continue
            rows.append(dict(pid=int(entry.name),rss_bytes=int(fields[21])*os.sysconf('SC_PAGE_SIZE')))
        except (OSError,ValueError,IndexError):pass
    return rows

def stop(p):
    try:os.killpg(p.pid,signal.SIGTERM)
    except ProcessLookupError:return
    try:p.wait(timeout=5)
    except subprocess.TimeoutExpired:pass
    try:os.killpg(p.pid,signal.SIGKILL)
    except ProcessLookupError:pass
    p.wait()

def interrupted(signum,frame):
    if ACTIVE is not None:stop(ACTIVE)
    raise SystemExit(128+signum)

def run_one(row,out,seconds,rss_limit):
    global ACTIVE
    name=row['name']; config=out/'configs'/f'{name}.toml'; config.write_text(config_text(row))
    run=out/'runs'/name; log=out/'logs'/f'{name}.log'
    if row['expected']=='not_run':
        return dict(name=name,status='not_run',reason=row['note'],expected=row['expected'])
    if run.exists():
        # A signal may arrive before a profile status is appended. Preserve that
        # incomplete attempt before resuming the same planned profile.
        suffix=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
        preserved=out/'interrupted_attempts'/f'{name}-{suffix}'
        preserved.mkdir(parents=True)
        shutil.move(str(run),str(preserved/'run'))
        if log.exists():shutil.move(str(log),str(preserved/'run.log'))
        old_resources=out/'resources'/f'{name}.json'
        if old_resources.exists():shutil.move(str(old_resources),str(preserved/'resources.json'))
        save(preserved/'reason.json',dict(reason='Existing output without a recorded profile status; preserved before resume',profile=name))
        print(f'PRESERVED interrupted attempt: {preserved}',flush=True)
    start=time.monotonic(); peak=0;max_processes=0;mon=[];reason=None
    with log.open('w') as stream:
        ACTIVE=subprocess.Popen([str(BIN),'e2e-run','--config',str(config),'--out',str(run)],cwd=ROOT/'benchmarks',stdout=stream,stderr=subprocess.STDOUT,start_new_session=True)
        p=ACTIVE;last_progress=0
        try:
            while p.poll() is None:
                now=time.monotonic()-start
                processes=process_group(p.pid);rss=sum(x['rss_bytes'] for x in processes)
                peak=max(peak,rss);max_processes=max(max_processes,len(processes))
                mon.append(dict(elapsed_seconds=now,rss_sum_bytes=rss,processes=len(processes)))
                if rss>rss_limit:
                    reason='aggregate_RSS_guard';stop(p);break
                if now>seconds:
                    reason='profile_wall_clock_timeout';stop(p);break
                if now-last_progress>=30:
                    lines=log.read_text(errors='replace').splitlines()
                    print(f'  {name}: {now:.0f}s, {len(processes)} processes, RSS sum {rss/2**30:.2f} GiB; '+(lines[-1][:180] if lines else 'starting'),flush=True)
                    last_progress=now
                time.sleep(1)
            code=p.wait()
        finally:
            stop(p);ACTIVE=None
    elapsed=time.monotonic()-start
    save(out/'resources'/f'{name}.json',mon)
    error=json.loads((run/'failure.json').read_text()) if (run/'failure.json').exists() else None
    audit=json.loads((run/'audit.json').read_text()) if (run/'audit.json').exists() else None
    complete=code==0 and audit is not None and audit.get('passed') is True
    status='completed' if complete else 'failed'
    if reason:status='stopped'
    logtext=log.read_text(errors='replace')
    if row['expected']=='blob_capacity_failure' and code!=0 and 'blob payload capacity' in logtext:status='expected_capacity_failure'
    if row['expected']=='config_rejection' and code!=0 and 'at most seven dealers' in logtext:status='expected_config_rejection'
    result=dict(name=name,status=status,expected=row['expected'],exit_code=code,wall_seconds=elapsed,peak_sampled_rss_sum_bytes=peak,max_sampled_processes=max_processes,stop_reason=reason,error=error,audit=audit,log_tail=logtext.splitlines()[-12:])
    print(f'END {name}: {status}, {elapsed:.1f}s',flush=True)
    return result

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--resume',action='store_true')
    parser.add_argument('--profile',action='append')
    parser.add_argument('--plan-only',action='store_true')
    parser.add_argument('--profile-timeout',type=int,default=1200)
    parser.add_argument('--rss-limit-gib',type=float,default=16)
    args=parser.parse_args();out=args.out.resolve()
    rows=matrix()
    if args.profile:
        known={r['name'] for r in rows};assert set(args.profile)<=known
        rows=[r for r in rows if r['name'] in args.profile]
    if out.exists():
        assert args.resume,'Output exists; use a fresh output or --resume'
        original=json.loads((out/'plan.json').read_text())
        assert original==rows,'Resume must use the original experiment plan'
    else:
        for folder in ['configs','runs','logs','resources','suite_source']:(out/folder).mkdir(parents=True,exist_ok=True)
        save(out/'plan.json',rows)
        sources=[ROOT/'run_experiments_v2.sh',Path(__file__),ROOT/'benchmarks/scripts/render_report_v2.py']
        hashes={}
        for path in sources:
            if path.exists():
                shutil.copy2(path,out/'suite_source'/path.name);hashes[str(path.relative_to(ROOT))]=digest(path)
        for path in sorted((ROOT/'benchmarks/src').rglob('*.rs')):hashes[str(path.relative_to(ROOT))]=digest(path)
        for path in sorted((ROOT/'benchmarks/contracts').rglob('*.sol')):hashes[str(path.relative_to(ROOT))]=digest(path)
        hashes['benchmarks/target/release/vess-bench']=digest(BIN)
        save(out/'source_hashes.json',hashes)
        save(out/'host.json',dict(timestamp_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),platform=platform.platform(),cpu=Path('/proc/cpuinfo').read_text(),memory=Path('/proc/meminfo').read_text(),monitor='1 second aggregate process-group RSS samples; shared pages counted repeatedly',profile_timeout_seconds=args.profile_timeout,rss_limit_gib=args.rss_limit_gib))
        for row in rows:(out/'configs'/f'{row["name"]}.toml').write_text(config_text(row))
    if args.plan_only:
        print(json.dumps(rows,indent=2));return
    for sig in [signal.SIGINT,signal.SIGTERM]:signal.signal(sig,interrupted)
    statuspath=out/'status.jsonl'
    done={r['name'] for r in [json.loads(x) for x in statuspath.read_text().splitlines()]} if statuspath.exists() else set()
    for index,row in enumerate(rows,1):
        if row['name'] in done:continue
        print(f'START {index}/{len(rows)} {row["name"]}: {row["expected"]}',flush=True)
        result=run_one(row,out,args.profile_timeout,args.rss_limit_gib*2**30)
        with statuspath.open('a') as f:f.write(json.dumps(result)+'\n')
    statuses=[json.loads(x) for x in statuspath.read_text().splitlines()]
    validate_statuses(rows,statuses)
    print('Suite complete; all planned outcomes verified: '+str(out),flush=True)

if __name__=='__main__':main()
