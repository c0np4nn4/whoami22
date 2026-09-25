#!/usr/bin/env python3
"""Exercise verification failures on memory copies and temporary fixtures only."""
import argparse, copy, json, subprocess, sys, tempfile
from pathlib import Path
from run_experiments_v2 import validate_statuses
from recheck_report_v2 import verify_trial

ROOT = Path(__file__).resolve().parents[2]

def read(path): return json.loads(path.read_text())
def lines(path): return [json.loads(x) for x in path.read_text().splitlines()]

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--input',type=Path,required=True)
    args = ap.parse_args(); root = args.input.resolve()
    plan, statuses = read(root/'plan.json'), lines(root/'status.jsonl')
    results = []
    def reject(name, function, message):
        try: function()
        except ValueError as error:
            assert message in str(error), (name,str(error))
            results.append(dict(test=name,rejected=True,reason=str(error)))
        else: raise AssertionError(f'Invalid fixture accepted: {name}')
    bad = copy.deepcopy(statuses)
    bad[0].update(status='failed',exit_code=1,audit=None)
    reject('unexpected profile failure',lambda:validate_statuses(plan,bad),'expected completed')
    reject('missing profile',lambda:validate_statuses(plan,statuses[:-1]),'Missing, duplicate')
    reject('duplicate profile',lambda:validate_statuses(plan,statuses+[statuses[0]]),'Missing, duplicate')
    short = copy.deepcopy(statuses); short[0]['audit']['trials'] = 1
    reject('too few completed trials',lambda:validate_statuses(plan,short),'incomplete successful-run evidence')
    # Check actual command exit codes; all names are already recorded so resume
    # must not launch Anvil or any new trial, even with this invalid fixture.
    with tempfile.TemporaryDirectory(prefix='vess-v2-status-control-') as tmp:
        fixture = Path(tmp)
        (fixture/'plan.json').write_text(json.dumps(plan))
        (fixture/'status.jsonl').write_text(''.join(json.dumps(s)+'\n' for s in bad))
        for script,args_ in [('run_experiments_v2.py',['--out',str(fixture),'--resume']),
                             ('render_report_v2.py',['--input',str(fixture),'--out',str(fixture/'report.tex')])]:
            p = subprocess.run([sys.executable,str(ROOT/'benchmarks/scripts'/script),*args_],
                               capture_output=True,text=True,timeout=20)
            assert p.returncode != 0 and 'expected completed, observed failed' in p.stderr, (script,p.stderr)
            assert 'START ' not in p.stdout and not (fixture/'report.tex').exists()
            results.append(dict(test=script+' rejects failed suite',rejected=True,exit_code=p.returncode))
    profile = next(p for p in plan if p['name']=='threshold-t32-n4')
    trial = root/'runs'/profile['name']/'n4-baseline-trial000'
    samples = [s for s in lines(trial.parent/'samples.jsonl') if s['run']==trial.name]
    crypto = next(c for c in lines(root/'recheck/crypto_checks.jsonl')
                  if (c['profile'],c['trial'])==(profile['name'],trial.name))
    modified = copy.deepcopy(samples)
    next(s for s in modified if s['metric']=='final_reconstruct')['data']['secret_matches_owner'] = False
    reject('failed reconstruction despite completion marker',
           lambda:verify_trial(root,profile,trial,modified,crypto),'secret reconstruction evidence')
    with tempfile.TemporaryDirectory(prefix='vess-v2-blob-control-') as tmp:
        fixture = Path(tmp); run = fixture/'runs'/profile['name']; run.mkdir(parents=True)
        status = next(s for s in statuses if s['name']==profile['name'])
        (fixture/'status.jsonl').write_text(json.dumps(status)+'\n')
        (run/'config.toml').symlink_to(trial.parent/'config.toml')
        target = run/trial.name; target.mkdir()
        (target/'nodes').symlink_to(trial/'nodes',target_is_directory=True)
        (target/'completion.json').symlink_to(trial/'completion.json')
        (target/'public').mkdir()
        for path in (trial/'public').iterdir():
            if path.name == '1.blob':
                data = bytearray(path.read_bytes()); data[-1] ^= 1
                (target/'public'/path.name).write_bytes(data)
            else: (target/'public'/path.name).symlink_to(path)
        p = subprocess.run([str(ROOT/'benchmarks/target/release/examples/recheck_v2_crypto'),
                            str(fixture),str(fixture/'output')],capture_output=True,text=True,timeout=30)
        assert p.returncode != 0 and 'actual blob bytes do not encode bundle' in p.stderr, p.stderr
        results.append(dict(test='mutated retained blob',rejected=True,exit_code=p.returncode))
    result = dict(passed=True,negative_controls=len(results),cases=results,
                  note='Original artifacts were never mutated; fixture directories were removed.')
    (root/'recheck/negative_controls.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))

if __name__ == '__main__': main()
