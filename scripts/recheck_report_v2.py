#!/usr/bin/env python3
"""Strict per-trial cross-check, independent of the report aggregation code.

Run recheck_v2_crypto first. Reads original evidence without modifying it.
"""
from pathlib import Path
from collections import Counter, defaultdict
import argparse, csv, hashlib, json, math, statistics, tomllib

ROOT = Path(__file__).resolve().parents[2]
COMMIT = '0xede0ef2c772f92e0eb3915d9b1f6874fe06efba093ed906762b87855be67350d'
ANCHOR = '0xc3856abc01eaa5537963c81160e9017cac08a36ed7f02b082fbd906e88672245'
VERDICT = '0xfe37dde3397ab6468637ae937639cd2091301ac0936be2431af86a2e0a547a83'

def require(ok, message):
    if not ok:
        raise ValueError(message)

def jread(path): return json.loads(path.read_text())
def lines(path): return [json.loads(x) for x in path.read_text().splitlines()]
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def word(value): return int(value).to_bytes(32, 'big').hex()
def txwords(tx):
    data = bytes.fromhex(tx.get('data', tx.get('input', ''))[2:])
    require(len(data) >= 4, 'missing transaction calldata')
    return [data[i:i+32].hex() for i in range(4, len(data), 32)]

def events_for(receipt, topic):
    return [e for e in receipt['logs'] if e['topics'] and e['topics'][0] == topic]

def verify_trial(root, plan, trial, samples, crypto):
    name = trial.name
    faults = '-faults-' in name
    n, k, f = plan['committee']
    ts, ns = plan['thresholds'], plan['populations']
    completion = jread(trial/'completion.json')
    require(completion['passed'] and completion['epochs'] == 3 and
            completion['faults'] == faults and completion['original_secret_reconstructed'], f'{name}: completion')
    grouped = defaultdict(list)
    for row in samples:
        require(row['run'] == name and row['committee'] == plan['committee'], f'{name}: sample identity')
        require(row['scenario'] == ('integrated_faults' if faults else 'baseline'), f'{name}: scenario')
        require(row['trial'] == int(name[-3:]), f'{name}: trial index')
        require(row['status'] == 'passed' and row['execution_mode'] == 'local_processes' and
                row['chain_condition'] == 'anvil_inclusion', f'{name}: measurement scope')
        require(row['t'] == ts[row['epoch']], f'{name}: threshold mismatch')
        actual_epoch = 2 if row['metric'] in ['offline_catchup', 'consistency_dispute',
            'plaintext_dispute', 'DA_service_and_payout'] else row['epoch']
        require(row['N'] == ns[actual_epoch], f'{name}: population mismatch for {row["metric"]}')
        require(row['duration_ns'] is None or row['duration_ns'] > 0, f'{name}: duration')
        grouped[row['metric']].append(row)
    def one(metric):
        require(len(grouped[metric]) == 1, f'{name}: expected one {metric}')
        return grouped[metric][0]
    lifecycle = one('lifecycle')
    require(lifecycle['data']['population_schedule'] == ns and
            lifecycle['data']['threshold_schedule'] == ts and
            lifecycle['data']['committed_transitions'] == 3, f'{name}: lifecycle schedule')
    one('deployment_and_process_setup')
    one('bootstrap_and_initial_issuance')
    checks = [one('initial_secret_check')] + grouped['reconstruct'] + [one('final_reconstruct')]
    require([x['epoch'] for x in checks] == [0,1,2,3,3], f'{name}: reconstruction epochs')
    for s in checks:
        d = s['data']
        require(d['secret_matches_owner'] and d['shares'] == d['threshold'] == ts[s['epoch']] and
                d['epoch'] == s['epoch'], f'{name}: secret reconstruction evidence')
    require(all(x['data']['public_constant'] == checks[0]['data']['public_constant'] for x in checks),
            f'{name}: secret commitment changed')
    # Nested intervals must fit their recorded enclosing interval.
    inside = one('bootstrap_and_initial_issuance')['duration_ns'] + one('final_reconstruct')['duration_ns']
    inside += sum(x['duration_ns'] for x in grouped['epoch_with_growth'])
    if faults: inside += one('authorized_current_epoch_reissuance')['duration_ns']
    require(inside <= lifecycle['duration_ns'], f'{name}: lifecycle smaller than sequential phases')
    for s in grouped['refresh']:
        nonce = s['data']['nonce']
        parts = []
        for metric in ['generation','reservation_and_certificate','direct_delivery_stage',
                       'archive_blob_publication','commit_and_apply']:
            matches = [x for x in grouped[metric] if x['data']['nonce'] == nonce]
            require(len(matches) == 1, f'{name}: phase cardinality {metric}/{nonce}')
            parts.extend(matches)
        require(sum(x['duration_ns'] for x in parts) <= s['duration_ns'], f'{name}: refresh duration')
    require([x['epoch'] for x in grouped['refresh']] == [1,2,3], f'{name}: refresh epochs')
    require([x['epoch'] for x in grouped['offline_catchup']] == [1,2], f'{name}: catch-up count')
    for s in grouped['offline_catchup']:
        require(s['data']['dealers_running'] == 0 and s['data']['archive_replicas_running'] == 1,
                f'{name}: recovery availability')
    if not faults:
        require(grouped['offline_catchup'][0]['data']['records_read'] == k, f'{name}: exactly-k recovery')
    if faults:
        require(one('published_attempt_abort')['data']['reservation_retained'], f'{name}: abort retention')
        one('crash_restart_before_commit')
        require(one('insufficient_records_rejected')['data']['valid_available'] == k-1, f'{name}: k-1 rejection')
        require(len(grouped['authorization_negative_checks']) == 4, f'{name}: authorization negative count')
        require(all(x['data']['exact_tuple_binding'] and x['data']['no_token_before_certificate']
                    for x in grouped['authorization_negative_checks']), f'{name}: authorization checks')

    publications = {b['nonce']: b for b in crypto['bundles']}
    require(len(publications) == 3 + faults, f'{name}: publications')
    txs = []
    for path in sorted((trial/'chain').glob('*.json')):
        v = jread(path)
        if 'receipt' not in v: continue
        r = v['receipt']
        require(int(r['status'],16) == 1, f'{name}: failed transaction {path.name}')
        for event in r['logs']:
            require(not event['removed'] and event['transactionHash'] == r['transactionHash'] and
                    event['blockHash'] == r['blockHash'], f'{name}: event receipt binding')
            require(event['address'].lower() == completion['contract'].lower(), f'{name}: foreign event')
        txs.append((path.name.split('-',1)[1][:-5], v, int(path.name.split('-')[0])))
    require([i for _,_,i in txs] == list(range(len(txs))), f'{name}: receipt sequence gap')
    hashes = [v['receipt']['transactionHash'] for _,v,_ in txs]
    require(len(set(hashes)) == len(hashes), f'{name}: duplicate receipt')
    labels = Counter(label for label,_,_ in txs)
    deployment = [v for label,v,_ in txs if label == 'deploy-E2EVess']
    artifact = jread(trial.parent/'source_snapshot/benchmarks/contract-out/E2EVess.sol/E2EVess.json')
    require(len(deployment) == 1 and deployment[0]['transaction']['data'] == artifact['bytecode']['object'],
            f'{name}: deployed bytecode does not match retained Solidity artifact')
    require(deployment[0]['receipt']['contractAddress'] == completion['contract'], f'{name}: deployed contract')
    require(labels['register-participant'] == labels['activate-participant'] == ns[-1], f'{name}: enrollment count')
    require(labels['canonical-epoch-commit'] == 3, f'{name}: commit transaction count')
    require(labels['abort-after-publication'] == int(faults), f'{name}: abort count')
    for label in ['register-participant','activate-participant']:
        ids = [int(txwords(v['transaction'])[0],16) for l,v,_ in txs if l == label]
        require(sorted(ids) == list(range(1, ns[-1]+1)), f'{name}: exact enrolled IDs')
    commits = {}
    publication_indexes = {}
    for label,v,index in txs:
        r = v['receipt']
        if label == 'lifecycle-blob-publication':
            w = txwords(v['transaction']); nonce = int(w[0],16); b = publications[nonce]
            require(w[1:3] == [b['record_root'],b['metadata']], f'{name}: publication calldata binding')
            require(v['transaction']['type'] == 3 and int(r['type'],16) == 3 and
                    int(r['blobGasUsed'],16) == 131072, f'{name}: actual blob receipt')
            require(v['transaction']['blob_sha256'] == [b['blob_sha256']] and
                    v['transaction']['versioned_hashes'] == [b['versioned_hash']], f'{name}: recomputed KZG binding')
            anchors = events_for(r, ANCHOR)
            require(len(anchors) == 1 and anchors[0]['data'][2:] == b['record_root']+b['versioned_hash'][2:],
                    f'{name}: on-chain blob anchor')
            require(nonce not in publication_indexes, f'{name}: duplicate publication')
            publication_indexes[nonce] = index
        if label == 'canonical-epoch-commit':
            nonce = int(txwords(v['transaction'])[0],16); b = publications[nonce]
            es = events_for(r, COMMIT)
            require(len(es) == 1 and es[0]['topics'][1:] == ['0x'+word(nonce),'0x'+b['source'],'0x'+b['target']]
                    and es[0]['data'][2:] == b['record_root']+b['metadata'], f'{name}: commit event binding')
            require(publication_indexes[nonce] < index, f'{name}: commit before publication')
            require(nonce not in commits, f'{name}: duplicate commit nonce')
            commits[nonce] = b
    require(set(publication_indexes) == set(publications), f'{name}: unpublished bundle')
    require(list(commits) == ([2,3,4] if faults else [1,2,3]), f'{name}: committed nonce schedule')
    if faults:
        for metric,label,kind in [('consistency_dispute','actual-record-bisection-verdict',4),
                                  ('plaintext_dispute','actual-record-plaintext-complaint',2)]:
            d = one(metric)['data']
            require(d['dealer_wrong'] and d['same_lifecycle_record'] and
                    d['record_hash'] in publications[d['nonce']]['record_hashes'], f'{name}: dispute record provenance')
            found = [v['receipt'] for l,v,_ in txs if l == label]
            require(len(found) == 1, f'{name}: dispute receipt count')
            verdicts = events_for(found[0], VERDICT)
            require(len(verdicts) == 1 and verdicts[0]['topics'][1] == '0x'+d['record_hash'] and
                    verdicts[0]['data'][2:] == word(kind)+word(0), f'{name}: actual dispute verdict')
            expected = 2*math.ceil(math.log2(max(ts[:2])))+3 if metric == 'consistency_dispute' else 2
            require(d['tx_count'] == expected, f'{name}: dispute count')
        require(len(grouped['DA_service_and_payout']) == 2 and
                all(s['data']['settled'] for s in grouped['DA_service_and_payout']), f'{name}: DA payout')

    metrics = jread(trial/'node_metrics.json')
    required_ids = set(range(1,n+1)) | set(range(1001,1001+ns[-1])) | {8001,9001,9002}
    require(len(metrics) == len(required_ids) and {m['id'] for m in metrics} == required_ids, f'{name}: role population')
    require(len({m['stats']['pid'] for m in metrics}) == len(metrics), f'{name}: independent final processes')
    for m in metrics:
        if m['role'] in ['participant','dealer']:
            require(m['stats']['epoch'] == 3, f'{name}: stale final node {m["id"]}')
    applied = releases = participants = 0
    owner_checks = []
    for m in metrics:
        directory = trial/'nodes'/f'{m["role"]}-{m["id"]}'
        ev = lines(directory/'events.jsonl')
        require(all(e['node'] == m['id'] and e['role'] == m['role'] and e['run'] == name for e in ev),
                f'{name}: event identity')
        certified = set(); node_applies = []
        for e in ev:
            d = e['data']
            if e['kind'] == 'certificate_signed': certified.add(d['digest'])
            if e['kind'] == 'token_release':
                require(d['digest'] in certified and d['digest'] == publications[d['nonce']]['reservation'],
                        f'{name}: release certificate binding/order')
                releases += 1
            if e['kind'] in ['commit_applied','catchup_applied']:
                require(d['nonce'] in commits and commits[d['nonce']]['target'] == d['target'], f'{name}: unmatched apply')
                node_applies.append(d['nonce']); applied += 1
            if e['kind'] == 'secret_reconstructed':
                require(m['role'] == 'owner' and d['matches_owner'], f'{name}: owner check')
                owner_checks.append((d['epoch'],d['shares']))
        if m['role'] == 'dealer':
            require(node_applies == list(commits), f'{name}: dealer epoch coverage')
        if m['role'] == 'participant':
            participants += 1
            id_ = m['id']-1000
            expected = [nonce for nonce,b in commits.items() if id_ <= ns[b['epoch']]]
            require(node_applies == expected, f'{name}: participant epoch coverage {id_}')
            issued = [e for e in ev if e['kind'] == 'issued']
            require(len(issued) == 1+int(faults and id_ == ns[-1]), f'{name}: participant issuance {id_}')
            if id_ == 1:
                require(sum(e['kind']=='catchup_applied' for e in ev) == 2, f'{name}: offline return')
    require(owner_checks == [(i,ts[i]) for i in [0,1,2,3,3]], f'{name}: exact owner check sequence')
    return dict(profile=plan['name'],trial=name,passed=True,participants=participants,
                commits=len(commits),reconstructions=len(owner_checks),receipts=len(txs),
                gas=sum(int(v['receipt']['gasUsed'],16) for _,v,_ in txs),
                blob_gas=sum(int(v['receipt'].get('blobGasUsed','0'),16) for _,v,_ in txs),
                applied=applied,releases=releases)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input',type=Path,required=True)
    args = parser.parse_args(); root = args.input.resolve(); out = root/'recheck'
    plan = jread(root/'plan.json'); statuses = lines(root/'status.jsonl')
    require(len(plan) == len(statuses) == len({s['name'] for s in statuses}), 'profile status uniqueness')
    require([p['name'] for p in plan] == [s['name'] for s in statuses], 'plan/status coverage')
    provenance = jread(root/'source_hashes.json')
    runtime = [k for k in provenance if k.endswith(('.rs','.sol')) or k.endswith('/vess-bench')]
    require(all(sha(ROOT/k) == provenance[k] for k in runtime), 'runtime source or binary changed')
    crypto = lines(out/'crypto_checks.jsonl'); crypto_summary = jread(out/'crypto_summary.json')
    require(crypto_summary['passed'], 'cryptographic replay not complete')
    cmap = {(c['profile'],c['trial']):c for c in crypto}
    require(len(cmap) == len(crypto) == crypto_summary['trials'], 'crypto coverage')
    rows = []; raw_groups = defaultdict(list); snapshots = 0
    for p,status in zip(plan,statuses):
        run = root/'runs'/p['name']
        config = tomllib.loads((root/'configs'/f'{p["name"]}.toml').read_text())
        require(config['thresholds'] == p['thresholds'] and config['populations'] == p['populations'] and
                config['committees'] == [p['committee']] and config['repeats'] == p['repeats'] and
                config['fault_scenarios'] == p['fault_scenarios'], f'{p["name"]}: config/plan')
        if status['status'] != 'completed':
            if p['expected'] == 'blob_capacity_failure':
                require(status['status'] == 'expected_capacity_failure' and status['exit_code'] != 0, 'capacity status')
                require(jread(run/'failure.json')['error'] == 'blob payload capacity', 'capacity error')
                require(not list(run.glob('n*-trial*/completion.json')), 'capacity trial completed unexpectedly')
                sizes = {x.stat().st_size for x in run.glob('n*-trial*/nodes/archive-*/*.bundle')}
                require(sizes == {155512} and min(sizes) > 126914, 'capacity failure actual bytes')
            elif p['expected'] == 'config_rejection':
                require(status['status'] == 'expected_config_rejection' and status['exit_code'] != 0 and not run.exists(), 'config rejection')
            else:
                require(p['expected'] == 'not_run' and status['status'] == 'not_run' and not run.exists(), 'static non-execution')
            continue
        require(status['exit_code'] == 0 and status['stop_reason'] is None and not (run/'failure.json').exists(), 'completed exit')
        require(tomllib.loads((run/'config.toml').read_text()) == config, 'executed config mismatch')
        for name,digest in jread(run/'source-sha256.json').items():
            require(sha(run/'source_snapshot'/name) == digest, f'snapshot hash {p["name"]}/{name}')
            snapshots += 1
        samples = lines(run/'samples.jsonl')
        require(sha(run/'samples.jsonl') == jread(root/'derived/validation.json')['raw_data_sha256'][p['name']], 'raw sample mutation')
        names = [f'n{p["committee"][0]}-baseline-trial{i:03d}' for i in range(p['repeats'])]
        if p['fault_scenarios']: names.append(f'n{p["committee"][0]}-faults-trial000')
        require(set(s['run'] for s in samples) == set(names), 'sample trial coverage')
        start = len(rows)
        for name in names:
            selected = [s for s in samples if s['run'] == name]
            row = verify_trial(root,p,run/name,selected,cmap[(p['name'],name)])
            rows.append(row)
        audit = jread(run/'audit.json'); part = rows[start:]
        for key,col in [('receipt_count','receipts'),('execution_gas','gas'),('blob_gas','blob_gas'),
                        ('canonical_apply_events','applied'),('release_events','releases'),('secret_reconstructions','reconstructions')]:
            require(sum(r[col] for r in part) == audit[key], f'{p["name"]}: original audit {key}')
        for s in samples:
            if s['duration_ns'] is not None:
                key=(p['name'],p['family'],p['committee'][0],s['scenario'],s['metric'],s['epoch'],s['t'],s['N'])
                raw_groups[key].append(s['duration_ns']/1e6)
        print(f'CHECKED {p["name"]}: {len(part)} lifecycles',flush=True)
    derived = list(csv.DictReader((root/'derived/summary.csv').open()))
    require(len(derived) == len(raw_groups), 'summary cell coverage')
    for r in derived:
        key=(r['profile'],r['family'],int(r['dealers']),r['scenario'],r['metric'],int(r['epoch']),int(r['t']),int(r['N']))
        values = raw_groups[key]
        require(int(r['observations']) == len(values), 'summary observation count')
        for col,v in [('median_ms',statistics.median(values)),('min_ms',min(values)),('max_ms',max(values))]:
            require(math.isclose(float(r[col]),v,rel_tol=1e-12,abs_tol=1e-9), f'summary aggregate {key}/{col}')
    require(len(rows) == len(cmap), 'per-trial crypto/structural cross-check coverage')
    result = dict(passed=True,profiles=sum(s['status']=='completed' for s in statuses),trials=len(rows),
        committed_transitions=sum(r['commits'] for r in rows),owner_reconstructions=sum(r['reconstructions'] for r in rows),
        participants=sum(r['participants'] for r in rows),receipts=sum(r['receipts'] for r in rows),
        execution_gas=sum(r['gas'] for r in rows),blob_gas=sum(r['blob_gas'] for r in rows),
        participant_and_dealer_apply_events=sum(r['applied'] for r in rows),
        certified_release_events=sum(r['releases'] for r in rows),summary_cells_checked=len(derived),
        source_snapshot_hashes_checked=snapshots,runtime_source_and_binary_hashes_checked=len(runtime),
        cryptographic_replay=crypto_summary,validator_sha256=sha(Path(__file__)),
        evidence_sha256={str(path.relative_to(root)):sha(path) for path in
                         [root/'plan.json',root/'status.jsonl',root/'derived/summary.csv']+
                         [root/'runs'/p['name']/'samples.jsonl' for p,s in zip(plan,statuses) if s['status']=='completed']},
        trial_checks=rows)
    (out/'independent_validation.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k!='trial_checks'},indent=2))

if __name__ == '__main__': main()
