#!/usr/bin/env python3
"""Derive manuscript tables and a vector figure from the completed E2E run.

No experiments are rerun and no raw observations are modified.
Use --check to compare generated table blocks with local_v2.tex.
"""
from pathlib import Path
import argparse
import csv
import hashlib
import json
import statistics as st

ROOT = Path(__file__).resolve().parents[2]
RUN = ROOT / 'benchmarks/results/e2e-anvil-final'
OUT = ROOT / 'paper_artifacts/local_v2'


def table(key, caption, label, spec, header, rows):
    return '\n'.join([
        f'% BEGIN E2E TABLE: {key}', r'\begin{table}[tbp]', r'\centering',
        '\\caption{' + caption + '}', '\\label{' + label + '}',
        r'\footnotesize', r'\setlength{\tabcolsep}{' + ('5pt' if key in ['chain', 'disputes'] else '3.5pt') + '}',
        '\\begin{tabular}{@{}' + spec + '@{}}', r'\toprule',
        header + r'\\', r'\midrule',
        *[row + r'\\' for row in rows], r'\bottomrule',
        r'\end{tabular}', r'\end{table}', f'% END E2E TABLE: {key}', ''])


def build():
    OUT.mkdir(parents=True, exist_ok=True)
    samples = [json.loads(line) for line in (RUN / 'samples.jsonl').read_text().splitlines()]
    summary = list(csv.DictReader((RUN / 'summary.csv').open()))
    audit = json.loads((RUN / 'audit.json').read_text())
    assert audit['passed'] and audit['trials'] == 12
    groups = {}
    for row in summary:
        key = (int(row['dealers']), row['scenario'], row['metric'], int(row['epoch']))
        assert key not in groups, key
        groups[key] = row
    def group(n, metric, epoch, scenario='baseline'):
        return groups[n, scenario, metric, epoch]
    def med(n, metric, epoch, scenario='baseline'):
        return float(group(n, metric, epoch, scenario)['median_ms'])
    def observations(n, metric, epoch, scenario='baseline'):
        return [s for s in samples if s['committee'][0] == n and s['scenario'] == scenario
                and s['metric'] == metric and s['epoch'] == epoch]
    # Verify the medians directly from independent lifecycle samples.
    for (n, scenario, metric, epoch), row in groups.items():
        vals = [s['duration_ns'] / 1e6 for s in observations(n, metric, epoch, scenario)]
        assert len(vals) == int(row['samples'])
        assert abs(st.median(vals) - float(row['median_ms'])) < 0.0000006
    receipt_rows = {}
    receipt_count = 0
    for trial in sorted(RUN.glob('n*-trial*')):
        entries = []
        for f in sorted((trial / 'chain').glob('*.json')):
            v = json.loads(f.read_text())
            if 'receipt' not in v:
                continue
            r = v['receipt']
            assert int(r['status'], 16) == 1
            entries.append(dict(index=int(f.stem.split('-')[0]), label=f.stem.split('-', 1)[1],
                                gas=int(r['gasUsed'], 16), blob_gas=int(r.get('blobGasUsed', '0x0'), 16)))
        receipt_rows[trial.name] = entries
        receipt_count += len(entries)
    assert receipt_count == audit['receipt_count'] == 3024
    chain, registry, dispute = {}, {}, {}
    for n in [4, 7]:
        baseline = [v for k, v in receipt_rows.items() if k.startswith(f'n{n}-baseline-')]
        assert len(baseline) == 5
        for label in ['reservation-CAS', 'lifecycle-blob-publication', 'canonical-epoch-commit']:
            series = [[r['gas'] for r in trial if r['label'] == label] for trial in baseline]
            assert all(len(v) == 3 for v in series)
            chain[n, label] = [st.median(v) for v in zip(*series)]
        registry[n] = dict(
            gas=st.median(sum(r['gas'] for r in trial if r['label'] in ['register-participant', 'activate-participant']) for trial in baseline),
            total_gas=st.median(sum(r['gas'] for r in trial) for trial in baseline))
        entries = receipt_rows[f'n{n}-faults-trial000']
        da_index = 0
        for r in entries:
            if r['label'] == 'actual-record-admission':
                first = r['index']
            if r['label'] in ['actual-record-bisection-verdict', 'actual-record-plaintext-complaint']:
                selected = [v for v in entries if first <= v['index'] <= r['index']]
                kind = 'consistency' if r['label'].endswith('verdict') else 'plaintext'
                dispute[n, kind] = dict(gas=sum(v['gas'] for v in selected), tx=len(selected))
                assert len(selected) == (13 if kind == 'consistency' else 2)
            if r['label'] == 'actual-publication-DA-obligation':
                da_first = r['index']
            if r['label'] == 'dealer-withdraw':
                da_index += 1
                selected = [v for v in entries if da_first <= v['index'] <= r['index']]
                dispute[n, f'da{da_index}'] = dict(gas=sum(v['gas'] for v in selected), tx=len(selected))
                assert len(selected) == 5
    tables = {}
    summary_rows = []
    for title, metric, epoch, scale in [
        ('Complete lifecycle (s)', 'lifecycle', 3, 1000),
        ('Catch-up to epoch 1 (ms)', 'offline_catchup', 1, 1),
        ('Catch-up to epoch 2 (ms)', 'offline_catchup', 2, 1),
    ]:
        summary_rows.append(title + ' & ' + ' & '.join(
            f'{med(n, metric, epoch)/scale:.3f}' for n in [4, 7]))
    tables['summary'] = table('summary',
        'End-to-end results: medians of five lifecycles per committee. Catch-up runs with all dealers stopped and one archive available.',
        'tab:e2e-summary', 'lrr',
        r'Measurement & $(4,2,1)$ & $(7,3,2)$', summary_rows)
    tables['schedule'] = table('schedule',
        r'One continuous lifecycle. Enrollment precedes the transition and uses the source threshold. $N$ counts enrolled participant processes; $|\Off|$ counts those missing the transition. Both committee configurations use this schedule.',
        'tab:e2e-schedule', 'lrrrr',
        r'Stage & New participants & $N$ & $t_{\rm src}\to t_{\rm dst}$ & $|\Off|$',
        [r'Initialization & 24 & 24 & $-\to16$ & --',
         r'Epoch $0\to1$ & 24 & 48 & $16\to32$ & 1',
         r'Epoch $1\to2$ & 32 & 80 & $32\to64$ & 1',
         r'Epoch $2\to3$ & 32 & 112 & $64\to32$ & 0'])
    rows = []
    for n, k, f in [(4,2,1),(7,3,2)]:
        g = group(n, 'lifecycle', 3)
        rows.append(f'$({n},{k},{f})$ & 5 & {float(g["median_ms"])/1000:.3f} & {float(g["min_ms"])/1000:.3f} & {float(g["max_ms"])/1000:.3f}')
    tables['lifecycle'] = table('lifecycle',
        'Directly timed baseline lifecycle latency in seconds. Each observation starts with owner initialization and ends with the final reconstruction after three committed transitions. Deployment/setup is excluded; growth, key rotation and planned offline return are included.',
        'tab:e2e-lifecycle', 'lrrrr',
        r'$(n_D,k_D,f_D)$ & Trials & Median (s) & Min (s) & Max (s)', rows)
    phases = [('growth_issuance','Growth / enrollment'), ('liveness','Liveness'),
              ('generation','Generation'), ('reservation_and_certificate','Reservation / certificate'),
              ('direct_delivery_stage','Direct delivery / staging'), ('archive_blob_publication','Archive / blob publication'),
              ('commit_and_apply','Commit / apply'), ('refresh',r'\emph{Refresh, directly timed}'),
              ('reconstruct','Reconstruction'), ('epoch_with_growth',r'\emph{Epoch with growth}')]
    rows = [title + ' & ' + ' & '.join(f'{med(n,m,e):.1f}' for n in [4,7] for e in [1,2,3]) for m,title in phases]
    tables['phases'] = table('phases',
        'Baseline phase medians in milliseconds, five lifecycle trials per cell. Epochs 1, 2 and 3 have target $(t,N)=(32,48),(64,80),(32,112)$. Refresh and epoch-with-growth are independently timed enclosing intervals; the displayed phase medians are not added to obtain either total.',
        'tab:e2e-phases', 'lrrrrrr',
        r'& \multicolumn{3}{c}{$n_D=4$} & \multicolumn{3}{c}{$n_D=7$}\\ \cmidrule(lr){2-4}\cmidrule(lr){5-7} Phase & 1 & 2 & 3 & 1 & 2 & 3', rows)
    rows = []
    for title, e, scenario in [('Baseline',1,'baseline'),('Baseline',2,'baseline'),
                                ('Inconsistent record',1,'integrated_faults'),('Bad plaintext',2,'integrated_faults')]:
        obs = [observations(n,'offline_catchup',e,scenario) for n in [4,7]]
        for values in obs:
            assert len({json.dumps(v['data'], sort_keys=True) for v in values}) == 1
        data = [v[0]['data'] for v in obs]
        rows.append(f'{title} & {e} & {med(4,"offline_catchup",e,scenario):.3f} & {med(7,"offline_catchup",e,scenario):.3f} & '
                    + '/'.join(str(d['records_read']) for d in data) + ' & '
                    + '/'.join(str(d['vector_fetches']) for d in data))
    tables['recovery'] = table('recovery',
        r'Recovery with all dealers stopped and one archive remaining. Baseline latencies are medians of five trials; each fault entry is one integrated trial. Fetch counts are shown as $n_D=4/7$. The recovered epoch is 1 or 2, but every recovery occurs at population $N=80$ after the second transition. Vector fetches retrieve a dealer\textquotesingle s source/target vector pair.',
        'tab:e2e-recovery', 'lrrrrr',
        r'Path & Epoch & 4 dealers (ms) & 7 dealers (ms) & Records & Vectors', rows)
    cases = [('lifecycle',3,'Fault lifecycle','s',1000),
             ('published_attempt_abort',1,'Published attempt, then abort','ms',1),
             ('crash_restart_before_commit',1,'Restart after durable staging','ms',1),
             ('insufficient_records_rejected',2,r'Reject $k_D-1$ records','ms',1),
             ('authorized_current_epoch_reissuance',3,'Authorized current-epoch re-issuance','ms',1)]
    rows = [f'{title} & {unit} & {med(4,m,e,"integrated_faults")/scale:.3f} & {med(7,m,e,"integrated_faults")/scale:.3f}' for m,e,title,unit,scale in cases]
    tables['faults'] = table('faults',
        'Selected durations within one integrated fault lifecycle per committee. These are functional observations, not repeated estimates of fault-case performance. The aborted candidate is published before a fresh successful retry.',
        'tab:e2e-faults','llrr',r'Measurement & Unit & 4 dealers & 7 dealers',rows)
    rows = []
    for n in [4,7]:
        for e in [1,2,3]:
            obs = observations(n,'archive_blob_publication',e)
            payloads = {v['data']['payload_bytes'] for v in obs}
            assert len(payloads)==1 and all(v['data']['physical_blob_bytes']==131072 for v in obs)
            rows.append(f'{n} & {e} & {1 if e<3 else 0} & {next(iter(payloads)):,} & ' +
                        ' & '.join(f'{chain[n,label][e-1]:,}' for label in ['reservation-CAS','lifecycle-blob-publication','canonical-epoch-commit']))
    tables['chain'] = table('chain',
        'Publication payload and execution gas of the three core transition transactions. Gas entries are medians of five baseline receipts for the same committee and epoch. Payload includes records, both states, vectors, metadata and the certificate. Every row additionally consumes 131,072 blob gas in one 128-KiB blob. Enrollment, key rotation and deployment are separate.',
        'tab:e2e-chain','rrrrrrr',
        r'$n_D$ & Epoch & $|\Off|$ & Payload (B) & Reserve gas & Publish gas & Commit gas',rows)
    rows = []
    for title,kind,metric,e in [('Consistency, $T=32$','consistency','consistency_dispute',1),
                              ('Plaintext, $t=64$','plaintext','plaintext_dispute',2),
                              ('DA after consistency','da1','DA_service_and_payout',1),
                              ('DA after plaintext','da2','DA_service_and_payout',2)]:
        rows.append(f'{title} & {dispute[4,kind]["tx"]} & ' +
                    ' & '.join(f'{med(n,metric,e,"integrated_faults"):.3f} & {dispute[n,kind]["gas"]/1e6:.3f}' for n in [4,7]))
    tables['disputes'] = table('disputes',
        'Accountability operations on actual lifecycle records, one observation per cell. Execution gas is in millions (Mgas). Dispute intervals include admission and all complaint/game transactions; publication selection and deposits precede the timer. DA intervals include obligation, request, actual-byte response and both withdrawals.',
        'tab:e2e-disputes','lrrrrr',
        r'& & \multicolumn{2}{c}{4 dealers} & \multicolumn{2}{c}{7 dealers}\\ \cmidrule(lr){3-4}\cmidrule(lr){5-6} Path & Tx & ms & Mgas & ms & Mgas',rows)
    for key, text in tables.items():
        (OUT/f'{key}.tex').write_text(text)
    def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
    metrics = dict(source='benchmarks/results/e2e-anvil-final',
                   sample_sha256=digest(RUN/'samples.jsonl'),summary_sha256=digest(RUN/'summary.csv'),
                   generator_sha256=digest(Path(__file__)),receipt_count=receipt_count,
                   chain_gas={str(k):v for k,v in chain.items()},registry_gas=registry,
                   dispute_gas={str(k):v for k,v in dispute.items()},audit=audit)
    (OUT/'metrics.json').write_text(json.dumps(metrics,indent=2)+'\n')
    # Scientific figure: actual observations and descriptive ranges, never p99/CI.
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    plt.rcParams.update({'font.family':'serif','font.size':8,'axes.labelsize':8,
                         'legend.fontsize':7,'pdf.fonttype':42,'ps.fonttype':42})
    fig, axes = plt.subplots(1,2,figsize=(4.8,2.55),gridspec_kw={'width_ratios':[0.85,1.25]})
    colors = {4:'#2563a6',7:'#b84a32'}
    for i,n in enumerate([4,7]):
        values = [r['duration_ns']/1e9 for r in observations(n,'lifecycle',3)]
        jitters = [-.12,-.06,0,.06,.12]
        axes[0].scatter([i+j for j in jitters],values,color=colors[n],s=15,alpha=.8,zorder=3)
        axes[0].hlines(st.median(values),i-.24,i+.24,color=colors[n],lw=1.5)
    axes[0].set(xticks=[0,1],xticklabels=['4 dealers','7 dealers'],ylabel='Lifecycle (s)',xlim=(-.45,1.45))
    axes[0].set_title('(a) Independent lifecycles',fontsize=8)
    for n,offset,marker in [(4,-.04,'o'),(7,.04,'s')]:
        vals=[[r['duration_ns']/1e9 for r in observations(n,'refresh',e)] for e in [1,2,3]]
        mids=[st.median(v) for v in vals]
        errors=[[m-min(v) for m,v in zip(mids,vals)],[max(v)-m for m,v in zip(mids,vals)]]
        axes[1].errorbar([e+offset for e in [1,2,3]],mids,yerr=errors,fmt=marker+'-',
                         color=colors[n],ms=3.5,lw=1,capsize=3,label=f'{n} dealers')
    axes[1].set(xticks=[1,2,3],xticklabels=['1\n32/48','2\n64/80','3\n32/112'],
                xlabel='Target epoch; t/N',ylabel='Refresh (s)',xlim=(.7,3.3))
    axes[1].set_title('(b) Refresh median and range',fontsize=8)
    axes[1].legend(loc='upper right',frameon=False,handlelength=1)
    for ax in axes:
        ax.grid(axis='y',alpha=.25,lw=.5)
        ax.spines[['top','right']].set_visible(False)
        ax.tick_params(labelsize=7)
    fig.tight_layout(pad=.8,w_pad=1.4)
    figure=ROOT/'figures/vess_e2e_latencies'
    fig.savefig(str(figure)+'.pdf',metadata={'CreationDate':None,'ModDate':None})
    fig.savefig(str(figure)+'.png',dpi=220)
    plt.close(fig)
    return tables


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check',action='store_true')
    args=parser.parse_args()
    tables=build()
    if args.check:
        manuscript=(ROOT/'local_v2.tex').read_text()
        for key,block in tables.items():
            assert block.strip() in manuscript, f'Manuscript table differs: {key}'
    print(f'Validated {len(tables)} tables and {3024} receipts; derived files in {OUT.relative_to(ROOT)}.')
