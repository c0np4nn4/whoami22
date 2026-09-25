#!/usr/bin/env python3
"""Derive local_v3 tables and figures from the verified follow-up dataset.

This script never reruns experiments or edits manuscript prose. --check verifies
that each generated table is embedded unchanged in local_v3.tex.
"""
from pathlib import Path
import argparse, hashlib, json, statistics
import render_report_v2 as report

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT/'benchmarks/results/report-v2-20260922'
OUT = ROOT/'paper_artifacts/local_v3'
BLOCKS = {}

def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def f(x,d=3): return '--' if x is None else f'{x:,.{d}f}'
def sec(item,metric,epoch=None,scenario='baseline'):
    x=report.med(item['samples'],metric,epoch,scenario)
    return None if x is None else x/1000
def ms(item,metric,epoch=None,scenario='baseline'):
    return report.med(item['samples'],metric,epoch,scenario)
def ident(p):
    n=p['committee'][0];family=p['family']
    if family=='reference':return f'R{n}'
    if family in ['threshold','high_threshold']:return f'T{p["thresholds"][0]}-{n}'
    if family in ['population','population_probe']:return f'N{p["populations"][0]}-{n}'
    return {'growth':f'G512-{n}','margin':'M5','capacity_probe':'X256-7',
            'config_probe':'X10','static_block':'X1024-4'}[family]
def schedule(values):
    return str(values[0]) if len(set(values))==1 else '$'+r'\to'.join(map(str,values))+'$'
def table(key,label,caption,headers,rows,spec=None,long=False):
    spec=spec or '@{}l'+'r'*(len(headers)-1)+'@{}'
    if long:
        text=r'\begingroup\footnotesize\setlength{\tabcolsep}{3pt}'+'\n'
        text+=r'\begin{longtable}{'+spec+'}\n'+r'\caption{'+caption+r'}\label{'+label+r'}\\'+'\n'
        text+=r'\toprule'+'\n'+' & '.join(headers)+r'\\\midrule\endfirsthead'+'\n'
        text+=r'\multicolumn{'+str(len(headers))+r'}{c}{\tablename~\thetable{} continued}\\\toprule'+'\n'
        text+=' & '.join(headers)+r'\\\midrule\endhead'+'\n'
        text+=r'\bottomrule\endfoot'+'\n'
    else:
        text=r'\begin{table}[tbp]\centering'+'\n'+r'\caption{'+caption+'}\n'+r'\label{'+label+'}\n'
        text+=r'\footnotesize\setlength{\tabcolsep}{3pt}'+'\n'+r'\begin{tabular}{'+spec+'}\n'
        text+=r'\toprule'+'\n'+' & '.join(headers)+r'\\\midrule'+'\n'
    text+='\n'.join(' & '.join(str(x) for x in row)+r'\\' for row in rows)+'\n'
    text+=(r'\end{longtable}\endgroup' if long else r'\bottomrule\end{tabular}\end{table}')+'\n'
    BLOCKS[key]=f'% BEGIN V3 TABLE: {key}\n'+text+f'% END V3 TABLE: {key}\n'

def chain_rows(path):
    rows=[]
    for p in sorted((path/'chain').glob('*.json')):
        v=json.loads(p.read_text())
        if 'receipt' in v:
            r=v['receipt'];assert int(r['status'],16)==1
            rows.append({'label':p.stem.split('-',1)[1],'gas':int(r['gasUsed'],16),'receipt':r})
    return rows

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--check',action='store_true');args=ap.parse_args()
    plan,statuses,complete,partial,validation=report.collect(DATA)
    verified=json.loads((DATA/'recheck/independent_validation.json').read_text())
    assert verified['passed'] and verified['trials']==72 and len(complete)==20
    for name,digest in verified['evidence_sha256'].items():assert sha(DATA/name)==digest,name
    by={x['plan']['name']:x for x in complete}
    threshold=[x for x in complete if x['plan']['family']=='threshold']
    population=sorted([x for x in complete if x['plan']['family'] in ['population','population_probe'] or
        (x['plan']['family']=='threshold' and x['plan']['thresholds'][0]==32)],key=lambda x:(x['plan']['committee'][0],x['plan']['populations'][0]))
    fault=[x for x in complete if x['plan']['fault_scenarios']]
    references=[by['reference-n4'],by['reference-n7']]
    table('summary','tab:e2e-summary',
        'Reference schedule in the follow-up suite: five baseline lifecycles per committee. Recovery uses one archive with all dealers stopped; the two recovery entries are separate request intervals.',
        ['Measurement','$(4,2,1)$','$(7,3,2)$'],[
        ['Lifecycle median (s)',*[f(sec(x,'lifecycle')) for x in references]],
        ['Lifecycle minimum (s)',*[f(min(report.times(x['samples'],'lifecycle'))/1000) for x in references]],
        ['Lifecycle maximum (s)',*[f(max(report.times(x['samples'],'lifecycle'))/1000) for x in references]],
        ['Initial issuance (s)',*[f(sec(x,'bootstrap_and_initial_issuance')) for x in references]],
        ['Catch-up to epoch 1 (ms)',*[f(ms(x,'offline_catchup',1)) for x in references]],
        ['Catch-up to epoch 2 (ms)',*[f(ms(x,'offline_catchup',2)) for x in references]]])
    table('threshold','tab:v3-threshold',
        'Fixed-population threshold sweep, $N=160$. Each entry is the median of three baseline lifecycles. Generation, refresh and reconstruction refer to epoch 2; lifecycle includes initialization and all three transitions.',
        ['$n_D$','$t$','Lifecycle (s)','Gen. (ms)','Refresh (s)','Recon. (ms)'],[
        [p['committee'][0],p['thresholds'][0],f(sec(x,'lifecycle')),f(ms(x,'generation',2)),f(sec(x,'refresh',2)),f(ms(x,'reconstruct',2))]
        for x in threshold for p in [x['plan']]])
    table('population','tab:v3-population',
        'Fixed-threshold population sweep, $t=32$. $r$ is the number of baseline lifecycles. Entries with $r=3$ are medians; entries with $r=1$ are individual observations. Setup precedes the lifecycle; refresh refers to epoch 2.',
        ['$n_D$','$N$','$r$','Lifecycle (s)','Refresh (s)','Setup (s)'],[
        [p['committee'][0],p['populations'][0],p['repeats'],f(sec(x,'lifecycle')),f(sec(x,'refresh',2)),f(sec(x,'deployment_and_process_setup'))]
        for x in population for p in [x['plan']]])
    dispute_rows=[];extra_dispute_rows=[];da_rows=[]
    for x in fault:
        p=x['plan'];trial=next(t for t in x['trials'] if not t['baseline'])
        ds={d['kind']:d for d in trial['disputes']};c=ds['consistency'];d=ds['plaintext']
        row=[p['committee'][0],p['thresholds'][0],c['transactions'],
            f(ms(x,'consistency_dispute',1,'integrated_faults')),f(c['execution_gas']/1e6),
            f(ms(x,'plaintext_dispute',2,'integrated_faults')),f(d['execution_gas']/1e6)]
        if p['family'] in ['threshold','high_threshold']:dispute_rows.append(row)
        else:extra_dispute_rows.append([ident(p),*row[2:]])
        receipts=chain_rows(DATA/'runs'/p['name']/trial['name']);sequences=[];current=None
        for r in receipts:
            if r['label']=='actual-publication-DA-obligation':current=[]
            if current is not None:current.append(r)
            if r['label']=='dealer-withdraw':
                assert current is not None and len(current)==5
                sequences.append(sum(z['gas'] for z in current));current=None
        assert len(sequences)==2
        da_rows.append([ident(p),f(ms(x,'DA_service_and_payout',1,'integrated_faults')),f(sequences[0]/1e6),
            f(ms(x,'DA_service_and_payout',2,'integrated_faults')),f(sequences[1]/1e6)])
    table('disputes','tab:v3-dispute-scaling',
        'Actual disputes on recovered records. Each row is one fault lifecycle. All plaintext paths use two transactions. Consistency uses $T=t$ in these constant-threshold cells. The $t=256$ row uses $N=320$; all other rows use $N=160$. Gas is execution Mgas, including admission.',
        ['$n_D$','$t$','Cons. tx','Cons. ms','Cons. gas','Plain. ms','Plain. gas'],dispute_rows)
    gas=[]
    for x in complete:
        trials=[t for t in x['trials'] if t['baseline']]
        total=statistics.median(t['execution_gas'] for t in trials);registry=statistics.median(t['registry_gas'] for t in trials)
        gas.append(dict(profile=x['plan']['name'],total=total,registry=registry,percentage=100*registry/total,
                        blob=statistics.median(t['blob_gas'] for t in trials)))
    gm={x['profile']:x for x in gas}
    table('gas_population','tab:v3-registry',
        'Execution gas for the fixed-$t=32$ population sweep. Totals include deployment and every baseline transaction. Registry is registration plus activation. Percentages are ratios of medians. $N=1024,2048$ are single observations.',
        ['$n_D$','$N$','Total Mgas','Registry Mgas',r'Registry (\%)'],[
            [x['plan']['committee'][0],x['plan']['populations'][0],f(g['total']/1e6),f(g['registry']/1e6),f(g['percentage'],1)]
            for x in population for g in [gm[x['plan']['name']]]])
    capacities=[]
    for n in [4,7]:
        for t in [128,256,512,1024]:
            observed='completed' if t==128 or (n==4 and t==256) else ('failed at publication' if n==7 and t==256 else 'not executed')
            capacities.append([n,t,f(report.payload(n,t,t,1),0),observed])
    table('capacity','tab:v3-capacity',
        'Serialized bundle sizes for equal source/target thresholds and one offline recipient. The capacity is 126,914 bytes. Sizes at $t=128$ and $256$ match retained actual bundles; $t=512$ and $1024$ are calculations only.',
        ['$n_D$','$t$','Payload (bytes)','Execution evidence'],capacities,'@{}rrrl@{}')
    table('plans','tab:v3-plan',
        'Complete experiment matrix. A single threshold or population denotes the same value in all four epochs. B/F are requested baseline/fault runs. S: completed; O: observed blob overflow; C: configuration rejection; U: unexecuted capacity block. Compact IDs map to full profile names in the artifact metrics file.',
        ['ID','$n_D/k_D/f_D$','$t$ schedule','$N$ schedule','B/F','Status'],[
            [ident(p),'/'.join(map(str,p['committee'])),schedule(p['thresholds']),schedule(p['populations']),
             f'{p["repeats"]}/{int(p["fault_scenarios"])}',{'completed':'S','expected_capacity_failure':'O','expected_config_rejection':'C','not_run':'U'}[s['status']]]
            for p,s in zip(plan,statuses)],'@{}llllcc@{}',long=True)
    table('lifecycles','tab:e2e-lifecycle',
        'Every completed profile. B is the number of baseline lifecycles and F counts separately executed fault lifecycles. Lifecycle values are seconds. A single observation has identical minimum, median and maximum and does not estimate variability.',
        ['ID','B/F','Median','Minimum','Maximum','Setup'],[
            [ident(p),f'{p["repeats"]}/{int(p["fault_scenarios"])}',f(statistics.median(v)),f(min(v)),f(max(v)),f(sec(x,'deployment_and_process_setup'))]
            for x in complete for p in [x['plan']] for v in [[z/1000 for z in report.times(x['samples'],'lifecycle')]]],long=True)
    phases=['generation','reservation_and_certificate','direct_delivery_stage','archive_blob_publication','commit_and_apply','refresh','reconstruct']
    headers=['ID','Epoch','Gen.','Reserve','Stage','Publish','Apply','Refresh','Recon.']
    table('reference_phases','tab:e2e-phases',
        'Reference-schedule phase medians in seconds, five baselines per committee. Enrollment, liveness, maintenance and reconstruction are outside the refresh interval. The independently measured enclosing refresh is not a sum of phase medians.',
        headers,[[ident(x['plan']),e,*[f(sec(x,m,e)) for m in phases]] for x in references for e in [1,2,3]])
    table('threshold_phases','tab:v3-threshold-phases',
        'Epoch-2 phase medians in seconds for the threshold cells, three baselines each. Population is 160 except T256-4, which uses 320. Phase medians are not added to derive the refresh interval.',
        ['ID','Gen.','Reserve','Stage','Publish','Apply','Refresh','Recon.'],[
            [ident(x['plan']),*[f(sec(x,m,2)) for m in phases]] for x in threshold+[by['threshold-t256-n4']]])
    table('population_phases','tab:v3-population-phases',
        'Fixed-$t=32$ phase observations in seconds. All phase columns after issuance refer to epoch 2. $N=1024,2048$ have one run; the other cells have three. Initialization includes issuing every participant an initial share.',
        ['$n_D$','$N$','Issuance','Gen.','Stage','Publish','Apply','Recon.'],[
            [x['plan']['committee'][0],x['plan']['populations'][0],f(sec(x,'bootstrap_and_initial_issuance')),
             *[f(sec(x,m,2)) for m in ['generation','direct_delivery_stage','archive_blob_publication','commit_and_apply','reconstruct']]] for x in population])
    table('recovery','tab:e2e-recovery',
        r'Archive catch-up request durations in milliseconds. B1/B2 are baseline medians for recovering epochs 1/2; F1/F2 are individual fault observations. Both recoveries take place after epoch 2. Baseline run counts are in Table~\ref{tab:e2e-lifecycle}. Dashes denote an unexecuted fault profile.',
        ['ID','B1','B2','F1','F2'],[
            [ident(x['plan']),*[f(ms(x,'offline_catchup',e,s)) for s in ['baseline','integrated_faults'] for e in [1,2]]]
            for x in complete],long=True)
    table('faults','tab:e2e-faults',
        'One integrated fault lifecycle per listed profile. Lifecycle is seconds; the four remaining durations are milliseconds. Re-issuance includes recovery authorization and activation. These observations are not repeated fault-performance estimates.',
        ['ID','Lifecycle','Abort','Restart','$k_D-1$ reject','Re-issue'],[
            [ident(x['plan']),f(sec(x,'lifecycle',scenario='integrated_faults')),
             *[f(ms(x,m,e,'integrated_faults')) for m,e in [('published_attempt_abort',1),('crash_restart_before_commit',1),('insufficient_records_rejected',2),('authorized_current_epoch_reissuance',3)]]]
            for x in fault])
    chain=[]
    for x in references:
        p=x['plan']; groups={l:[[] for _ in range(3)] for l in ['reservation-CAS','lifecycle-blob-publication','canonical-epoch-commit']}
        for t in x['trials']:
            if not t['baseline']:continue
            receipts=chain_rows(DATA/'runs'/p['name']/t['name'])
            for label in groups:
                selected=[r['gas'] for r in receipts if r['label']==label];assert len(selected)==3
                for i,v in enumerate(selected):groups[label][i].append(v)
        for e in [1,2,3]:
            chain.append([p['committee'][0],e,int(e<=2),f(report.payload(p['committee'][0],p['thresholds'][e-1],p['thresholds'][e],int(e<=2)),0),
                *[f(statistics.median(groups[l][e-1])/1000) for l in groups]])
    table('chain','tab:e2e-chain',
        'Reference publication payload and median execution kGas for five baselines. Each publication additionally consumes 131,072 blob gas. Payload includes both states, commitment vectors, records and certificates; $o$ is the offline-recipient count.',
        ['$n_D$','Epoch','$o$','Payload (B)','Reserve','Publish','Commit'],chain)
    table('extra_disputes','tab:e2e-disputes',
        r'Reference and positive-margin fault disputes, one observation per profile. Consistency uses $T=32$, and the plaintext case has target $t=64$. Together with Table~\ref{tab:v3-dispute-scaling}, this covers every executed fault profile. Gas is Mgas; plaintext uses two transactions.',
        ['ID','Cons. tx','Cons. ms','Cons. gas','Plain. ms','Plain. gas'],extra_dispute_rows)
    table('da','tab:v3-da',
        'Actual-byte DA response and settlement after the consistency (DA1) and plaintext (DA2) cases. Each interval consists of obligation, request, answer and two withdrawals: five transactions. Values are single observations; gas is execution Mgas.',
        ['ID','DA1 (ms)','DA1 gas','DA2 (ms)','DA2 gas'],da_rows)
    table('all_gas','tab:v3-all-gas',
        'Baseline transaction accounting for every completed profile. Entries are medians except the two single-run population probes. Registry percentages are ratios of the two medians. Every baseline uses 393,216 blob gas in three publications, separately from execution gas.',
        ['ID','Total Mgas','Registry Mgas',r'Registry (\%)'],[
            [ident(x['plan']),f(g['total']/1e6),f(g['registry']/1e6),f(g['percentage'],1)]
            for x in complete for g in [gm[x['plan']['name']]]],long=True)
    table('resources','tab:v3-resources',
        'Profile wall time and one-second process-group resource samples, including setup, all requested trials and audit. RSS is a sum over processes and can count shared pages repeatedly; it is not a physical-memory peak. Dashes indicate no execution.',
        ['ID','Status','Wall (s)','RSS sum (GiB)','Processes'],[
            [ident(p),{'completed':'S','expected_capacity_failure':'O','expected_config_rejection':'C','not_run':'U'}[s['status']],
             f(s.get('wall_seconds'),1),f(s['peak_sampled_rss_sum_bytes']/2**30,2) if 'peak_sampled_rss_sum_bytes' in s else '--',s.get('max_sampled_processes','--')]
            for p,s in zip(plan,statuses)],long=True)
    old_samples=report.rows_json(ROOT/'benchmarks/results/e2e-anvil-final/samples.jsonl')
    table('earlier_reference','tab:v3-reference-provenance',
        'Earlier reference dataset and the new reference rerun, kept as separate executions. Each entry is the median of five baseline lifecycles in seconds. These observations are not pooled or treated as an optimization comparison.',
        ['$n_D$','Earlier dataset','Follow-up reference'],[
            [n,f(statistics.median(s['duration_ns']/1e9 for s in old_samples if s['committee'][0]==n and s['scenario']=='baseline' and s['metric']=='lifecycle')),
             f(sec(by[f'reference-n{n}'],'lifecycle'))] for n in [4,7]])
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    from matplotlib.ticker import ScalarFormatter
    plt.rcParams.update({'font.family':'serif','font.size':8,'pdf.fonttype':42})
    fig,axes=plt.subplots(2,1,figsize=(4.8,5.0),layout='constrained')
    for ax,items,field,title in [(axes[0],threshold,'thresholds','(a) Fixed population N = 160'),(axes[1],population,'populations','(b) Fixed threshold t = 32')]:
        for n,color,marker in [(4,'#176b9b','o'),(7,'#b45217','s')]:
            cells=sorted([x for x in items if x['plan']['committee'][0]==n],key=lambda x:x['plan'][field][0])
            xx=[x['plan'][field][0] for x in cells]
            values=[[v/1000 for v in report.times(x['samples'],'refresh',2)] for x in cells]
            yy=[statistics.median(v) for v in values]
            ax.errorbar(xx,yy,yerr=[[m-min(v) for m,v in zip(yy,values)],[max(v)-m for m,v in zip(yy,values)]],
                label=f'{n} dealers',color=color,marker=marker,markersize=4,capsize=3,linestyle='-' if n==4 else '--')
            for a,b,x in zip(xx,yy,cells):
                if x['plan']['repeats']==1:
                    ax.annotate('one run',(a,b),xytext=(-6,8) if a==1024 else (-6,-16),textcoords='offset points',ha='right',va='bottom' if a==1024 else 'top',fontsize=7)
        ax.set_xscale('log',base=2);ax.set_xticks(sorted({x['plan'][field][0] for x in items}))
        ax.xaxis.set_major_formatter(ScalarFormatter());ax.set_ylabel('Epoch-2 refresh (s)')
        ax.set_xlabel('Participant threshold t' if field=='thresholds' else 'Participant population N')
        ax.set_title(title,loc='left');ax.grid(True,alpha=.2);ax.legend(loc='upper left',frameon=False)
    figure=ROOT/'figures/vess_v3_controlled_scaling.pdf';fig.savefig(figure);plt.close(fig)
    OUT.mkdir(parents=True,exist_ok=True);(OUT/'tables').mkdir(exist_ok=True)
    for key,block in BLOCKS.items():(OUT/'tables'/f'{key}.tex').write_text(block)
    (OUT/'metrics.json').write_text(json.dumps({'dataset':str(DATA.relative_to(ROOT)),'validation':validation,
        'independent_validation_summary':{k:v for k,v in verified.items() if k not in ['trial_checks','evidence_sha256']},
        'profile_ids':{ident(p):p['name'] for p in plan},'baseline_gas':gas,
        'tables':list(BLOCKS),'table_sha256':{k:hashlib.sha256(v.encode()).hexdigest() for k,v in BLOCKS.items()},
        'generator_sha256':sha(Path(__file__))},indent=2)+'\n')
    if args.check:
        manuscript=(ROOT/'local_v3.tex').read_text()
        for key,block in BLOCKS.items():assert manuscript.count(block)==1,('table differs or is missing',key)
        assert len(__import__('re').findall(r'% BEGIN V3 TABLE:',manuscript))==len(BLOCKS)
    print(f'{len(BLOCKS)} verified tables; figure {figure.relative_to(ROOT)}; manuscript check {args.check}')

if __name__=='__main__':main()
