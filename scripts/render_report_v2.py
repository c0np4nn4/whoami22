#!/usr/bin/env python3
"""Review parameter sweeps of the existing Rust/Anvil harness; preserve raw data."""
from pathlib import Path
import argparse, collections, csv, datetime, hashlib, json, math, re, shutil, statistics
from run_experiments_v2 import validate_statuses

ROOT=Path(__file__).resolve().parents[2]
CAPACITY=4094*31

def read_json(path):return json.loads(path.read_text())
def rows_json(path):return [json.loads(x) for x in path.read_text().splitlines()] if path.exists() else []
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def esc(s):
    mapping={'\\':r'\textbackslash{}','&':r'\&','%':r'\%','$':r'\$','#':r'\#','_':r'\_','{':r'\{','}':r'\}','~':r'\textasciitilde{}','^':r'\textasciicircum{}'}
    return ''.join(mapping.get(c,c) for c in str(s))
def payload(n,a,b,o):return 32*(n+2)*(a+b)+432+232*n+o*(8+856*n)
def median(values):return statistics.median(values) if values else None
def fmt(x,d=3):return '--' if x is None else f'{x:,.{d}f}'
def pick(samples,metric,epoch=None,scenario='baseline'):
    return [s for s in samples if s['metric']==metric and s['scenario']==scenario and (epoch is None or s['epoch']==epoch) and s.get('duration_ns') is not None]
def times(samples,metric,epoch=None,scenario='baseline'):
    return [s['duration_ns']/1e6 for s in pick(samples,metric,epoch,scenario)]
def med(samples,metric,epoch=None,scenario='baseline'):return median(times(samples,metric,epoch,scenario))
def table(headers,rows,spec=None,caption=None):
    spec=spec or 'l'+'r'*(len(headers)-1)
    top=(r'\paragraph{'+esc(caption)+'}\n') if caption else ''
    top+='\n\\begin{center}\\small\n\\begin{longtable}{'+spec+'}\n\\toprule\n'
    top+=' & '.join(headers)+r'\\'+'\n\\midrule\\endhead\n'
    top+='\n'.join(' & '.join(map(str,row))+r'\\' for row in rows)
    return top+'\n\\bottomrule\n\\end{longtable}\n\\end{center}\n'

def collect(root):
    plan=read_json(root/'plan.json'); statuses=rows_json(root/'status.jsonl')
    validate_statuses(plan,statuses)
    by_name={r['name']:r for r in statuses};complete=[];partial=[];sample_count=0
    all_receipts=all_gas=all_blob=0;model_matches=0
    for row in plan:
        name=row['name'];run=root/'runs'/name;status=by_name.get(name,{'name':name,'status':'pending'})
        samples=rows_json(run/'samples.jsonl');sample_count+=len(samples)
        trials=[]
        for trial in sorted(run.glob('n*-trial*')) if run.exists() else []:
            receipts=[]
            for f in sorted((trial/'chain').glob('*.json')):
                v=read_json(f)
                if 'receipt' not in v:continue
                r=v['receipt'];assert int(r['status'],16)==1,(name,f)
                receipts.append(dict(index=int(f.stem.split('-')[0]),label=f.stem.split('-',1)[1],gas=int(r['gasUsed'],16),blob_gas=int(r.get('blobGasUsed','0x0'),16)))
            baseline='-baseline-' in trial.name
            reg=sum(r['gas'] for r in receipts if r['label'] in ['register-participant','activate-participant'])
            total=sum(r['gas'] for r in receipts);blob=sum(r['blob_gas'] for r in receipts)
            completion=read_json(trial/'completion.json') if (trial/'completion.json').exists() else None
            disputes=[];start=None
            for r in receipts:
                if r['label']=='actual-record-admission':start=r['index']
                if r['label'] in ['actual-record-bisection-verdict','actual-record-plaintext-complaint']:
                    assert start is not None
                    interval=[x for x in receipts if start<=x['index']<=r['index']]
                    kind='consistency' if r['label'].endswith('verdict') else 'plaintext'
                    tmax=max(row['thresholds'][:2])
                    expected=2*math.ceil(math.log2(tmax))+3 if kind=='consistency' else 2
                    assert len(interval)==expected,(name,kind,len(interval),expected)
                    disputes.append(dict(kind=kind,transactions=len(interval),execution_gas=sum(x['gas'] for x in interval)))
            trials.append(dict(name=trial.name,baseline=baseline,completed=bool(completion and completion['passed']),receipts=len(receipts),execution_gas=total,blob_gas=blob,registry_gas=reg,disputes=disputes))
        for s in samples:
            if s['metric']=='archive_blob_publication':
                e=s['epoch'];o=1 if e<=2 else 0
                predicted=payload(row['committee'][0],row['thresholds'][e-1],row['thresholds'][e],o)
                assert predicted==s['data']['payload_bytes'],(name,e,predicted,s['data'])
                assert s['data']['physical_blob_bytes']==131072
                model_matches+=1
        archived_sizes=sorted({f.stat().st_size for f in run.glob('n*-trial*/nodes/archive-*/*.bundle')}) if run.exists() else []
        item=dict(plan=row,status=status,samples=samples,trials=trials,archived_bundle_sizes=archived_sizes)
        if status['status']=='completed':
            audit=read_json(run/'audit.json')
            assert audit['passed']
            assert len(trials)==row['repeats']+int(row['fault_scenarios'])
            assert all(t['completed'] for t in trials)
            assert len(pick(samples,'lifecycle',scenario='baseline'))==row['repeats']
            assert sum(t['receipts'] for t in trials)==audit['receipt_count']
            assert sum(t['execution_gas'] for t in trials)==audit['execution_gas']
            assert sum(t['blob_gas'] for t in trials)==audit['blob_gas']
            all_receipts+=audit['receipt_count'];all_gas+=audit['execution_gas'];all_blob+=audit['blob_gas']
            complete.append(item)
        else:partial.append(item)
    validation=dict(completed_profiles=len(complete),baseline_lifecycles=sum(x['plan']['repeats'] for x in complete),fault_lifecycles=sum(int(x['plan']['fault_scenarios']) for x in complete),successful_receipts_in_completed_profiles=all_receipts,execution_gas_in_completed_profiles=all_gas,blob_gas_in_completed_profiles=all_blob,payload_predictions_checked=model_matches,raw_sample_rows=sample_count,expected_profiles=len(plan),recorded_statuses=len(statuses))
    assert len(statuses)==len(plan),'Suite is not complete; wait until every planned profile has a status'
    return plan,statuses,complete,partial,validation

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input',type=Path,required=True);parser.add_argument('--out',type=Path,required=True)
    args=parser.parse_args();root=args.input.resolve();out=args.out.resolve()
    plan,statuses,complete,partial,validation=collect(root)
    derived=root/'derived';derived.mkdir(exist_ok=True)
    # Preserve the exact generator used for this review, separately from execution provenance.
    shutil.copy2(Path(__file__),root/'suite_source'/'render_report_v2.py')
    source_hashes=read_json(root/'source_hashes.json')
    unchanged=[]
    for name,h in source_hashes.items():
        if name.startswith('benchmarks/src/') or name.startswith('benchmarks/contracts/'):
            assert digest(ROOT/name)==h,('Runtime source changed during execution',name)
            unchanged.append(name)
    validation['unchanged_runtime_source_files']=len(unchanged)
    validation['report_generator_sha256']=digest(Path(__file__))
    validation['raw_data_sha256']={x['plan']['name']:digest(root/'runs'/x['plan']['name']/'samples.jsonl') for x in complete+partial if (root/'runs'/x['plan']['name']/'samples.jsonl').exists()}
    validation['status_counts']=dict(collections.Counter(s['status'] for s in statuses))
    (derived/'validation.json').write_text(json.dumps(validation,indent=2)+'\n')
    metrics=[]
    for item in complete:
        p=item['plan'];s=item['samples']
        groups=collections.defaultdict(list)
        for r in s:
            if r['duration_ns'] is not None:groups[(r['scenario'],r['metric'],r['epoch'],r['t'],r['N'])].append(r['duration_ns']/1e6)
        for key,values in sorted(groups.items()):
            metrics.append(dict(profile=p['name'],family=p['family'],dealers=p['committee'][0],scenario=key[0],metric=key[1],epoch=key[2],t=key[3],N=key[4],observations=len(values),median_ms=median(values),min_ms=min(values),max_ms=max(values)))
    with (derived/'summary.csv').open('w') as f:
        w=csv.DictWriter(f,fieldnames=['profile','family','dealers','scenario','metric','epoch','t','N','observations','median_ms','min_ms','max_ms']);w.writeheader();w.writerows(metrics)
    threshold=[x for x in complete if x['plan']['family']=='threshold']
    population=[x for x in complete if x['plan']['family'] in ['population','population_probe'] or (x['plan']['family']=='threshold' and x['plan']['thresholds'][0]==32)]
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    plt.rcParams.update({'font.family':'serif','font.size':9,'pdf.fonttype':42})
    fig,axes=plt.subplots(1,2,figsize=(10,3.4))
    for ax,items,which in [(axes[0],threshold,'thresholds'),(axes[1],population,'populations')]:
        for n,color in [(4,'#2563a6'),(7,'#b84a32')]:
            selected=sorted([x for x in items if x['plan']['committee'][0]==n],key=lambda x:x['plan'][which][0])
            if not selected:continue
            xx=[x['plan'][which][0] for x in selected]
            vv=[[v/1000 for v in times(x['samples'],'refresh',2)] for x in selected]
            yy=[median(v) for v in vv]
            ax.errorbar(xx,yy,yerr=[[m-min(v) for m,v in zip(yy,vv)],[max(v)-m for m,v in zip(yy,vv)]],marker='o',capsize=3,color=color,label=f'{n} dealers')
            for x,y,item in zip(xx,yy,selected):
                if item['plan']['repeats']==1:ax.annotate('one run',(x,y),xytext=(3,5),textcoords='offset points',fontsize=7)
        ax.set_xscale('log',base=2);ax.set_ylabel('Epoch-2 refresh (s)');ax.grid(alpha=.25)
        if ax.get_legend_handles_labels()[0]:ax.legend(frameon=False)
        ticks=sorted({x['plan'][which][0] for x in items})
        if ticks:ax.set_xticks(ticks,labels=[str(x) for x in ticks])
    axes[0].set_xlabel('Threshold t (N = 160)');axes[1].set_xlabel('Population N (t = 32)')
    fig.tight_layout();plot=derived/'controlled_scaling.pdf';fig.savefig(plot,metadata={'CreationDate':None,'ModDate':None});plt.close(fig)
    pathrel=root.relative_to(ROOT) if root.is_relative_to(ROOT) else root
    successful=validation['baseline_lifecycles']+validation['fault_lifecycles']
    transitions=sum(x['status']['audit']['trial_evidence'][i]['committed_epochs'] for x in complete for i in range(len(x['status']['audit']['trial_evidence'])))
    recon=sum(x['status']['audit']['secret_reconstructions'] for x in complete)
    tex=r'''\documentclass[10pt,a4paper]{article}
\usepackage[T1]{fontenc}
\usepackage[margin=20mm]{geometry}
\usepackage{booktabs,longtable,array,graphicx,amsmath,hyperref,placeins}
\hypersetup{hidelinks}
\setlength{\emergencystretch}{3em}
\setlength{\tabcolsep}{4pt}
\title{VESS Follow-up Experiments: Executable Scope, Scaling, and Implementation Limits}
\author{Local Rust/Anvil experimental report}
\date{2026-09-22}
\begin{document}\maketitle
'''
    tex+='\\begin{abstract}\nWe tested which follow-up questions can be answered by the existing Rust/Anvil implementation, without changing its Rust or Solidity protocol code. The suite separates threshold and population effects, repeats the growing-participant reference, exercises the existing fault/dispute paths at different thresholds, and probes implementation limits. '
    tex+=f'{successful} complete lifecycles ({validation["baseline_lifecycles"]} baseline and {validation["fault_lifecycles"]} integrated-fault lifecycles) passed the artifact audit, covering {transitions} committed transitions and {recon} original-secret reconstruction checks. '
    tex+='Non-completions and unsupported experiments are retained and reported separately. These are single-host distributed-process measurements with Anvil inclusion.\\end{abstract}\n'
    tex+='\\section{Reviewed findings}\n'
    findings=[]
    for n in [4,7]:
        a=next((x for x in complete if x['plan']['name']==f'threshold-t16-n{n}'),None)
        b=next((x for x in complete if x['plan']['name']==f'threshold-t128-n{n}'),None)
        if a and b:
            ra=med(a['samples'],'refresh',2);rb=med(b['samples'],'refresh',2)
            ga=med(a['samples'],'generation',2);gb=med(b['samples'],'generation',2)
            findings.append(f'With {n} dealers and fixed N=160, increasing t from 16 to 128 changes the epoch-2 refresh median from {ra/1000:.3f} to {rb/1000:.3f} seconds ({rb/ra:.2f}x). Generation changes from {ga:.1f} to {gb:.1f} ms. This describes these cells, not an asymptotic scaling law.')
        pop=[x for x in complete if x['plan']['committee'][0]==n and len(set(x['plan']['populations']))==1 and x['plan']['thresholds']==[32]*4]
        if pop:
            largest=max(pop,key=lambda x:x['plan']['populations'][0]);p=largest['plan']
            qualifier='This is one feasibility observation, not a repeated performance estimate.' if p['repeats']==1 else f'These medians use {p["repeats"]} independent lifecycles.'
            findings.append(f'The largest tested and completed fixed-t=32 population for {n} dealers is N={p["populations"][0]}, with {p["repeats"]} baseline lifecycle(s), a lifecycle median of {med(largest["samples"],"lifecycle")/1000:.3f} s and an epoch-2 refresh median of {med(largest["samples"],"refresh",2)/1000:.3f} s. '+qualifier)
    high=next((x for x in complete if x['plan']['name']=='threshold-t256-n4'),None)
    if high:findings.append(f'The separate four-dealer t=256,N=320 cell completes {high["plan"]["repeats"]} baseline and one fault lifecycle; its baseline lifecycle median is {med(high["samples"],"lifecycle")/1000:.3f} s. This uses a different population from the primary threshold sweep.')
    cap=next((x for x in partial if x['plan']['name']=='capacity-t256-n7'),None)
    if cap and cap['status']['status']=='expected_capacity_failure':findings.append('The seven-dealer t=256,N=320 attempt actually fails at the one-blob serialization boundary after generating/staging the candidate and writing the archive bundle. The 155,512-byte bundle exceeds the 126,914-byte limit. At the tested four/seven-dealer configurations, a t=1024 transition exceeds this publication path\'s capacity and needs implementation changes.')
    controlled_disputes=[d for x in threshold for t in x['trials'] for d in t['disputes']]
    if controlled_disputes:
        ct=sorted({d['transactions'] for d in controlled_disputes if d['kind']=='consistency'})
        pg=[d['execution_gas'] for d in controlled_disputes if d['kind']=='plaintext']
        findings.append(f'Across the controlled threshold cells, consistency disputes use transaction counts {ct}; each plaintext path uses two transactions. Observed plaintext execution gas ranges from {min(pg)/1e6:.3f} to {max(pg)/1e6:.3f} million. These are actual transaction sequences, with one fault execution per cell.')
    findings.append('The suite cannot answer concurrent return, matched snapshot recovery, disjoint-recipient abort accumulation or WAN/Byzantine omission behavior by changing configuration alone. These remain explicitly unexecuted questions.')
    tex+='\\begin{itemize}\n'+''.join('\\item '+esc(v)+'\n' for v in findings)+'\\end{itemize}\n'
    tex+='\\section{Questions supported by the current code}\n'
    capability=[
        ('Threshold and population scaling','Supported by Config','Controlled sweeps and bounded large-population probes.'),
        ('Snapshot versus difference baseline','Requires implementation','A record mode exists, but archived publication/recovery is wired to difference records; no matched snapshot lifecycle.'),
        ('Concurrent offline return','Requires harness changes','Participant 1 alone misses epochs 1 and 2. The return loop is serial.'),
        ('Repeated aborts with disjoint recipients','Requires harness changes','The fault profile performs one abort and retries the same recipient set.'),
        ('Cost attribution','Partly supported','Existing phase timers and receipts separate coarse costs; no isolated TLS, KZG or CPU profiler.'),
        ('Multi-host, WAN and omission schedules','Requires implementation','Loopback addresses and responsive all-dealer orchestration are fixed.'),
        ('Production assumptions','Review only','Trusted registration/publication, owner correctness oracle, erasure and finality remain outside this experiment.'),
        ('Dispute-size and margin configurations','Supported in part','Existing fault paths at changed thresholds; n=5,k=2,f=1 gives margin 1, with the same built-in faults.')]
    tex+=table(['Question','Current support','What was done / boundary'],[[esc(a),esc(b),esc(c)] for a,b,c in capability],r'p{.25\linewidth}p{.20\linewidth}p{.44\linewidth}')
    tex+=r'''The configurable fields are committee parameters, threshold/population schedules, baseline repeat count, the built-in fault profile and RPC timeout. The runner requires at least four schedule entries and at most seven dealers. Constant populations are legal and retain one process per participant; they isolate the population present at each transition, whereas separate growth profiles test enrollment during the lifecycle. A positive-margin committee does not itself inject simultaneous bad-and-missing records. The relevant code is \path{benchmarks/src/e2e/runner.rs} (Config checks, fixed offline participant, single abort and publication), \path{benchmarks/src/e2e/node.rs} (difference-token recovery), \path{benchmarks/src/e2e/wire.rs} (loopback transport), and \path{benchmarks/src/chain.rs} (blob payload capacity). Existing microbenchmarks using another cryptographic backend are not a matched end-to-end baseline.

\section{Design, boundaries and execution provenance}
'''
    tex+=f'Authoritative suite: \\path{{{pathrel}}}. Execute \\texttt{{./run\\_experiments\\_v2.sh <fresh-output-directory>}}. The shell script builds the locked executable offline, compiles the contracts, runs profiles sequentially, records failure statuses and resource samples, derives this report, and builds the PDF. The runtime source is unchanged across all profiles ({len(unchanged)} Rust/Solidity files hash-checked).\n'
    host=read_json(root/'host.json');cpu=host['cpu']
    cpu_model=next((line.split(':',1)[1].strip() for line in cpu.splitlines() if line.startswith('model name')), 'unknown')
    logical=sum(line.startswith('processor\t') for line in cpu.splitlines())
    memory=re.search(r'MemTotal:\s+(\d+)',host['memory'])
    mem_gib=int(memory.group(1))/2**20 if memory else 0
    tex+=f'\\par Host: {esc(cpu_model)}, {logical} visible logical processors, {mem_gib:.2f} GiB physical memory. Operating-system identity and the pre-run memory snapshot are retained in \\texttt{{host.json}}.\n'
    if complete:
        versions=read_json(root/'runs'/complete[0]['plan']['name']/'tool_versions.json')
        tex+='\\par Recorded toolchain: '+esc(versions.get('rustc','unknown').splitlines()[0])+'; '+esc(versions.get('anvil','unknown').splitlines()[0])+'. Solidity compiler/optimizer settings and lockfiles are retained in each source snapshot.\n'
    tex+=r'''Each independent lifecycle starts a fresh Anvil, contract and role state. The reference uses five baselines per committee; controlled cells use three baselines and, where enabled, one additional integrated fault lifecycle. Population probes at 1024 and 2048 request one baseline each. Fault observations are not repetitions of fault-case latency. Profiles and committees are run in a fixed order; CPU affinity/frequency and OS caches are not pinned. No randomized-order or inferential-statistics claim is made.

Lifecycle latency runs from owner initialization through final reconstruction, including initial issuance, any population growth, three transitions, key rotation, planned downtime/return and configured faults. Initial chain, contract, PKI and non-participant process setup are outside this interval. The suite's profile wall time also includes setup, repeated lifecycles and post-run audit. Refresh includes generation through commit/application, excluding growth, preceding liveness and subsequent offline recovery. The primary controlled refresh comparison uses epoch 2: constant source/target threshold, identical participant count and one offline participant, after the first publication. These observations do not remove all state/history effects or measure a pure cryptographic operation.

The controller continues to collect all dealer responses/signatures and processes control RPCs in batches of 16. All roles use localhost mTLS with fresh connections; the owner retains a secret-pair oracle. Every catch-up still concerns one participant, with all dealers and one archive stopped. Median/minimum/maximum are computed from independent lifecycle observations; phase medians are never added into an E2E total. A profile has a 1200-second wall-clock guard and a 16-GiB sampled aggregate-RSS guard. RSS sums may double-count shared pages and are not physical-memory peaks. Guard stops are reported as incomplete experiments, not protocol failures.
'''
    design=[]
    for p in plan:
        design.append([esc(p['name']),'/'.join(map(str,p['committee'])),esc(','.join(map(str,p['thresholds']))),esc(','.join(map(str,p['populations']))),str(p['repeats']), 'yes' if p['fault_scenarios'] else 'no'])
    tex+=table(['Profile','n/k/f','Threshold schedule','Population schedule','Base.','Fault'],design,r'lcllrc')
    tex+='\\section{Completion and retained non-completions}\n'
    states=[]
    for p,s in zip(plan,statuses):
        assert p['name']==s['name']
        states.append([esc(p['name']),esc(s['status']),fmt(s.get('wall_seconds'),1),fmt(s.get('peak_sampled_rss_sum_bytes',0)/2**30,2)])
    tex+=table(['Profile','Observed status','Wall (s)','RSS sum (GiB)'],states,r'llrr')
    for item in partial:
        p=item['plan'];s=item['status'];error=s.get('error') or {};reason=error.get('error') or s.get('stop_reason') or s.get('reason') or '\n'.join(s.get('log_tail',[]))
        final_events=[f'{r["metric"]}@epoch{r["epoch"]}' for r in item['samples'][-4:]]
        tex+='\\paragraph{'+esc(p['name'])+'} '+esc(reason)+'\n'
        if final_events:tex+='Last recorded sample events: '+esc(', '.join(final_events))+'.\n'
        if item['archived_bundle_sizes']:tex+='Retained archive bundle byte lengths: '+esc(', '.join(map(str,item['archived_bundle_sizes'])))+'. These archive writes do not imply successful chain publication.\n'
        if item['trials']:tex+=f'Retained partial trials: {len(item["trials"])}; complete trial markers: {sum(t["completed"] for t in item["trials"])}. These are excluded from complete-profile performance tables.\n'
    tex+='\\section{Reference and controlled scaling results}\n'
    rows=[]
    for item in complete:
        p=item['plan'];v=times(item['samples'],'lifecycle')
        rows.append([esc(p['name']),str(len(v)),fmt(median(v)/1000),fmt(min(v)/1000),fmt(max(v)/1000),fmt(med(item['samples'],'deployment_and_process_setup')/1000)])
    tex+=table(['Profile','Runs','Lifecycle median (s)','Min (s)','Max (s)','Setup median (s)'],rows,r'lrrrrr')
    tex+='\\subsection{Threshold sweep at fixed population}\n'
    tex+=r'''The primary threshold sweep keeps $N=160$ and all four thresholds equal within each lifecycle. It therefore controls population, growth, offline count and the source/target threshold relationship. Increasing $t$ also changes initialization and reconstruction work; full-lifecycle time is not generation-only time. The separate $t=256$ run uses $N=320$ and is not an additional point on the fixed-$N=160$ curve.
'''
    rows=[]
    for item in threshold:
        p=item['plan'];s=item['samples']
        rows.append([str(p['committee'][0]),str(p['thresholds'][0]),fmt(med(s,'generation',2)),fmt(med(s,'direct_delivery_stage',2)),fmt(med(s,'archive_blob_publication',2)),fmt(med(s,'commit_and_apply',2)),fmt(med(s,'refresh',2)),fmt(med(s,'reconstruct',2))])
    tex+=table(['Dealers','t','Generation','Stage','Publication','Commit/apply','Refresh','Reconstruct'],rows,'rrrrrrrr')
    tex+='All phase values in this and the following controlled tables are milliseconds; entries are medians of three lifecycles unless explicitly marked as probes.\n'
    tex+='\\subsection{Population sweep at fixed threshold}\n'
    tex+=r'''This sweep keeps $t=32$ and a constant population within each lifecycle. All $N$ participants are issued initial shares; one is offline for two transitions, and the rest receive direct updates. An increase in population changes whole-cohort work rather than the complexity of verifying a single share. The $N=160$ cell is shared with the threshold sweep and is counted only once in suite totals. Initial PKI provisioning copies every peer certificate into every role directory and replicates the peer list, so its file count grows quadratically with configured population. That provisioning is outside lifecycle time but included in setup/profile wall time; it is an implementation cost, not a cryptographic protocol lower bound.
'''
    rows=[]
    for item in sorted(population,key=lambda x:(x['plan']['committee'][0],x['plan']['populations'][0])):
        p=item['plan'];s=item['samples']
        rows.append([str(p['committee'][0]),str(p['populations'][0]),str(p['repeats']),fmt(med(s,'bootstrap_and_initial_issuance')),fmt(med(s,'generation',2)),fmt(med(s,'direct_delivery_stage',2)),fmt(med(s,'commit_and_apply',2)),fmt(med(s,'refresh',2))])
    tex+=table(['Dealers','N','Runs','Initial issuance','Generation','Stage','Commit/apply','Refresh'],rows,'rrrrrrrr')
    tex+='\\begin{figure}[htbp]\\centering\n\\includegraphics[width=\\linewidth]{'+plot.as_posix()+'}\n\\caption{Controlled epoch-2 refresh observations. Points are medians; bars are observed min/max, not confidence intervals. Single-run probes are annotated. Incomplete profiles do not appear.}\\end{figure}\n\\FloatBarrier\n'
    tex+='\\subsection{Growth, recovery and existing fault paths}\n'
    tex+=r'''The growth profiles hold $t=32$ while the population increases $64\to128\to256\to512$. These distinguish operational enrollment from the constant-population cells. They preserve source-epoch issuance and the subsequent continuous state transitions. The margin profile changes the committee to $(5,2,1)$, with $m=n_D-2f_D-k_D=1$, but retains the existing single-fault/availability schedule.
'''
    rows=[]
    for item in complete:
        p=item['plan'];s=item['samples']
        if p['family'] in ['reference','threshold','high_threshold','growth','margin']:
            rows.append([esc(p['name']),fmt(med(s,'offline_catchup',1)),fmt(med(s,'offline_catchup',2)),fmt(med(s,'published_attempt_abort',1,'integrated_faults')),fmt(med(s,'authorized_current_epoch_reissuance',3,'integrated_faults'))])
    tex+=table(['Profile','Catch-up e1','Catch-up e2','Abort interval','Re-issuance'],rows,'lrrrr')
    tex+=r'''Catch-up entries are per-update baseline medians. Both recoveries occur after epoch 2; their median values are not added into a two-update median. Abort and re-issuance are single integrated-fault observations in milliseconds. Re-issuance includes recovery authorization and activation transactions and requires live dealers, whereas archive catch-up has a different timer and uses another participant/epoch context. This table is not a matched comparison of alternative recovery designs.
'''
    tex+='\\section{Dispute scaling and execution-gas accounting}\n'
    rows=[]
    for item in complete:
        p=item['plan'];s=item['samples']
        if p['family'] not in ['threshold','high_threshold'] or not p['fault_scenarios']:continue
        for t in item['trials']:
            for d in t['disputes']:
                metric='consistency_dispute' if d['kind']=='consistency' else 'plaintext_dispute';epoch=1 if d['kind']=='consistency' else 2
                rows.append([str(p['committee'][0]),str(p['thresholds'][0]),d['kind'],str(d['transactions']),fmt(d['execution_gas']/1e6),fmt(med(s,metric,epoch,'integrated_faults'))])
    tex+=table(['Dealers','t','Path','Tx','Execution Mgas','Latency (ms)'],rows,'rrlrrr')
    tex+=r'''These are actual recovered records and actual EVM receipts, including record admission. Consistency paths include game initialization, both parties' midpoint moves and final adjudication. Plaintext paths include admission and the complaint. The power-of-two consistency cases can be compared with the specified $2\log_2(t)+3$ transaction count for this implementation; each size still has only one fault execution per committee. Complete transaction gas includes authentication, storage and proof inputs, so a threshold-independent plaintext verification equation need not imply identical transaction gas. DA response/settlement executes the built-in five-transaction path. No new timeout or non-response branch is injected.
'''
    rows=[];gas_stats=[]
    for item in complete:
        p=item['plan'];tr=[t for t in item['trials'] if t['baseline']];g=median([t['execution_gas'] for t in tr]);reg=median([t['registry_gas'] for t in tr]);b=median([t['blob_gas'] for t in tr])
        gas_stats.append(dict(profile=p['name'],median_total_execution_gas=g,median_registry_execution_gas=reg,ratio_of_medians=reg/g,median_blob_gas=b))
        rows.append([esc(p['name']),fmt(g/1e6),fmt(reg/1e6),fmt(reg/g*100,1),fmt(b,0)])
    tex+=table(['Profile','Total Mgas','Registry Mgas','Ratio (percent)','Blob gas'],rows,'lrrrr')
    tex+=r'''Totals above include deployment and all transactions in a baseline lifecycle. Registry gas counts participant registration and activation, two transactions per enrolled participant. The percentage is the ratio of those medians, not a median per-trial percentage. Blob gas is kept separate from execution gas. Transactions and phases within one lifecycle are correlated; receipt count is not an independent performance sample count.
'''
    (derived/'gas.json').write_text(json.dumps(gas_stats,indent=2)+'\n')
    tex+='\\section{Single-blob publication boundary}\n'
    tex+=r'''The existing E2E runner passes the complete serialized bundle to \texttt{blob\_bundle} and submits one blob. That function reserves two field slots for the 256-bit record root and rejects payloads above $4094\times31=126{,}914$ bytes. Although the shared chain library has a multi-blob transaction helper, the E2E publication, archive binding and admission path do not use a chunked multi-blob bundle.

For this exact bincode layout, full-committee publication, and $o$ offline recipients, the payload is
\[
 B=32(n_D+2)(t_{\rm src}+t_{\rm dst})+432+232n_D+o(8+856n_D).
\]
This counts serialized public/source/target vectors, keys, records and certificates. It is an implementation-specific byte count, not a general VESS lower bound. Its predictions were checked against every retained successful publication in this suite.
'''
    capacity=[]
    for n in [4,7]:
        for t in [128,256,512,1024]:
            size=payload(n,t,t,1);capacity.append([str(n),str(t),f'{size:,}', 'fits' if size<=CAPACITY else 'exceeds one blob'])
    tex+=table(['Dealers','Constant t','Predicted payload (B)','Current serializer'],capacity,'rrrl')
    tex+=r'''For constant source/target thresholds and one offline participant, the byte-count limits are $t\le318$ with four dealers and $t\le206$ with seven dealers. These are capacity calculations, not claims of measured success at the limiting thresholds. The actual $(n_D,t,N)=(7,256,320)$ profile probes a predicted overflow; its observed outcome and reached stage are reported above. The $t=1024$ profile is explicitly not run because its full bundle exceeds this code path's capacity. Population 2048 at $t=32$, if completed, answers a different question from threshold 1024 and must not be described as a $t=1024$ experiment.
'''
    tex+='\\section{What the measurements answer and what remains}\n'
    tex+=r'''The tables establish the completed parameter cells and identify incomplete ones. They support host-specific comparisons of whole-cohort work, continuous execution, the current serialization boundary, registration cost and the existing fault/dispute paths. Controlled threshold and population sweeps improve on the original schedule in which both changed together. They do not establish production tail latency, WAN behavior, Byzantine broadcast liveness, physical secure erasure or long-term data availability.

The first-publication timer can be compared with the second at identical $(t,N)$ in the controlled profiles, but it still combines archive transfer, KZG work, transaction submission and inclusion. Key rotation, epoch/certificate state and initialization history differ. No single-component attribution follows without finer instrumentation. Concurrent return, disjoint-recipient abort accumulation, matched snapshot recovery, arbitrary missing/bad-record combinations and distributed deployment need harness/protocol integration changes. Raising only the threshold parameter cannot bypass the one-blob E2E limit.

The reference rerun and the older paper dataset are separate executions. Differences between them can reflect host load and initialization; they are not optimizations or regressions because no runtime code was changed. This report leaves \texttt{local\_v1.tex}, \texttt{local\_v2.tex}, \texttt{e2e\_result.tex} and the earlier authoritative data unchanged.
'''
    tex+='\\section{Evidence review and reproduction}\n'
    tex+=f'The audit of completed profiles checks {validation["successful_receipts_in_completed_profiles"]:,} successful receipts, {validation["execution_gas_in_completed_profiles"]:,} execution gas and {validation["blob_gas_in_completed_profiles"]:,} blob gas across {successful} complete lifecycles. The generator independently re-counts receipts and compares the totals with the Rust audit; it also validates {validation["payload_predictions_checked"]} observed payload sizes against the serialization formula. Failure-profile receipts are retained but excluded from these complete-lifecycle totals.\n'
    tex+=r'''The suite retains its plan and per-profile TOML, raw samples, node events, public bundles, inputs/receipts, original Rust source snapshots, errors, per-profile logs and sampled process-group RSS. \texttt{status.jsonl} distinguishes completion, failure, timeout/resource stop, expected rejection and non-execution. \texttt{derived/summary.csv}, \texttt{gas.json} and \texttt{validation.json} contain the report's numerical derivation and hashes. Existing per-profile generic report text is not the interpretation of these sweeps; this report uses the explicit plan and actual statuses.

\begin{verbatim}
./run_experiments_v2.sh benchmarks/results/report-v2-reproduction
# Derive this report again without rerunning experiments:
python3 benchmarks/scripts/render_report_v2.py \
  --input '''+str(pathrel)+r''' \
  --out report_v2.tex
\end{verbatim}
The output directory for a new run must be fresh. An interrupted suite can resume with the same output and \texttt{--resume}; existing recorded profile statuses are preserved rather than rerun or overwritten. If a profile was interrupted before its status was written, its partial output is moved to \texttt{interrupted\_attempts/} before that profile is retried. The experiment uses synthetic keys and secrets. Public sharing of the complete node stores would require separately selecting and preparing the artifact contents.
\end{document}
'''
    tex=tex.replace('a 1200-second wall-clock guard and a 16-GiB sampled aggregate-RSS guard', f'a {host["profile_timeout_seconds"]}-second wall-clock guard and a {host["rss_limit_gib"]:g}-GiB sampled aggregate-RSS guard')
    out.write_text(tex)
    if out != root/'report_v2.tex':
        shutil.copy2(out,root/'report_v2.tex')
    print(json.dumps({k:v for k,v in validation.items() if k!='raw_data_sha256'},indent=2))

if __name__=='__main__':main()
