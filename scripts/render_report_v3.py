#!/usr/bin/env python3
"""Build explanatory English/Korean reports from the existing verified suite.

Reads original measurements only. Prose lives in paper_artifacts/report_v3/.
Both languages use the same numerical rows and retain full table contents in
the final TeX files. No experiment or earlier report is modified.
"""
from pathlib import Path
import collections
import hashlib
import json
import re
import statistics

import render_report_v2 as source

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / 'benchmarks/results/report-v2-20260922'
OUT = ROOT / 'paper_artifacts/report_v3'
TABLES = {'en': {}, 'ko': {}}
NUMBERS = {}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def choose(en, ko, lang):
    return en if lang == 'en' else ko


def fmt(value, digits=3):
    return '--' if value is None else f'{value:,.{digits}f}'


def ms(item, metric, epoch=None, scenario='baseline'):
    return source.med(item['samples'], metric, epoch, scenario)


def seconds(item, metric, epoch=None, scenario='baseline'):
    value = ms(item, metric, epoch, scenario)
    return None if value is None else value / 1000


def schedule(values):
    return str(values[0]) if len(set(values)) == 1 else '$' + r'\to'.join(map(str, values)) + '$'


def setting(item, lang):
    p = item['plan']
    n, t, population = p['committee'][0], schedule(p['thresholds']), schedule(p['populations'])
    # Every table can be read without looking up a profile identifier.
    return choose(f'{n} dealers; $t={t}$; $N={population}$',
                  f'dealer {n}명; $t={t}$; $N={population}$', lang).replace('$$', '$') if '$' not in t + population else (
        choose(f'{n} dealers; ', f'dealer {n}명; ', lang)
        + '$t$: ' + t + r'\newline ' + '$N$: ' + population)


def table(key, caption_en, caption_ko, headers_en, headers_ko, rows,
          spec=None, long=False, localized_rows=None, group=None):
    for lang in ['en', 'ko']:
        caption = choose(caption_en, caption_ko, lang)
        headers = choose(headers_en, headers_ko, lang)
        actual_rows = localized_rows[lang] if localized_rows else rows
        columns = spec or '@{}' + 'r' * len(headers) + '@{}'
        head = (' & '.join(headers) + r'\\\midrule' + '\n')
        if group:
            head = choose(group[0], group[1], lang) + '\n' + head
        if long:
            tex = r'\begingroup\small\setlength{\tabcolsep}{4pt}' + '\n'
            tex += r'\begin{longtable}{' + columns + '}\n'
            tex += r'\caption{' + caption + r'}\label{tab:' + key + r'}\\' + '\n'
            tex += r'\toprule' + '\n' + head + r'\endfirsthead' + '\n'
            tex += r'\multicolumn{' + str(len(headers)) + r'}{c}{' + choose('Continued', '계속', lang) + r'}\\\toprule' + '\n'
            tex += head + r'\endhead\bottomrule\endfoot' + '\n'
        else:
            tex = r'\begin{table}[!htbp]\centering' + '\n'
            tex += r'\caption{' + caption + r'}\label{tab:' + key + '}\n'
            tex += r'\small\setlength{\tabcolsep}{5pt}' + '\n'
            tex += r'\begin{tabular}{' + columns + r'}\toprule' + '\n' + head
        tex += '\n'.join(' & '.join(map(str, row)) + r'\\' for row in actual_rows) + '\n'
        tex += (r'\end{longtable}\endgroup' if long else r'\bottomrule\end{tabular}\end{table}') + '\n'
        TABLES[lang][key] = f'% BEGIN REPORT V3 TABLE: {key}\n\n{tex}\n% END REPORT V3 TABLE: {key}\n'
        # Translations must not change a numerical entry in a generated table.
        NUMBERS.setdefault(key, {})[lang] = [re.findall(r'\d+(?:[,.]\d+)*', ' '.join(map(str, row))) for row in actual_rows]



def plot_scaling(threshold, population):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    from matplotlib import font_manager
    import subprocess
    korean_font = subprocess.check_output(['fc-match', '-f', '%{file}', 'NanumGothic'], text=True).strip()
    font_manager.fontManager.addfont(korean_font)
    korean_family = font_manager.FontProperties(fname=korean_font).get_name()
    for lang in ['en', 'ko']:
        plt.rcParams.update({'font.family': 'DejaVu Sans' if lang == 'en' else korean_family,
                             'font.size': 10, 'pdf.fonttype': 42, 'axes.unicode_minus': False})
        fig, axes = plt.subplots(2, 1, figsize=(6.6, 5.8))
        for ax, items, field in [(axes[0], threshold, 'thresholds'), (axes[1], population, 'populations')]:
            for n, color, marker in [(4, '#196B99', 'o'), (7, '#B45924', 's')]:
                selected = sorted([x for x in items if x['plan']['committee'][0] == n], key=lambda x: x['plan'][field][0])
                xx = [x['plan'][field][0] for x in selected]
                values = [[v/1000 for v in source.times(x['samples'], 'refresh', 2)] for x in selected]
                medians = [statistics.median(v) for v in values]
                ax.errorbar(xx, medians, yerr=[[m-min(v) for m,v in zip(medians,values)], [max(v)-m for m,v in zip(medians,values)]],
                            color=color, marker=marker, markersize=5, capsize=3,
                            label=choose(f'{n} dealers', f'dealer {n}명', lang))
                for xp, yp, item in zip(xx, medians, selected):
                    if item['plan']['repeats'] == 1:
                        ax.plot(xp, yp, marker, markerfacecolor='white', markeredgecolor=color, markersize=6, zorder=5)
                        ax.annotate(choose('one run', '1회 실행', lang), (xp, yp), xytext=(-5,-17 if xp==2048 else 8),
                                    textcoords='offset points', ha='right', fontsize=9)
            ax.set_ylim(bottom=0)
            ax.grid(axis='y', alpha=.25)
            ax.set_ylabel(choose('One refresh (seconds)', '한 번의 갱신 (초)', lang))
            ax.legend(frameon=False, loc='upper left')
            for side in ['top', 'right']:ax.spines[side].set_visible(False)
        axes[0].set_title(choose('Change the threshold; keep 160 participants', '참여자 160명을 유지하고 복원 임계값 변경', lang), loc='left', fontsize=11)
        axes[0].set_xlabel(choose('Shares needed to reconstruct the secret (threshold)', 'Secret 복원에 필요한 share 수 (임계값)', lang))
        axes[0].set_xticks([16,32,64,128])
        axes[1].set_title(choose('Change participant count; keep threshold 32', '복원 임계값 32를 유지하고 참여자 수 변경', lang), loc='left', fontsize=11)
        axes[1].set_xlabel(choose('Number of participants', '참여자 수', lang))
        axes[1].set_xticks([160,320,640,1024,2048])
        fig.tight_layout(pad=1.1, h_pad=2)
        fig.savefig(ROOT/'figures'/f'report_v3_scaling_{lang}.pdf', metadata={'CreationDate':None,'ModDate':None})
        plt.close(fig)


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    plan, statuses, completed, incomplete, totals = source.collect(DATA)
    verified = json.loads((DATA / 'recheck/independent_validation.json').read_text())
    assert verified['passed'] and verified['trials'] == 72
    for name, expected in verified['evidence_sha256'].items():
        assert digest(DATA / name) == expected, name
    old_validation = json.loads((DATA / 'derived/validation.json').read_text())
    for name, expected in old_validation['raw_data_sha256'].items():
        assert digest(DATA / 'runs' / name / 'samples.jsonl') == expected, name
    by = {x['plan']['name']: x for x in completed}
    refs = [by[f'reference-n{n}'] for n in [4, 7]]
    threshold = [x for x in completed if x['plan']['family'] == 'threshold']
    population = sorted([x for x in completed if x['plan']['family'] in ['population', 'population_probe'] or
                         (x['plan']['family'] == 'threshold' and x['plan']['thresholds'][0] == 32)],
                        key=lambda x: (x['plan']['committee'][0], x['plan']['populations'][0]))
    faults = [x for x in completed if x['plan']['fault_scenarios']]
    plot_scaling(threshold, population)

    table('reference', 'Growing-participant reference experiment. Each row summarizes five baseline lifecycles; ranges are observed minima and maxima.',
          '참여자가 증가하는 기준 실험. 각 행은 정상 lifecycle 5회의 중앙값과 관측된 최솟값·최댓값이다.',
          ['Dealers', 'Baseline runs', 'Whole lifecycle (s)', 'Observed range (s)'],
          ['Dealer 수', '정상 실행 횟수', '전체 lifecycle (초)', '관측 범위 (초)'],
          [[x['plan']['committee'][0], 5, fmt(seconds(x, 'lifecycle')),
            fmt(min(source.times(x['samples'], 'lifecycle')) / 1000) + '--' + fmt(max(source.times(x['samples'], 'lifecycle')) / 1000)] for x in refs])
    table('threshold', 'Increasing the reconstruction threshold while keeping 160 participants. Three baseline runs per row; entries are medians. Refresh is the second transition.',
          '참여자 160명을 유지하고 복원 임계값만 증가시킨 실험. 각 행은 정상 실행 3회의 중앙값이며, 갱신 시간은 두 번째 전환에서 측정했다.',
          ['Dealers', r'Threshold $t$', 'One refresh (s)', 'Whole lifecycle (s)'],
          ['Dealer 수', r'복원 임계값 $t$', '한 번의 갱신 (초)', '전체 lifecycle (초)'],
          [[x['plan']['committee'][0], x['plan']['thresholds'][0], fmt(seconds(x, 'refresh', 2)), fmt(seconds(x, 'lifecycle'))] for x in threshold])
    table('population', 'Increasing the number of participants with reconstruction threshold 32. Three-run entries are medians; one-run entries are individual observations.',
          '복원 임계값을 32로 유지하고 참여자 수를 증가시킨 실험. 3회 실행한 행은 중앙값, 1회 실행한 행은 개별 관측값이다.',
          ['Dealers', 'Participants', 'Runs', 'One refresh (s)', 'Whole lifecycle (s)'],
          ['Dealer 수', '참여자 수', '실행 횟수', '한 번의 갱신 (초)', '전체 lifecycle (초)'],
          [[x['plan']['committee'][0], x['plan']['populations'][0], x['plan']['repeats'], fmt(seconds(x, 'refresh', 2)), fmt(seconds(x, 'lifecycle'))] for x in population])
    growth = [by[f'growth-p512-n{n}'] for n in [4, 7]]
    table('growth', r'Enrollment during the lifecycle: $64\to128\to256\to512$ participants, with threshold 32 throughout. Three baseline runs per committee.',
          r'실행 도중 참여자를 $64\to128\to256\to512$명으로 늘린 실험. 복원 임계값은 32로 유지했고, 위원회별 정상 실행은 3회다.',
          ['Dealers', 'Whole lifecycle median (s)', 'Observed range (s)'],
          ['Dealer 수', '전체 lifecycle 중앙값 (초)', '관측 범위 (초)'],
          [[x['plan']['committee'][0], fmt(seconds(x, 'lifecycle')), fmt(min(source.times(x['samples'], 'lifecycle'))/1000)+'--'+fmt(max(source.times(x['samples'], 'lifecycle'))/1000)] for x in growth])
    table('return', 'One returning participant in the reference experiment, with all dealers stopped. Each entry is the median of five recovery requests for that update, in milliseconds.',
          '기준 실험에서 dealer를 모두 중단한 상태로 참여자 한 명이 복귀한 결과. 각 값은 해당 갱신에 대한 복구 요청 5회의 중앙값이며, 단위는 밀리초다.',
          ['Dealers', 'First missed update (ms)', 'Second missed update (ms)'],
          ['Dealer 수', '첫 번째 누락 갱신 (ms)', '두 번째 누락 갱신 (ms)'],
          [[x['plan']['committee'][0], fmt(ms(x, 'offline_catchup', 1)), fmt(ms(x, 'offline_catchup', 2))] for x in refs])

    dispute_rows = []
    for x in threshold + [by['threshold-t256-n4']]:
        trial = next(t for t in x['trials'] if not t['baseline'])
        d = {v['kind']: v for v in trial['disputes']}
        dispute_rows.append([x['plan']['committee'][0], x['plan']['thresholds'][0], d['consistency']['transactions'],
                             fmt(ms(x, 'consistency_dispute', 1, 'integrated_faults')),
                             fmt(d['consistency']['execution_gas']/1e6),
                             fmt(ms(x, 'plaintext_dispute', 2, 'integrated_faults')),
                             fmt(d['plaintext']['execution_gas']/1e6)])
    table('disputes', 'Two different faults, measured on actual recovered records. Each row is one fault lifecycle. The polynomial dispute uses the shown transaction count; every decrypted-value complaint uses two transactions. Times are milliseconds and gas is in millions of execution-gas units. Population is 160 except at threshold 256, where it is 320.',
          '실제 복구 record에서 발생한 두 종류의 오류를 처리한 비용. 각 행은 장애 lifecycle 1회의 관측이다. 다항식 불일치 분쟁의 거래 수는 표에 표시했으며, 복호문 불일치 이의제기는 모두 거래 2건을 사용한다. 시간은 ms, 가스는 백만 execution gas 단위다. 참여자는 160명이며 임계값 256인 행만 320명이다.',
          ['Dealers', '$t$', r'\makecell{Transaction\\count}', 'Time (ms)', 'Mgas', 'Time (ms)', 'Mgas'],
          ['Dealer 수', '$t$', '거래 수', '시간 (ms)', 'Mgas', '시간 (ms)', 'Mgas'], dispute_rows,
          group=(r' & & \multicolumn{3}{c}{Polynomial mismatch} & \multicolumn{2}{c}{Decrypted-value mismatch}\\\cmidrule(lr){3-5}\cmidrule(lr){6-7}',
                 r' & & \multicolumn{3}{c}{다항식 불일치} & \multicolumn{2}{c}{복호문 불일치}\\\cmidrule(lr){3-5}\cmidrule(lr){6-7}'))

    gas = {}
    for x in completed:
        normal = [t for t in x['trials'] if t['baseline']]
        total = statistics.median(t['execution_gas'] for t in normal)
        registry = statistics.median(t['registry_gas'] for t in normal)
        gas[x['plan']['name']] = dict(total=total, registry=registry, ratio=registry/total*100,
                                    blob=statistics.median(t['blob_gas'] for t in normal))
    table('gas', 'Execution gas at threshold 32. Total includes deployment and all transactions in one baseline lifecycle. Registration includes both participant registration and activation. Percentages are ratios of medians; 1,024 and 2,048 participants have one run each.',
          '복원 임계값 32에서의 execution gas. 총량은 정상 lifecycle 1회의 배포 및 모든 거래를 포함한다. 등록 비용은 참여자 등록과 활성화를 합한 값이다. 비율은 각 중앙값의 비이며, 1,024명·2,048명은 각각 한 번의 실행값이다.',
          ['Dealers', 'Participants', 'Total Mgas', 'Registration Mgas', r'Registration (\%)'],
          ['Dealer 수', '참여자 수', '총량 (Mgas)', '등록 (Mgas)', r'등록 비중 (\%)'],
          [[x['plan']['committee'][0], x['plan']['populations'][0], fmt(g['total']/1e6), fmt(g['registry']/1e6), fmt(g['ratio'], 1)] for x in population for g in [gas[x['plan']['name']]]])
    capacity_rows = {'en': [], 'ko': []}
    for lang in capacity_rows:
        for n in [4, 7]:
            for t in [128, 256, 512, 1024]:
                observed = choose('Completed', '실행 완료', lang) if t == 128 or (n == 4 and t == 256) else (
                    choose('Publication failed', '게시 단계 실패', lang) if (n, t) == (7, 256) else choose('Calculation only', '계산값만 있음', lang))
                capacity_rows[lang].append([n, t, fmt(source.payload(n, t, t, 1), 0), observed])
    table('capacity', 'Bundle size with equal source/target thresholds and one offline participant. The current payload limit is 126,914 bytes. Thresholds 128 and 256 use retained actual bundles; 512 and 1,024 are predictions without completed executions.',
          '전환 전후 임계값이 같고 오프라인 참여자가 한 명일 때의 게시 자료 크기. 현재 한도는 126,914바이트다. 임계값 128·256은 실제 보관 자료와 일치하는 크기이며, 512·1,024는 실행 완료 결과가 없는 계산값이다.',
          ['Dealers', 'Threshold', 'Bundle bytes', 'Evidence'],
          ['Dealer 수', '복원 임계값', '자료 크기 (바이트)', '근거'], [], '@{}rrrl@{}', localized_rows=capacity_rows)

    families = [(['reference'], 'Growing reference schedule', '참여자·임계값이 변하는 기준 실험'),
                (['threshold'], 'Vary threshold at 160 participants', '참여자 160명에서 임계값 변경'),
                (['population'], 'Threshold 32; 320 or 640 participants', '임계값 32에서 참여자 320명·640명'),
                (['growth'], 'Grow from 64 to 512 participants', '실행 도중 참여자 64명에서 512명으로 증가'),
                (['margin'], '5-dealer committee', 'Dealer 5명인 위원회'),
                (['high_threshold'], '4 dealers at threshold 256', 'Dealer 4명에서 임계값 256'),
                (['population_probe'], '1,024 or 2,048 participants', '참여자 1,024명·2,048명')]
    coverage = {'en': [], 'ko': []}
    for fam, en, ko in families:
        selected = [x for x in completed if x['plan']['family'] in fam]
        for lang in coverage:
            coverage[lang].append([choose(en, ko, lang), len(selected), sum(x['plan']['repeats'] for x in selected), sum(int(x['plan']['fault_scenarios']) for x in selected)])
    table('coverage', 'How the 72 completed lifecycles are counted. A setting fixes the committee and the four-epoch threshold/participant schedule. Normal and fault executions are counted separately.',
          '완료된 lifecycle 72회의 구성. 하나의 설정은 위원회와 네 epoch의 임계값·참여자 수 일정을 고정한 것이다. 정상 실행과 장애 실행은 별도로 센다.',
          ['Experiment', 'Settings', 'Baseline runs', 'Fault runs'],
          ['실험', '설정 수', '정상 실행', '장애 실행'], [], '@{}p{.52\linewidth}rrr@{}', localized_rows=coverage)

    localized = {'en': [], 'ko': []}
    for lang in localized:
        for x in completed:
            values = [v/1000 for v in source.times(x['samples'], 'lifecycle')]
            localized[lang].append([setting(x, lang), x['plan']['repeats'], int(x['plan']['fault_scenarios']),
                                    fmt(statistics.median(values)), fmt(min(values))+'--'+fmt(max(values)),
                                    fmt(seconds(x, 'deployment_and_process_setup'))])
    table('all_lifecycles', 'Every completed setting. Times are seconds. Lifecycle and setup values describe baseline executions; the fault column only counts separately executed fault lifecycles. A one-run range does not estimate variability. Arrows give epochs 0, 1, 2 and 3; a single value is constant throughout.',
          '완료된 모든 설정. 시간 단위는 초다. lifecycle과 준비 시간은 정상 실행의 값이며, 장애 열은 별도로 수행한 장애 lifecycle 횟수다. 1회 실행의 범위는 변동성을 추정하지 않는다. 화살표는 epoch 0·1·2·3의 값이고, 단일 값은 실행 내내 일정하다.',
          ['Setting', r'\makecell{Baseline\\runs}', r'\makecell{Fault\\runs}', r'\makecell{Lifecycle\\median}', r'\makecell{Lifecycle\\range}', r'\makecell{Setup\\median}'],
          ['설정', r'\makecell{정상\\횟수}', r'\makecell{장애\\횟수}', r'\makecell{전체 실행\\중앙값}', r'\makecell{전체 실행\\범위}', r'\makecell{준비 시간\\중앙값}'], [],
          '@{}p{.36\linewidth}rrrrr@{}', True, localized)
    phases = ['generation', 'reservation_and_certificate', 'direct_delivery_stage', 'archive_blob_publication', 'commit_and_apply', 'refresh']
    table('threshold_phases', 'Second-transition phase medians in seconds, three baseline runs per setting. Population is 160 except for threshold 256, which uses 320. The enclosing refresh interval is measured directly.',
          '두 번째 전환의 단계별 중앙값. 단위는 초이며 설정별 정상 실행은 3회다. 참여자는 160명이지만 임계값 256인 행은 320명이다. 전체 갱신 구간은 직접 측정했다.',
          ['Dealers', '$t$', r'\makecell{Generate\\updates}', r'\makecell{Reserve\\release}', r'\makecell{Deliver\\and stage}', r'\makecell{Publish\\data}', r'\makecell{Commit\\and apply}', r'\makecell{Whole\\refresh}'],
          ['Dealer 수', '$t$', r'\makecell{갱신값\\생성}', r'\makecell{공개 대상\\예약}', r'\makecell{전달 및\\임시 저장}', r'\makecell{자료\\게시}', r'\makecell{확정 및\\적용}', r'\makecell{전체\\갱신}'],
          [[x['plan']['committee'][0], x['plan']['thresholds'][0], *[fmt(seconds(x, metric, 2)) for metric in phases]] for x in threshold+[by['threshold-t256-n4']]])
    table('population_phases', 'Costs at reconstruction threshold 32, in seconds. Initial issuance covers the entire initial participant set; other phase columns refer to transition 2. Values are three-run medians except the two largest four-dealer settings, each observed once.',
          '복원 임계값 32에서의 단계별 비용. 단위는 초다. 최초 발급은 초기 참여자 전체를 대상으로 하고, 나머지 단계는 두 번째 전환의 값이다. 4-dealer의 최대 두 설정은 각각 1회 관측, 나머지는 3회 중앙값이다.',
          ['Dealers', 'Participants', r'\makecell{Initial\\issuance}', r'\makecell{Generate\\updates}', r'\makecell{Deliver\\and stage}', r'\makecell{Commit\\and apply}'],
          ['Dealer 수', '참여자 수', r'\makecell{최초\\발급}', r'\makecell{갱신값\\생성}', r'\makecell{전달 및\\임시 저장}', r'\makecell{확정 및\\적용}'],
          [[x['plan']['committee'][0], x['plan']['populations'][0], fmt(seconds(x, 'bootstrap_and_initial_issuance')),
            fmt(seconds(x, 'generation', 2)), fmt(seconds(x, 'direct_delivery_stage', 2)), fmt(seconds(x, 'commit_and_apply', 2))] for x in population])
    table('reconstruction', 'Reconstruction after epoch 2, in milliseconds. Each entry is the median of three baseline lifecycles with 160 participants. These times are outside the refresh interval.',
          'Epoch 2 이후 secret 복원 시간. 단위는 ms이며 참여자 160명인 정상 lifecycle 3회의 중앙값이다. 이 시간은 갱신 구간 밖에 있다.',
          ['Dealers', 'Threshold', 'Reconstruction (ms)'], ['Dealer 수', '복원 임계값', 'Secret 복원 (ms)'],
          [[x['plan']['committee'][0], x['plan']['thresholds'][0], fmt(ms(x, 'reconstruct', 2))] for x in threshold])
    recovery = {'en': [], 'ko': []}
    fault_rows = {'en': [], 'ko': []}
    all_gas = {'en': [], 'ko': []}
    resources = {'en': [], 'ko': []}
    for lang in recovery:
        for x in completed:
            recovery[lang].append([setting(x, lang), x['plan']['repeats'], fmt(ms(x, 'offline_catchup', 1)), fmt(ms(x, 'offline_catchup', 2))])
            g = gas[x['plan']['name']]
            all_gas[lang].append([setting(x, lang), fmt(g['total']/1e6), fmt(g['registry']/1e6), fmt(g['ratio'], 1)])
        for x in faults:
            fault_rows[lang].append([setting(x, lang), fmt(seconds(x, 'lifecycle', scenario='integrated_faults')),
                                    fmt(ms(x, 'published_attempt_abort', 1, 'integrated_faults')),
                                    fmt(ms(x, 'crash_restart_before_commit', 1, 'integrated_faults')),
                                    fmt(ms(x, 'authorized_current_epoch_reissuance', 3, 'integrated_faults'))])
        all_items = {x['plan']['name']: x for x in completed+incomplete}
        for p in plan:
            x = all_items[p['name']]
            s = x['status']
            resources[lang].append([setting(x, lang),
                {'completed': choose('Completed', '완료', lang),
                 'expected_capacity_failure': choose('Blob overflow', 'Blob 용량 초과', lang),
                 'expected_config_rejection': choose('Rejected before run', '실행 전 거절', lang),
                 'not_run': choose('Not run', '미실행', lang)}[s['status']],
                 fmt(s.get('wall_seconds'), 1), fmt(s['peak_sampled_rss_sum_bytes']/2**30, 2) if 'peak_sampled_rss_sum_bytes' in s else '--'])
    table('all_recovery', 'One returning participant, with all dealers stopped. Each column is a separate per-update baseline median in milliseconds (or an individual value for a one-run setting). Both requests take place after the second transition.',
          'Dealer를 모두 중단한 상태의 참여자 한 명 복귀. 각 열은 갱신 하나에 대한 정상 실행 중앙값이며 단위는 ms다. 1회 실행 설정은 개별 값이다. 두 요청은 모두 두 번째 전환 이후에 발생한다.',
          ['Setting', 'Runs', r'\makecell{First missed\\update (ms)}', r'\makecell{Second missed\\update (ms)}'],
          ['설정', '실행 횟수', r'\makecell{첫 번째 누락\\갱신 (ms)}', r'\makecell{두 번째 누락\\갱신 (ms)}'], [],
          '@{}p{.48\linewidth}rrr@{}', True, recovery)
    table('all_faults', 'One fault lifecycle per setting. Whole-lifecycle time is seconds; the other columns are milliseconds. The abort interval includes work performed before abort, not just the abort call. Restart is measured after durable staging. Re-issuance includes authorization and activation.',
          '설정별 장애 lifecycle 1회의 관측. 전체 실행은 초, 나머지는 ms 단위다. 중단 구간에는 중단 전 작업도 포함되며 중단 호출만의 시간이 아니다. 재시작은 영속적 임시 저장 이후 측정했고, 재발급에는 권한 확인과 활성화가 포함된다.',
          ['Setting', r'\makecell{Whole fault\\lifecycle (s)}', r'\makecell{Attempt then\\abort (ms)}', r'\makecell{Restart\\(ms)}', r'\makecell{Re-issue\\(ms)}'],
          ['설정', r'\makecell{전체 장애\\실행 (초)}', r'\makecell{시도 후\\중단 (ms)}', r'\makecell{재시작\\(ms)}', r'\makecell{재발급\\(ms)}'], [],
          '@{}p{.36\linewidth}rrrr@{}', True, fault_rows)
    table('all_gas', 'Complete baseline execution-gas accounting, in millions of gas units. Totals include deployment, enrollment, rotation and all baseline transactions. Every baseline also uses 393,216 blob-gas units, reported separately from execution gas.',
          '정상 실행의 전체 execution gas. 단위는 백만 gas다. 배포·등록·키 교체 및 모든 정상 거래를 포함한다. 각 정상 실행은 별도로 393,216 blob gas를 사용하며 execution gas에 합산하지 않는다.',
          ['Setting', 'Total Mgas', 'Registration Mgas', r'Registration (\%)'],
          ['설정', '총량 (Mgas)', '등록 (Mgas)', r'등록 비중 (\%)'], [],
          '@{}p{.44\linewidth}rrr@{}', True, all_gas)
    table('resources', 'Elapsed time for the entire experiment at each setting, including setup, all repetitions and audit; it is not one lifecycle. RSS is the largest sampled sum of process resident-memory counters and may double-count shared pages. Memory is in GiB.',
          '각 설정의 준비·모든 반복 실행·검증을 합친 경과 시간이며, lifecycle 1회의 시간이 아니다. RSS는 프로세스 상주 메모리 계수의 합에서 관측한 최대 표본으로, 공유 페이지를 중복 계산할 수 있다. 메모리 단위는 GiB다.',
          ['Setting', 'Outcome', r'\makecell{Whole experiment\\time (s)}', r'\makecell{Sampled RSS\\sum (GiB)}'],
          ['설정', '결과', r'\makecell{설정 전체\\경과 시간 (초)}', r'\makecell{관측 RSS\\합 (GiB)}'], [],
          '@{}p{.42\linewidth}p{.18\linewidth}rr@{}', True, resources)

    for key, locales in NUMBERS.items():
        assert locales['en'] == locales['ko'], ('Translation changed numbers', key)
    assert all(ms(x, 'published_attempt_abort', 1, 'integrated_faults') is not None for x in faults)

    values = {
        'RefFour': fmt(seconds(refs[0], 'lifecycle')), 'RefSeven': fmt(seconds(refs[1], 'lifecycle')),
        'ThresholdFourLow': fmt(seconds(by['threshold-t16-n4'], 'refresh', 2)),
        'ThresholdFourHigh': fmt(seconds(by['threshold-t128-n4'], 'refresh', 2)),
        'ThresholdSevenLow': fmt(seconds(by['threshold-t16-n7'], 'refresh', 2)),
        'ThresholdSevenHigh': fmt(seconds(by['threshold-t128-n7'], 'refresh', 2)),
        'ThresholdFourRatio': fmt(ms(by['threshold-t128-n4'], 'refresh', 2)/ms(by['threshold-t16-n4'], 'refresh', 2), 2),
        'ThresholdSevenRatio': fmt(ms(by['threshold-t128-n7'], 'refresh', 2)/ms(by['threshold-t16-n7'], 'refresh', 2), 2),
        'LargeLife': fmt(seconds(by['population-p2048-n4'], 'lifecycle')),
        'LargeRefresh': fmt(seconds(by['population-p2048-n4'], 'refresh', 2)),
        'LargeSetup': fmt(seconds(by['population-p2048-n4'], 'deployment_and_process_setup')),
        'LargeIssuance': fmt(seconds(by['population-p2048-n4'], 'bootstrap_and_initial_issuance')),
        'SmallGen': fmt(ms(by['threshold-t32-n4'], 'generation', 2)),
        'LargeGen': fmt(ms(by['population-p2048-n4'], 'generation', 2)),
        'SmallRegistration': fmt(gas['threshold-t32-n4']['ratio'], 1),
        'LargeRegistration': fmt(gas['population-p2048-n4']['ratio'], 1),
        'HighLife': fmt(seconds(by['threshold-t256-n4'], 'lifecycle')),
        'MarginLife': fmt(seconds(by['margin-n5'], 'lifecycle')),
        'LargeWall': fmt(by['population-p2048-n4']['status'].get('wall_seconds'), 1),
    }
    definitions = r'\newcommand{\Vnum}[1]{\csname result#1\endcsname}' + '\n'
    definitions += '\n'.join(r'\expandafter\def\csname result' + k + r'\endcsname{' + v + '}' for k, v in values.items()) + '\n'
    output_hashes = {}
    for lang, name in [('en', 'report_v3'), ('ko', 'report_v3_ko')]:
        template = (OUT / f'report_{lang}.tex').read_text()
        assert template.count('% GENERATED VALUES') == 1
        text = template.replace('% GENERATED VALUES', definitions)
        needed = re.findall(r'^% TABLE:(\w+)$', text, re.M)
        assert set(needed) == set(TABLES[lang]), (lang, set(TABLES[lang])-set(needed))
        assert len(needed) == len(set(needed))
        for key in needed:
            text = re.sub(r'^% TABLE:'+re.escape(key)+r'$', lambda _: TABLES[lang][key].rstrip(), text, flags=re.M)
        assert all(key in values for key in re.findall(r'\\Vnum\{(\w+)\}', text))
        labels = re.findall(r'\\label\{([^}]+)\}', text)
        refs_in_text = re.findall(r'\\(?:ref|eqref|pageref)\{([^}]+)\}', text)
        assert len(labels) == len(set(labels))
        assert not set(refs_in_text)-set(labels), (lang, set(refs_in_text)-set(labels))
        assert not re.search(r'population-p\d|threshold-t\d|run_experiments|\\begin\{verbatim\}|\\path\{', text)
        assert not any(ord(c)<32 and c not in '\n\t' for c in text)
        (ROOT/f'{name}.tex').write_text(text)
        output_hashes[name+'.tex'] = digest(ROOT/f'{name}.tex')
        folder = OUT/'tables'/lang
        folder.mkdir(parents=True, exist_ok=True)
        for key, block in TABLES[lang].items():
            (folder/f'{key}.tex').write_text(block)
    manifest = {
        'dataset': str(DATA.relative_to(ROOT)), 'new_experiments_run': False,
        'validated_measurement_totals': totals, 'table_count_per_language': len(TABLES['en']),
        'translated_table_numbers_identical': True, 'prose_values': values,
        'data_hashes': verified['evidence_sha256'], 'source_report_sha256': digest(ROOT/'report_v2.tex'),
        'output_sha256': output_hashes, 'generator_sha256': digest(Path(__file__)),
        'table_sha256': {lang: {key: hashlib.sha256(v.encode()).hexdigest() for key, v in blocks.items()} for lang, blocks in TABLES.items()},
        'setting_map': {x['plan']['name']: {lang: setting(x, lang) for lang in ['en', 'ko']} for x in completed+incomplete},
    }
    (OUT/'metrics.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2)+'\n')
    print(f'Built English and Korean reports from {verified["trials"]} existing lifecycles; {len(TABLES["en"])} numerical tables per language.')


if __name__ == '__main__':
    main()
