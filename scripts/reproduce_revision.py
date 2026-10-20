#!/usr/bin/env python3
"""Reproduce the 0.1.1 inventory, discovery and optional scheduling evaluation.

Run from the repository root, after installing .[source,solver,validate,versions].
No TLS target is contacted. Results describe this checkout, not the 0.1.0 paper.
"""
import argparse
from collections import Counter
from dataclasses import replace, asdict
import csv
import importlib.metadata
import json
from pathlib import Path
import platform
import statistics
import subprocess
import time

import yaml
from qramp import __version__, scan, assess, plan, report
from qramp.model import Inventory
from qramp.readiness import readiness_report

ROOT = Path(__file__).resolve().parents[1]

def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False)+'\n', encoding='utf-8')

def check_schedule(tasks, capacity):
    by_id={t.id:t for t in tasks}; load=Counter()
    for t in tasks:
        if t.start_month is None:
            raise AssertionError('unscheduled task')
        for pre in t.prerequisites:
            p=by_id[pre]
            assert t.start_month >= p.start_month+p.duration_months
        for month in range(t.start_month,t.start_month+t.duration_months):
            load[t.owner,month]+=1
            assert load[t.owner,month] <= capacity.get('per_owner_concurrent',{}).get(t.owner,capacity.get('default_concurrent',1))
    return True


def challenge(out):
    data=json.loads((ROOT/'testbed/revision-source-fixtures.json').read_text())
    rows=[]; totals={}
    for f in data['fixtures']:
        folder=out/'challenge-inputs'/f['id']; folder.mkdir(parents=True,exist_ok=True)
        (folder/f['filename']).write_text(f['source'],encoding='utf-8')
        inv=scan(Inventory(),source_dir=str(folder))
        predicted=any(o.collector.startswith('source-') for a in inv.assets for o in a.occurrences)
        verdict=('TP' if predicted else 'FN') if f['positive'] else ('FP' if predicted else 'TN')
        rows.append({k:f[k] for k in ('id','language','kind','positive')} | {'predicted':predicted,'verdict':verdict,'occurrences':inv.occurrence_count()})
    for lang in ('python','java','go','rust','c','total'):
        counts=Counter(r['verdict'] for r in rows if lang=='total' or r['language']==lang)
        totals[lang]={k:counts[k] for k in ('TP','FP','FN','TN')}
        totals[lang]['precision']=counts['TP']/(counts['TP']+counts['FP']) if counts['TP']+counts['FP'] else None
        totals[lang]['recall']=counts['TP']/(counts['TP']+counts['FN']) if counts['TP']+counts['FN'] else None
    write(out/'discovery.json',{'scope':data['description'],'results':rows,'summary':totals})
    with (out/'discovery.csv').open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=rows[0].keys()); w.writeheader(); w.writerows(rows)
    return totals


def sensitivity(out, baseline, capacity, limit, repeats):
    ids=sorted({t.target_asset for t in baseline}); keep=set(ids[::2])
    copied=[replace(t,id='copy-'+t.id,prerequisites=['copy-'+p for p in t.prerequisites]) for t in baseline]
    configs=[
      ('baseline',baseline,capacity),
      ('capacity-one',baseline,{'default_concurrent':1}),
      ('double-capacity',baseline,{'default_concurrent':2*capacity.get('default_concurrent',1),'per_owner_concurrent':{k:2*v for k,v in capacity.get('per_owner_concurrent',{}).items()}}),
      ('half-duration',[replace(t,duration_months=max(1,(t.duration_months+1)//2)) for t in baseline],capacity),
      ('double-duration',[replace(t,duration_months=2*t.duration_months) for t in baseline],capacity),
      ('complete-asset-subset',[t for t in baseline if t.target_asset in keep],capacity),
      ('duplicated-graph',baseline+copied,capacity)]
    summary=[]
    for name,tasks,cap in configs:
        rows=[]
        for solver,n in [('list',1),('cpsat',repeats)]:
            for rep in range(n):
                run=[replace(t,start_month=None) for t in tasks]
                meta=plan.schedule(run,cap,36,solver=solver,time_limit_s=limit)
                assert solver!='cpsat' or meta['solver']=='cp-sat', 'install .[solver] to reproduce CP-SAT results'
                check_schedule(run,cap)
                row={'configuration':name,'requested_solver':solver,'repetition':rep+1,'tasks':len(run),'E':plan.weighted_exposure_days(run),'meta':meta}
                rows.append(row)
                write(out/'schedules'/name/f'{solver}-{rep+1}.json',row | {'capacity':cap,'schedule':[asdict(t) for t in run]})
        lst=rows[0]['E']; med=statistics.median(r['E'] for r in rows[1:])
        summary.append({'configuration':name,'tasks':len(tasks),'list_E':lst,'cpsat_E_median':med,'reduction_pct':100*(lst-med)/lst if lst else 0,'runs':rows})
        print(f'scheduling {name}: {len(tasks)} tasks, list={lst}, CP-SAT median={med}',flush=True)
    write(out/'scheduling.json',summary)
    return summary


def main():
    ap=argparse.ArgumentParser(__doc__)
    ap.add_argument('--out',default='revision-results')
    ap.add_argument('--sensitivity',action='store_true')
    ap.add_argument('--time-limit',type=float,default=10.0)
    ap.add_argument('--repeats',type=int,default=3)
    args=ap.parse_args()
    if args.time_limit<=0 or args.repeats<1: ap.error('time-limit and repeats must be positive')
    out=Path(args.out).resolve();out.mkdir(parents=True,exist_ok=True)
    owners=yaml.safe_load((ROOT/'testbed/policy/owners.yaml').read_text())
    start=time.perf_counter()
    inv=scan(Inventory(),source_dir=str(ROOT/'testbed/sample-app'),sbom_path=str(ROOT/'testbed/sample-app/sbom.cdx.json'),manifests_dir=str(ROOT/'testbed/manifests'),cert_dir=str(ROOT/'testbed/certs'),config_dir=str(ROOT/'testbed/etc'),owner_map=owners)
    inv.save(str(out/'cbom.json')); loaded=Inventory.load(str(out/'cbom.json'))
    assert {a.key:a.asset_id for a in inv.assets}=={a.key:a.asset_id for a in loaded.assets}
    assert inv.occurrence_count()==loaded.occurrence_count()
    assessment=assess.assess(str(out/'cbom.json'),str(ROOT/'src/qramp/rules/transition-2024.yaml'),str(ROOT/'testbed/policy/data-lifetimes.yaml'),str(out/'assessment.json'))
    planned=plan.plan(str(out/'assessment.json'),str(ROOT/'testbed/policy/teams.yaml'),36,str(out/'plan-list.yaml'),solver='list')
    evidence=report.verify(str(out/'plan-list.yaml'),str(out/'cbom.json'),str(out/'verification.json'))
    report.plan_to_csv(str(out/'plan-list.yaml'),str(out/'plan.csv'))
    assessed=Inventory.load(str(out/'assessment.json'))
    from qramp.cyclonedx import to_cyclonedx
    from qramp.sarif import to_sarif
    write(out/'cbom.cdx.json',to_cyclonedx(assessed))
    write(out/'qramp.sarif',to_sarif(assessed,assess.load_rules(str(ROOT/'src/qramp/rules/transition-2024.yaml'))))
    report.dashboard(str(out/'assessment.json'),str(out/'dashboard.html'))
    pmap=yaml.safe_load((ROOT/'src/qramp/data/provider-map.yaml').read_text())
    def git(*args):
        try:return subprocess.check_output(['git','-C',str(ROOT),*args],text=True).strip()
        except (OSError,subprocess.CalledProcessError):return 'unavailable'
    summary={'software_version':__version__,'source_commit':git('rev-parse','HEAD'),'dirty_checkout':bool(git('status','--porcelain')),'python':platform.python_version(),'platform':platform.platform(),'dependency_versions':{p:importlib.metadata.version(p) for p in ('cryptography','PyYAML','networkx','tree-sitter','tree-sitter-python','tree-sitter-java','tree-sitter-go','tree-sitter-rust','tree-sitter-c','ortools','cyclonedx-python-lib','jsonschema')},'scan_assets':len(inv),'loaded_assets':len(loaded),'occurrences':inv.occurrence_count(),'certificates':len(inv.certificates),'components':len(inv.components),'assessment':assessment,'tasks':planned['task_count'],'task_types':dict(Counter(t['type'] for t in planned['tasks'])),'list_schedule':planned['solver_meta'],'list_E':planned['weighted_exposure_days'],'verification_status_counts':evidence['status_counts'],'readiness':readiness_report(assessed,pmap),'pipeline_wall_seconds':time.perf_counter()-start}
    summary['discovery']=challenge(out)
    if args.sensitivity:
        capacity=yaml.safe_load((ROOT/'testbed/policy/teams.yaml').read_text())
        summary['scheduling']=sensitivity(out,plan.synthesise_tasks(assessed),capacity,args.time_limit,args.repeats)
    write(out/'summary.json',summary)
    print(json.dumps({k:summary[k] for k in ('software_version','scan_assets','loaded_assets','occurrences','tasks','verification_status_counts')},indent=2),flush=True)
    print(f'Results: {out}',flush=True)

if __name__=='__main__':main()
