#!/usr/bin/env python3
"""Offline validation against external files and independently constructed references.
The source annotation is separately constructed, not independent human annotation.
Run from any directory: python scripts/validate_review2.py --out review2-validation
OpenSSL CLI is required for the independent certificate field reference.
"""
import argparse
from collections import Counter
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import warnings
import yaml
from qramp import scan, assess, plan, report
from qramp.model import Inventory
from qramp.collectors import certs, configs, manifests, sbom, tls
from packaging.requirements import Requirement

ROOT=Path(__file__).resolve().parents[1]
DATA=ROOT/'testbed/external-validation'

def write(p,obj):
 p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(obj,indent=2,default=str)+'\n',encoding='utf-8')

def source_reference(out):
 labels=json.loads((DATA/'source-reference.json').read_text())
 inv=scan(Inventory(),source_dir=str(DATA/'source'));inv.save(str(out/'source-inventory.json'))
 observed={}
 for a in inv.assets:
  for o in a.occurrences:
   if o.collector!='source-py':continue
   path,line=o.locator.rsplit(':',1)
   observed[(str(Path(path).relative_to(DATA/'source')),int(line))]=a.algorithm
 rows=[]
 for x in labels:
  found=observed.pop((x['file'],x['line']),None)
  good=found==x['algorithm']
  rows.append(x|{'observed':found,'verdict':'TP' if good else 'FN'})
 for (file,line),alg in observed.items():rows.append({'file':file,'line':line,'observed':alg,'verdict':'FP'})
 counts=Counter(r['verdict'] for r in rows)
 result={'unit':'hash/MAC construction call site in the complete selected files, including file-local selectable digest calls; not runtime execution or whole-project completeness','TP':counts['TP'],'FP':counts['FP'],'FN':counts['FN'],'precision':counts['TP']/(counts['TP']+counts['FP']),'recall':counts['TP']/(counts['TP']+counts['FN']),'files':3,'reference_sites':len(labels),'rows':rows}
 write(out/'source-comparison.json',result);return result

def cert_reference(out):
 data=(DATA/'certs/cacert.pem').read_bytes()
 blocks=re.findall(rb'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----',data,re.S)
 # Compare one certificate per input block to avoid ambiguities in bundle locators.
 rows=[]
 sigs={'sha1WithRSAEncryption':('rsa','sha1'),'sha256WithRSAEncryption':('rsa','sha2-256'),'sha384WithRSAEncryption':('rsa','sha2-384'),'sha512WithRSAEncryption':('rsa','sha2-512'),'ecdsa-with-SHA256':('ecdsa','sha2-256'),'ecdsa-with-SHA384':('ecdsa','sha2-384'),'ecdsa-with-SHA512':('ecdsa','sha2-512')}
 with tempfile.TemporaryDirectory() as td:
  td=Path(td)
  for n,block in enumerate(blocks):
   p=td/f'{n}.pem';p.write_bytes(block+b'\n')
   text=subprocess.check_output(['openssl','x509','-in',str(p),'-noout','-text','-serial'],text=True)
   sig=re.search(r'Signature Algorithm:\s*([^\n]+)',text)[1].strip()
   pub=re.search(r'Public Key Algorithm:\s*(\S+)',text)[1]
   bits=int(re.search(r'Public-Key:\s*\((\d+) bit\)',text)[1])
   serial=re.search(r'^serial=(\S+)',text,re.M)[1].lower().lstrip('0') or '0'
   alg={'rsaEncryption':'rsa','id-ecPublicKey':'ecdsa'}[pub]
   curve=(re.search(r'ASN1 OID:\s*(\S+)',text)[1] if pub=='id-ecPublicKey' else '')
   curve={'prime256v1':'secp256r1'}.get(curve,curve)
   salg,shash=sigs[sig]
   expected={'serial':serial,'key_algorithm':alg,'key_bits':bits,'curve':curve,'signature_algorithm':salg,'signature_digest':shash}
   inv=Inventory();certs.run(inv,cert_dir=str(td))
   # Remove each block after its independent scan so each inventory has one node.
   c=inv.certificates[0]; key=c.key_ref;sign=c.sig_ref
   actual={'serial':c.serial,'key_algorithm':key[1],'key_bits':key[3],'curve':key[2] if alg=='ecdsa' else '', 'signature_algorithm':sign[1],'signature_digest':sign[2].removeprefix('cert-sig:')}
   rows.append({'block':n+1,'sha256':hashlib.sha256(block).hexdigest(),'reference':expected,'observed':actual,'fields_equal':expected==actual,'weak_digest_reference':shash=='sha1','weak_digest_observed':'weak-signature' in c.weak_tags})
   p.unlink()
 bundle=Inventory();stats=certs.run(bundle,cert_dir=str(DATA/'certs'))
 result={'reference_tool':subprocess.check_output(['openssl','version'],text=True).strip(),'unit':'certificate public-key algorithm, size, curve, signature algorithm/digest and serial; no path-validation or deployment claim','reference_certificates':len(blocks),'collected_certificates':len(bundle.certificates),'all_fields_equal':sum(x['fields_equal'] for x in rows),'weak_digest_TP':sum(x['weak_digest_reference'] and x['weak_digest_observed'] for x in rows),'weak_digest_FP':sum(not x['weak_digest_reference'] and x['weak_digest_observed'] for x in rows),'weak_digest_FN':sum(x['weak_digest_reference'] and not x['weak_digest_observed'] for x in rows),'collector_stats':stats,'rows':rows}
 write(out/'certificate-comparison.json',result);return result

def dependency_reference(out):
 rows=[];sbomrows=[]
 # Read all ordinary dependency declarations with a separate ecosystem parser.
 for project in ('httpx','ansible'):
  folder=DATA/'manifests'/project
  reference=[]
  for raw in (folder/'requirements.txt').read_text().splitlines():
   line=raw.split('#',1)[0].strip()
   if not line or line.startswith('-'):continue
   req=Requirement(line);reference.append({'name':req.name.lower(),'constraint':str(req.specifier)})
  inv=Inventory();stats=manifests.run(inv,source_dir=str(folder))
  actual={c.name for c in inv.components}
  expected={x['name'] for x in reference if x['name']=='cryptography'}
  rows.append({'project':project,'declarations':reference,'expected_crypto_components':sorted(expected),'observed_crypto_components':sorted(actual),'TP':len(expected&actual),'FP':len(actual-expected),'FN':len(expected-actual),'stats':stats})
  p=DATA/'sbom'/f'{project}.cdx.json';doc=json.loads(p.read_text())
  # Reference is the independent CycloneDX generator's component listing, not QRAMP's provider resolver.
  exp={c['name'].lower() for c in doc.get('components',[]) if c['name'].lower()=='cryptography'}
  si=Inventory();ss=sbom.run(si,sbom_path=str(p));actual={c.name for c in si.components}
  sbomrows.append({'project':project,'components_in_document':len(doc.get('components',[])),'reference_crypto':sorted(exp),'observed_crypto':sorted(actual),'TP':len(exp&actual),'FP':len(actual-exp),'FN':len(exp-actual),'stats':ss})
 result={'reference_parser':'packaging.requirements.Requirement '+importlib.metadata.version('packaging'),'scope':'declared cryptography component recovery only; generated SBOMs are derived from the same two manifests, not independent deployments; capability-edge correctness and runtime use not measured','manifest_rows':rows,'sbom_rows':sbomrows,'manifest_totals':{k:sum(r[k] for r in rows) for k in ('TP','FP','FN')},'sbom_totals':{k:sum(r[k] for r in sbomrows) for k in ('TP','FP','FN')}}
 write(out/'dependency-comparison.json',result);return result

def config_reference(out):
 # Separate property reader: comments excluded, continuation lines joined.
 properties={};buffer=''
 for raw in (DATA/'configs/java.security').read_text().splitlines():
  s=raw.strip()
  if not s or s.startswith(('#','!')):continue
  buffer+=s[:-1] if s.endswith('\\') else s
  if s.endswith('\\'):continue
  if '=' in buffer:
   k,v=buffer.split('=',1);properties[k.strip()]=v.strip()
  buffer=''
 value=properties['jdk.tls.disabledAlgorithms']
 clauses=[x.strip().lower() for x in value.split(',')]
 # MD5withRSA is a disabled signature clause, not a prohibition of all MD5 uses.
 # The legacy parser checks generic substring md5; evaluate the same narrower
 # certificate-signature risk category without claiming generic MD5 is disabled.
 expected_disabled={'sslv3':any(x=='sslv3' for x in clauses),'tlsv1':any(x=='tlsv1' for x in clauses),'rc4':any(x=='rc4' for x in clauses),'md5withrsa':any(x=='md5withrsa' for x in clauses),'3des':any(x=='3des_ede_cbc' for x in clauses)}
 inv=Inventory();stats=configs.run(inv,config_dir=str(DATA/'configs'))
 findings=[{'algorithm':a.algorithm,'params':a.params,'evidence':o.evidence,'file':Path(o.locator.split(':')[0]).name} for a in inv.assets for o in a.occurrences]
 # Expected no weak-category findings for these 5 JDK entries; other 2 files
 # have no active declarations in QRAMP's supported directive families.
 result={'unit':'five JDK weak-category policy entries; two service-template files with no active supported crypto directives are negative controls; no daemon defaults/inheritance evaluated','jdk_reference_property':value,'disabled_categories':expected_disabled,'TP':0,'FP':len(findings),'FN':0,'TN':5-len(findings),'service_file_negative_controls':2,'findings':findings,'stats':stats}
 write(out/'configuration-comparison.json',result);return result

def faults(out):
 root=out/'faults';root.mkdir(parents=True,exist_ok=True);app=root/'app';app.mkdir(exist_ok=True)
 f=app/'x.py';f.write_text('import hashlib\nhashlib.md5(b"x")\n')
 inv=scan(Inventory(),source_dir=str(app));inv.save(str(root/'baseline.json'))
 life=root/'life.yaml';life.write_text('default_years: 3\n');cap=root/'capacity.yaml';cap.write_text('default_concurrent: 2\n')
 assess.assess(str(root/'baseline.json'),str(ROOT/'src/qramp/rules/transition-2024.yaml'),str(life),str(root/'assessed.json'))
 pp=root/'plan.yaml';plan.plan(str(root/'assessed.json'),str(cap),36,str(pp),solver='list')
 cases={'retained':'import hashlib\nhashlib.md5(b"x")\n','sha256':'import hashlib\nhashlib.sha256(b"x")\n','alias-md5-plus-sha256':'from hashlib import md5 as hidden\nimport hashlib\nhidden(b"x")\nhashlib.sha256(b"x")\n','sha1-plus-sha256':'import hashlib\nhashlib.sha1(b"x")\nhashlib.sha256(b"x")\n','sha1-only':'import hashlib\nhashlib.sha1(b"x")\n'}
 rows=[]
 for name,src in cases.items():
  f.write_text(src);fresh=scan(Inventory(),source_dir=str(app));cp=root/(name+'-fresh.json');fresh.save(str(cp))
  ev=report.verify(str(pp),str(cp),str(root/(name+'-evidence.json')))
  rows.append({'scenario':name,'source':src,'status_counts':ev['status_counts'],'accepted':ev['accepted'],'migration_status':ev['migration_status'],'reassessment_required':ev['reassessment_required'],'observed_algorithms':sorted({a.algorithm for a in fresh.assets})})
 write(out/'acceptance-counterexamples.json',rows);return rows

def relocate(out):
 from ortools.sat.python import cp_model
 from reproduce_revision import check_schedule
 owners=yaml.safe_load((ROOT/'testbed/policy/owners.yaml').read_text());capacity=yaml.safe_load((ROOT/'testbed/policy/teams.yaml').read_text())
 oldsolve=cp_model.CpSolver.Solve;fingerprints=[]
 def controlled(self,model,*args,**kw):
  fingerprints.append(hashlib.sha256(str(model.Proto()).encode()).hexdigest())
  self.parameters.max_deterministic_time=0.5
  self.parameters.max_time_in_seconds=60
  return oldsolve(self,model,*args,**kw)
 cp_model.CpSolver.Solve=controlled
 rows=[];tasks_by_root=[];schedules=[];cps=[]
 try:
  with tempfile.TemporaryDirectory() as td:
   for suffix in ('a','long checkout name/nested/b','third/c'):
    base=Path(td)/suffix;shutil.copytree(ROOT/'testbed',base)
    inv=scan(Inventory(),source_dir=str(base/'sample-app'),sbom_path=str(base/'sample-app/sbom.cdx.json'),manifests_dir=str(base/'manifests'),cert_dir=str(base/'certs'),config_dir=str(base/'etc'),owner_map=owners)
    cp=Path(td)/'input.json';inv.save(str(cp));assessed=Path(td)/'assessed.json'
    assess.assess(str(cp),str(ROOT/'src/qramp/rules/transition-2024.yaml'),str(base/'policy/data-lifetimes.yaml'),str(assessed))
    tasks=plan.synthesise_tasks(Inventory.load(str(assessed)));tasks_by_root.append([(t.id,t.prerequisites) for t in tasks])
    li=[replace(t,start_month=None) for t in tasks];lm=plan.schedule(li,capacity,36,solver='list');check_schedule(li,capacity);schedules.append([(t.id,t.start_month) for t in li])
    cs=[replace(t,start_month=None) for t in tasks];cm=plan.schedule(cs,capacity,36,solver='cpsat');check_schedule(cs,capacity);cps.append([(t.id,t.start_month) for t in cs])
    rows.append({'location':suffix,'tasks':len(tasks),'list_E':plan.weighted_exposure_days(li),'list_meta':lm,'cpsat_E':plan.weighted_exposure_days(cs),'cpsat_meta':cm,'model_sha256':fingerprints[-1]})
 finally:cp_model.CpSolver.Solve=oldsolve
 result={'locations':3,'identical_ids_and_prerequisites':all(x==tasks_by_root[0] for x in tasks_by_root),'identical_list_schedule':all(x==schedules[0] for x in schedules),'identical_cpsat_model':len(set(fingerprints))==1,'identical_cpsat_schedule_at_fixed_work':all(x==cps[0] for x in cps),'cpsat_budget':'max_deterministic_time=0.5, wall cap=60 s; diagnostic only, separate from 10 s sensitivity runs','rows':rows}
 assert result['identical_ids_and_prerequisites'] and result['identical_list_schedule'] and result['identical_cpsat_model']
 write(out/'relocation-comparison.json',result);return result

def main():
 p=argparse.ArgumentParser(__doc__);p.add_argument('--out',default='review2-validation');args=p.parse_args();out=Path(args.out).resolve();out.mkdir(parents=True,exist_ok=True)
 # Verify external input hashes before measuring anything.
 prov=json.loads((DATA/'provenance.json').read_text())
 for f in prov['files']+prov.get('derived_artifacts',[]):assert hashlib.sha256((DATA/f['local_path']).read_bytes()).hexdigest()==f['sha256']
 warnings.filterwarnings('ignore',category=Warning,module='qramp.collectors.certs')
 results={'source':source_reference(out),'certificates':cert_reference(out),'dependencies':dependency_reference(out),'configs':config_reference(out),'counterexamples':faults(out),'relocation':relocate(out)}
 from validate_tls_review2 import run as tls_validation
 results['tls']=tls_validation(out/'tls')
 write(out/'validation-summary.json',results)
 print(json.dumps({k:{q:v for q,v in x.items() if q not in ('rows','findings','stats','collector_stats','manifest_rows','sbom_rows')} if isinstance(x,dict) else x for k,x in results.items()},indent=2))
if __name__=='__main__':main()
