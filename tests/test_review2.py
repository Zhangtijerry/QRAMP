"""Review-two regression tests. Known acceptance counterexamples are explicit."""
from dataclasses import replace
from pathlib import Path
import copy
import pytest
from qramp import scan, plan
from qramp.model import Inventory, Occurrence
from test_revision import source_setup, verify

@pytest.mark.parametrize('source,algorithms',[
 ('from hashlib import md5 as hidden\nimport hashlib\nhidden(b"x")\nhashlib.sha256(b"x")\n',{'sha2-256'}),
 ('import hashlib\nhashlib.sha1(b"x")\nhashlib.sha256(b"x")\n',{'sha1','sha2-256'}),
])
def test_acceptance_does_not_establish_migration(tmp_path,source,algorithms):
 app,_,pp,_=source_setup(tmp_path);(app/'x.py').write_text(source)
 fresh=scan(Inventory(),source_dir=str(app))
 assert {a.algorithm for a in fresh.assets}==algorithms
 result=verify(tmp_path,pp,fresh,phase=None)
 assert result['accepted'] and result['passed']==2
 assert result['migration_status']=='not_established'
 assert result['reassessment_required']
 assert {x['algorithm'] for x in result['observed_added_asset_identities']}==algorithms


def test_relocation_and_input_order_leave_ids_and_list_schedule_unchanged(tmp_path):
 inputs=[]
 for dirname in ('a','nested dir/second'):
  root=tmp_path/dirname;root.mkdir(parents=True)
  for filename in ('x.py','y.py'):(root/filename).write_text('import hashlib\nhashlib.md5(b"x")\n')
  inv=scan(Inventory(),source_dir=str(root))
  for a in inv.assets:a.exposure_class='quantum_broken';a.tier='P2'
  inputs.append(inv)
 inputs[1]._assets=dict(reversed(list(inputs[1]._assets.items())))
 for a in inputs[1].assets:a.occurrences.reverse()
 scheduled=[]
 for inv in inputs:
  tasks=plan.synthesise_tasks(inv)
  plan.schedule(tasks,{'default_concurrent':1},36,solver='list')
  scheduled.append([(t.id,t.prerequisites,t.start_month) for t in tasks])
 assert scheduled[0]==scheduled[1]
 assert {t.target_locations[0]['path'] for t in plan.synthesise_tasks(inputs[0])} != {t.target_locations[0]['path'] for t in plan.synthesise_tasks(inputs[1])}

@pytest.mark.parametrize('collector,relative',[('source-py','sub/x.py:3'),('configs','sub/x.conf:4'),('certs','sub/x.pem'),('sbom','x.json#openssl@3.5'),('manifests','requirements.txt#cryptography@42')])
def test_canonical_locator_covers_all_file_collectors(tmp_path,collector,relative):
 invs=[]
 for dirname in ('short','a long nested path/other'):
  root=tmp_path/dirname
  # Manifest locators are already root-relative in this collector.
  loc=relative if collector=='manifests' else str(root/relative)
  inv=Inventory();a=inv.observe('hash','md5',Occurrence(collector,loc,'test'));a.exposure_class='quantum_broken';a.tier='P2'
  inv.record_collector(collector,{'root':str(root)})
  invs.append(inv)
 assert [t.id for t in plan.synthesise_tasks(invs[0])]==[t.id for t in plan.synthesise_tasks(invs[1])]


def test_same_basename_different_subdirectories_do_not_collide(tmp_path):
 inv=Inventory()
 for path in ('one/x.py:1','two/x.py:1'):
  a=inv.observe('hash','md5',Occurrence('source-py',str(tmp_path/path),'test'));a.exposure_class='quantum_broken'
 inv.record_collector('source-py',{'root':str(tmp_path)})
 tasks=plan.synthesise_tasks(inv)
 assert len(tasks)==4 and len({t.id for t in tasks})==4


def test_absolute_legacy_locator_needs_root_metadata(tmp_path):
 inv=Inventory();a=inv.observe('hash','md5',Occurrence('source-py',str(tmp_path/'x.py:1'),'test'));a.exposure_class='quantum_broken'
 with pytest.raises(ValueError,match='rescan'):plan.synthesise_tasks(inv)
