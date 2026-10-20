"""Regression cases for the 0.1.1 review fixes; no remote probes."""
import copy
import json
from pathlib import Path

import pytest
import yaml

from qramp import scan, assess, plan, report
from qramp.model import Inventory, Occurrence
from qramp.collectors import certs, source_c

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / 'src/qramp/rules/transition-2024.yaml'


def make_plan(tmp_path, inv):
    cbom = tmp_path / 'cbom.json'; inv.save(str(cbom))
    life = tmp_path / 'life.yaml'; life.write_text('default_years: 3\n')
    assessed = tmp_path / 'assessment.json'
    assess.assess(str(cbom), str(RULES), str(life), str(assessed))
    capacity = tmp_path / 'capacity.yaml'; capacity.write_text('default_concurrent: 2\n')
    pp = tmp_path / 'plan.yaml'
    doc = plan.plan(str(assessed), str(capacity), 36, str(pp), solver='list')
    return pp, doc


def verify(tmp_path, pp, inv, phase=1):
    cp = tmp_path / 'fresh.json'; inv.save(str(cp))
    return report.verify(str(pp), str(cp), str(tmp_path / 'evidence.json'), phase=phase)


def md5_results(result):
    return [r for r in result['results'] if 'MD5' in r['acceptance']]


@pytest.mark.parametrize('legacy', [False, True])
def test_identity_roundtrip_and_evidence(legacy, tmp_path):
    inv = Inventory()
    for primitive, alg in [('hash', 'sha2-256'), ('hash', 'sha2-512'),
                           ('key-agreement', 'ml-kem'), ('signature', 'ml-dsa'),
                           ('key-agreement', 'hybrid-pq')]:
        for n in range(2):
            inv.observe(primitive, alg, Occurrence('source-py', f'a{n}.py:1', alg))
    doc = inv.to_cbom()
    if legacy:
        for c in doc['components']:
            c['qramp'].pop('algorithm')
    cp = tmp_path / 'i.json'; cp.write_text(json.dumps(doc))
    actual = Inventory.load(str(cp))
    for _ in range(2):
        actual.save(str(cp)); actual = Inventory.load(str(cp))
    assert {a.key: a.asset_id for a in actual.assets} == {a.key: a.asset_id for a in inv.assets}
    assert actual.occurrence_count() == 10


def test_internal_roundtrip_preserves_certificate_refs(tmp_path):
    inv = Inventory(); certs.run(inv, cert_dir=str(ROOT / 'testbed/certs'))
    cp = tmp_path / 'c.json'; inv.save(str(cp))
    loaded = Inventory.load(str(cp))
    assert [(c.bom_ref, c.key_ref, c.sig_ref, c.signed_by) for c in inv.certificates] == [
        (c.bom_ref, c.key_ref, c.sig_ref, c.signed_by) for c in loaded.certificates]
    assert all(c.key_ref for c in loaded.certificates)


def test_duplicate_input_components_accumulate_evidence(tmp_path):
    inv = Inventory(); inv.observe('hash', 'md5', Occurrence('source-py', 'a.py:1', 'one'))
    doc = inv.to_cbom(); duplicate = copy.deepcopy(doc['components'][0])
    duplicate['evidence']['occurrences'][0]['locator'] = 'b.py:2'
    doc['components'].append(duplicate)
    cp = tmp_path / 'c.json'; cp.write_text(json.dumps(doc))
    assert Inventory.load(str(cp)).occurrence_count() == 2


SOURCE_CASES = [
    ('x.py', 'import hashlib\nhashlib.md5(b"x")\n'),
    ('X.java', 'import java.security.MessageDigest; class X { void f() throws Exception { MessageDigest.getInstance("MD5"); } }'),
    ('x.go', 'package x\nimport "crypto/md5"\nfunc f(){ md5.Sum([]byte("x")) }'),
    ('x.rs', 'fn main(){ let h = Md5::new(); }'),
    ('x.c', 'void f(){ EVP_md5(); }'),
]


@pytest.mark.parametrize('filename,content', SOURCE_CASES)
def test_all_five_languages_block_retained_md5(tmp_path, filename, content):
    app = tmp_path / 'app'; app.mkdir(); (app / filename).write_text(content)
    inv = scan(Inventory(), source_dir=str(app))
    pp, _ = make_plan(tmp_path, inv)
    checks = md5_results(verify(tmp_path, pp, inv))
    assert checks and all(r['status'] == 'fail' for r in checks)


def source_setup(tmp_path):
    app = tmp_path / 'app'; app.mkdir()
    (app / 'x.py').write_text('import hashlib\nhashlib.md5(b"x")\n')
    inv = scan(Inventory(), source_dir=str(app))
    pp, doc = make_plan(tmp_path, inv)
    return app, inv, pp, doc


def test_complete_rescan_accepts_removed_literal_and_replacement(tmp_path):
    app, _, pp, _ = source_setup(tmp_path)
    (app / 'x.py').write_text('import hashlib\nhashlib.sha256(b"x")\n')
    fresh = scan(Inventory(), source_dir=str(app))
    results = verify(tmp_path, pp, fresh, phase=None)
    assert results['checked'] == 2
    assert results['passed'] == 2


def test_missing_collector_is_deferred(tmp_path):
    _, _, pp, _ = source_setup(tmp_path)
    checks = md5_results(verify(tmp_path, pp, Inventory()))
    assert checks and all(r['status'] == 'deferred' for r in checks)


@pytest.mark.parametrize('move', ['inside', 'outside'])
def test_moved_file_does_not_pass_by_absence(tmp_path, move):
    app, _, pp, _ = source_setup(tmp_path)
    destination = (app if move == 'inside' else tmp_path) / 'moved.py'
    (app / 'x.py').rename(destination)
    fresh = scan(Inventory(), source_dir=str(app))
    assert all(r['status'] == 'deferred' for r in md5_results(verify(tmp_path, pp, fresh)))


def test_changed_root_does_not_pass(tmp_path):
    _, _, pp, _ = source_setup(tmp_path)
    other = tmp_path / 'other'; other.mkdir(); (other / 'x.py').write_text('x = 1\n')
    fresh = scan(Inventory(), source_dir=str(other))
    assert all(r['status'] == 'deferred' for r in md5_results(verify(tmp_path, pp, fresh)))


def test_changed_detection_queries_do_not_pass(tmp_path):
    app, _, pp, _ = source_setup(tmp_path)
    (app / 'x.py').write_text('x = 1\n')
    fresh = scan(Inventory(), source_dir=str(app))
    next(c for c in fresh.meta['collectors'] if c['name'] == 'source-py')['query_hash'] = 'changed'
    assert all(r['status'] == 'deferred' for r in md5_results(verify(tmp_path, pp, fresh)))


def test_parse_errors_do_not_pass(tmp_path):
    app, _, pp, _ = source_setup(tmp_path)
    (app / 'x.py').write_text('def broken(\n')
    fresh = scan(Inventory(), source_dir=str(app))
    assert all(r['status'] == 'deferred' for r in md5_results(verify(tmp_path, pp, fresh)))


def test_skipped_c_collector_does_not_pass(tmp_path, monkeypatch):
    app = tmp_path / 'app'; app.mkdir(); (app / 'x.c').write_text('void f(){ EVP_md5(); }')
    inv = scan(Inventory(), source_dir=str(app)); pp, _ = make_plan(tmp_path, inv)
    monkeypatch.setattr(source_c._ENGINE, 'available', False)
    monkeypatch.setattr(source_c._ENGINE, '_reason', 'backend unavailable')
    fresh = scan(Inventory(), source_dir=str(app))
    assert all(r['status'] == 'deferred' for r in md5_results(verify(tmp_path, pp, fresh)))


def test_indeterminate_use_blocks_absence_acceptance(tmp_path):
    app, _, pp, _ = source_setup(tmp_path)
    (app / 'x.py').write_text('x = 1\n')
    fresh = scan(Inventory(), source_dir=str(app))
    fresh.observe('hash', 'md5', Occurrence('source-py', str(app/'x.py')+':2', 'unknown', tags=['indeterminate']))
    assert all(r['status'] == 'deferred' for r in md5_results(verify(tmp_path, pp, fresh)))


def test_legacy_plan_with_c_or_rust_md5_fails(tmp_path):
    pp = tmp_path / 'plan.yaml'
    pp.write_text(yaml.safe_dump({'tasks': [{'id':'legacy', 'type':'externalise-algorithm',
        'phase':1, 'target_display':'MD5 [hash]', 'target_algorithm':'md5',
        'acceptance':'source_scan finds no hard-coded algorithm literal for MD5 [hash]'}]}))
    for collector in ('source-c', 'source-rust'):
        inv = Inventory(); inv.observe('hash','md5',Occurrence(collector,'x:1','retained'))
        assert verify(tmp_path, pp, inv)['status_counts']['fail'] == 1
    assert verify(tmp_path, pp, Inventory())['status_counts']['deferred'] == 1


def test_owner_and_file_obligations_are_independent(tmp_path):
    app=tmp_path/'app'; app.mkdir()
    for filename in ('a.py','b.py'):
        (app/filename).write_text('import hashlib\nhashlib.md5(b"x")\n')
    inv=scan(Inventory(), source_dir=str(app), owner_map={'a.py':'team-a','b.py':'team-b'})
    pp, doc=make_plan(tmp_path, inv)
    external=[t for t in doc['tasks'] if t['type']=='externalise-algorithm']
    assert {t['owner'] for t in external} == {'team-a','team-b'}
    assert len(external)==2
    (app/'a.py').write_text('import hashlib\nhashlib.sha256(b"x")\n')
    fresh=scan(Inventory(), source_dir=str(app), owner_map={'a.py':'team-a','b.py':'team-b'})
    outcome={r['id']:r for r in verify(tmp_path,pp,fresh)['results']}
    assert {t['owner']:outcome[t['id']]['status'] for t in external} == {'team-a':'pass','team-b':'fail'}


def test_recipe_matches_primitive_and_capability_evidence():
    for primitive in ('hash','symmetric-cipher','signature','pk-encryption'):
        inv=Inventory(); a=inv.observe(primitive,'legacy',Occurrence('source-py','a.py:1','use'))
        a.exposure_class='quantum_broken'
        types={t.type for t in plan.synthesise_tasks(inv)}
        assert 'enable-hybrid-kex' not in types and 'decommission-legacy' not in types
    inv=Inventory(); a=inv.observe('signature','rsa',Occurrence('sbom','bom#lib','capability'))
    a.exposure_class='quantum_broken'
    assert {t.type for t in plan.synthesise_tasks(inv)} == {'investigate-asset'}


def test_passive_modern_tls_does_not_prove_decommission():
    idx={'tls_versions':{'host:443':{'1.3'}},'tls_groups':{},'literals':set(),'by_algorithm':{}}
    ok,detail=report._eval_predicate({'type':'decommission-legacy'},'tls_endpoint(host:443)',idx,None)
    assert not ok and 'deferred' in detail


def test_revocation_requires_manual_confirmation():
    idx={'tls_versions':{},'tls_groups':{},'literals':set(),'by_algorithm':{},'weak_cert':{}}
    ok,detail=report._eval_predicate({'type':'deploy-and-revoke'},'',idx,None)
    assert not ok and 'manual' in detail


def test_missing_scan_path_rejected(tmp_path):
    with pytest.raises(ValueError, match='does not exist'):
        scan(Inventory(),source_dir=str(tmp_path/'absent'))


def test_malformed_certificate_is_reported(tmp_path):
    (tmp_path/'bad.pem').write_text('not a certificate')
    inv=Inventory(); stats=certs.run(inv,cert_dir=str(tmp_path))
    assert stats['files']==1 and stats['errors'] and stats['certificates']==0


def test_schedule_respects_capacity_far_beyond_reporting_horizon():
    tasks=[plan.Task(id=str(i),type='x',phase=1,target_asset='a',target_display='a',owner='team',duration_months=2) for i in range(40)]
    meta=plan.schedule(tasks,{'default_concurrent':1},1,solver='list')
    assert meta['makespan_months']==80
    intervals=sorted((t.start_month,t.start_month+t.duration_months) for t in tasks)
    assert all(b[0]>=a[1] for a,b in zip(intervals,intervals[1:]))


def test_schedule_same_phase_prerequisites_and_invalid_graphs():
    parent=plan.Task(id='z',type='x',phase=1,target_asset='a',target_display='a',owner='team',duration_months=1)
    child=plan.Task(id='a',type='x',phase=1,target_asset='a',target_display='a',owner='team',duration_months=1,prerequisites=['z'])
    plan.schedule([child,parent],{'default_concurrent':2},4,solver='list')
    assert child.start_month >= parent.start_month+1
    with pytest.raises(ValueError,match='capacity'):
        plan.schedule([parent],{'default_concurrent':0},4,solver='list')
    parent.prerequisites=['a']
    with pytest.raises(ValueError,match='cycle'):
        plan.schedule([parent,child],{'default_concurrent':2},4,solver='list')


def test_manual_prerequisite_prevents_child_acceptance(tmp_path):
    app,_,pp,_=source_setup(tmp_path)
    doc=yaml.safe_load(pp.read_text())
    doc['tasks'].insert(0,{'id':'manual','type':'investigate-asset','phase':0,'acceptance':'manual review'})
    for t in doc['tasks'][1:]:
        if t['type']=='externalise-algorithm':t['prerequisites']=['manual']
    pp.write_text(yaml.safe_dump(doc))
    (app/'x.py').write_text('import hashlib\nhashlib.sha256(b"x")\n')
    result=verify(tmp_path,pp,scan(Inventory(),source_dir=str(app)))
    assert all(r['status']=='deferred' for r in result['results'])


def test_certificate_requirement_uses_actual_floor():
    inv=Inventory(); certs.run(inv,cert_dir=str(ROOT/'testbed/certs'))
    from qramp.model import Certificate
    # Keep just the real 2048-bit fixture and its actual algorithm references.
    cert=next(c for c in inv.certificates if c.locator.endswith('gateway-rsa2048.pem'))
    scoped=Inventory();scoped.add_certificate(cert)
    for key in (cert.key_ref,cert.sig_ref):scoped._assets[key]=inv._assets[key]
    ok,detail=report._check_reissue({'requirement':{'min_key_length':4096}}, {},scoped)
    assert not ok and '4096' in detail


def test_bad_certificate_rescan_is_deferred(tmp_path):
    import shutil
    folder=tmp_path/'certs';folder.mkdir();target=folder/'service.pem'
    shutil.copy(ROOT/'testbed/certs/weak-rsa1024.pem',target)
    inv=Inventory();certs.run(inv,cert_dir=str(folder));pp,_=make_plan(tmp_path,inv)
    target.write_text('invalid replacement certificate')
    fresh=Inventory();certs.run(fresh,cert_dir=str(folder))
    assert all(not r['passed'] for r in verify(tmp_path,pp,fresh,phase=None)['results'])


def test_parameter_change_does_not_hide_retained_hardcoded_algorithm(tmp_path):
    app=tmp_path/'app';app.mkdir();f=app/'x.py'
    template='from cryptography.hazmat.primitives.asymmetric import rsa\nrsa.generate_private_key(public_exponent=65537,key_size={})\n'
    f.write_text(template.format(2048))
    before=scan(Inventory(),source_dir=str(app));pp,_=make_plan(tmp_path,before)
    f.write_text(template.format(1024))
    after=scan(Inventory(),source_dir=str(app))
    checks=verify(tmp_path,pp,after)['results']
    assert checks and all(r['status']=='fail' for r in checks)


def test_new_c_use_is_reported_separately_and_blocks_cli(tmp_path):
    from qramp.cli import main
    app,_,pp,_=source_setup(tmp_path)
    (app/'x.py').write_text('import hashlib\nhashlib.sha256(b"x")\n')
    (app/'new.c').write_text('void f(){ EVP_md5(); }')
    fresh=scan(Inventory(),source_dir=str(app))
    result=verify(tmp_path,pp,fresh,phase=None)
    assert all(r['passed'] for r in result['results'])  # original file was fixed
    assert result['accepted'] is False
    assert any(f['collector']=='source-c' for f in result['unplanned_target_occurrences'])
    assert main(['verify',str(pp),'--against',str(tmp_path/'fresh.json'),
                 '--evidence-out',str(tmp_path/'cli-evidence.json')])==2


def test_empty_phase_selection_cannot_pass(tmp_path):
    _,inv,pp,_=source_setup(tmp_path)
    with pytest.raises(ValueError,match='no tasks match'):
        verify(tmp_path,pp,inv,phase=99)
    pp.write_text(yaml.safe_dump({'tasks': []}))
    assert verify(tmp_path,pp,inv,phase=None)['accepted'] is False


def test_unreadable_configuration_encoding_is_recorded(tmp_path):
    from qramp.collectors import configs
    (tmp_path/'sshd_config').write_bytes(b'\xff\xfe invalid text')
    (tmp_path/'unrelated.bin').write_bytes(b'\xff\xfe')
    inv=Inventory();stats=configs.run(inv,config_dir=str(tmp_path))
    assert len(stats['errors']) == 1 and not stats['scanned_paths']
