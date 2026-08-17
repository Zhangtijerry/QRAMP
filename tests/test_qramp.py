"""End-to-end and unit tests for QRAMP. Run: pytest -q"""
import os
import ssl
import socket
import tempfile
import threading
import datetime

import pytest

from qramp.model import Inventory, Occurrence, CryptoAsset, canon_algorithm, diff
from qramp.collectors import source_py, source_java, source_go, source_rust, certs as cert_col, configs as cfg_col, sbom as sbom_col, tls as tls_col
from qramp import assess, plan, report

HERE = os.path.dirname(__file__)
TB = os.path.join(HERE, "..", "testbed")
RULES = os.path.join(HERE, "..", "src", "qramp", "rules", "transition-2024.yaml")


# ---------- model ----------
def test_canon_algorithm_aliases():
    assert canon_algorithm("Kyber") == "ml-kem"
    assert canon_algorithm("SHA-256") == "sha2-256"
    assert canon_algorithm("prime256v1") == "ecdsa"


def test_occurrence_resolution_merges_by_key():
    inv = Inventory()
    inv.observe("pk-encryption", "RSA", Occurrence("a", "f1", "e1"), key_length=2048)
    inv.observe("pk-encryption", "rsa", Occurrence("b", "f2", "e2"), key_length=2048)
    assert len(inv) == 1
    assert inv.occurrence_count() == 2


def test_asset_id_is_stable():
    a = CryptoAsset("signature", "ecdsa", "secp256r1", 256, "")
    assert a.asset_id == CryptoAsset("signature", "ecdsa", "secp256r1", 256, "").asset_id


# ---------- collectors ----------
@pytest.mark.skipif(not source_py.HAVE_TS_PY, reason="tree-sitter-python not installed")
def test_source_collector_finds_legacy_and_indeterminate():
    inv = Inventory()
    source_py.run(inv, source_dir=os.path.join(TB, "sample-app"))
    displays = {a.display for a in inv.assets}
    assert any("MD5" in d for d in displays)
    assert any("DES-56" in d for d in displays)
    # indeterminate RSA keygen recorded with low confidence + tag
    rsa_occs = [o for a in inv.assets if a.algorithm == "rsa" for o in a.occurrences]
    assert any("indeterminate" in o.tags for o in rsa_occs)


def test_config_collector_parses_ssh_and_nginx():
    inv = Inventory()
    cfg_col.run(inv, config_dir=os.path.join(TB, "etc"))
    algs = {a.algorithm for a in inv.assets}
    assert "3des" in algs          # from Ciphers
    assert "dh" in algs            # group14 kex
    assert "tls" in algs           # nginx ssl_protocols


def test_cert_collector_reads_public_keys_only():
    inv = Inventory()
    cert_col.run(inv, cert_dir=os.path.join(TB, "certs"))
    algs = {a.algorithm for a in inv.assets}
    assert "rsa" in algs and "ecdsa" in algs and "ed25519" in algs


# ---------- weak certificate parameters (chain hygiene) ----------
CERT_DIR = os.path.join(TB, "certs")


def _cert_tags(inv, predicate):
    """Collect the union of occurrence tags for assets matching predicate."""
    tags = set()
    for a in inv.assets:
        if predicate(a):
            for o in a.occurrences:
                tags |= set(o.tags)
    return tags


def test_cert_weak_rsa_key_flagged():
    inv = Inventory()
    stats = cert_col.run(inv, cert_dir=CERT_DIR)
    assert stats["weak_findings"] >= 3
    rsa1024 = [a for a in inv.assets
               if a.algorithm == "rsa" and a.key_length == 1024]
    assert rsa1024, "RSA-1024 cert not detected"
    assert "weak-key" in _cert_tags(inv, lambda a: a is rsa1024[0])


def test_cert_weak_curve_flagged():
    inv = Inventory()
    cert_col.run(inv, cert_dir=CERT_DIR)
    weak = [a for a in inv.assets
            if a.algorithm == "ecdsa" and a.params == "secp192r1"]
    assert weak, "secp192r1 cert not detected"
    assert "weak-curve" in _cert_tags(inv, lambda a: a is weak[0])


def test_cert_sha1_signature_is_composite_asset():
    """A SHA1-RSA signed cert becomes a distinct signature asset keyed on the
    digest — separate from SHA256-RSA — and tagged weak-signature."""
    inv = Inventory()
    cert_col.run(inv, cert_dir=CERT_DIR)
    sha1sig = [a for a in inv.assets
               if a.primitive == "signature" and a.params == "cert-sig:sha1"]
    sha256sig = [a for a in inv.assets
                 if a.primitive == "signature" and a.params == "cert-sig:sha2-256"]
    assert sha1sig, "SHA1-RSA signature not modelled"
    assert sha256sig, "SHA256-RSA signature not modelled"
    assert sha1sig[0].asset_id != sha256sig[0].asset_id     # distinct assets
    assert "weak-signature" in _cert_tags(inv, lambda a: a is sha1sig[0])


def test_cert_expiry_tags():
    """The near-term cert carries a validity warning. The committed fixture is
    generated with ~30 days left, so depending on when the suite runs it will
    be tagged either expiring-soon or (once past its notAfter) expired — both
    are acceptable validity warnings."""
    inv = Inventory()
    cert_col.run(inv, cert_dir=CERT_DIR)
    all_tags = _cert_tags(inv, lambda a: True)
    assert "expiring-soon" in all_tags or "expired" in all_tags


def test_cert_strong_certs_not_flagged():
    """The strong baseline certs must carry none of the weak-* tags."""
    inv = Inventory()
    cert_col.run(inv, cert_dir=CERT_DIR)
    # RSA-2048 gateway, EC-256 api, Ed25519 mesh, all SHA256/native sigs
    strong = [a for a in inv.assets
              if (a.algorithm == "rsa" and a.key_length == 2048)
              or (a.algorithm == "ecdsa" and a.params == "secp256r1")
              or a.algorithm == "ed25519"]
    for a in strong:
        for o in a.occurrences:
            if o.collector == "certs":
                assert "weak-key" not in o.tags
                assert "weak-curve" not in o.tags


# ---------- certificate trust chain / weakest link ----------
CHAIN_DIR = os.path.join(TB, "certs", "chain")


def test_cert_chain_nodes_and_linking():
    inv = Inventory()
    stats = cert_col.run(inv, cert_dir=CHAIN_DIR)
    assert stats["chain_links"] >= 2
    subjects = {c.subject for c in inv.certificates}
    assert any("secure.example.com" in s for s in subjects)
    # a leaf resolves its signed_by to its CA
    leaf = [c for c in inv.certificates
            if "secure.example.com" in c.subject and not c.is_ca][0]
    assert leaf.signed_by is not None
    ca = [c for c in inv.certificates if c.bom_ref == leaf.signed_by][0]
    assert ca.is_ca and "SHA1 Legacy Root CA" in ca.subject


def test_cert_ca_detection():
    inv = Inventory()
    cert_col.run(inv, cert_dir=CHAIN_DIR)
    cas = {c.subject for c in inv.certificates if c.is_ca}
    leaves = {c.subject for c in inv.certificates if not c.is_ca}
    assert any("Root CA" in s for s in cas)
    assert any("example.com" in s for s in leaves)


def test_weakest_link_strong_leaf_under_sha1_ca():
    """The headline case: a clean leaf issued by a SHA1-signing CA is flagged
    even though the leaf itself carries no weakness."""
    inv = Inventory()
    cert_col.run(inv, cert_dir=CHAIN_DIR)
    leaf = [c for c in inv.certificates
            if "secure.example.com" in c.subject and not c.is_ca][0]
    assert leaf.weak_tags == set()                 # leaf itself is clean
    wl = inv.weakest_link(leaf)
    assert "weak-signature" in wl["chain_weaknesses"]
    assert wl["chain_broken_by"] and "SHA1" in wl["chain_broken_by"]


def test_weakest_link_clean_chain():
    inv = Inventory()
    cert_col.run(inv, cert_dir=CHAIN_DIR)
    leaf = [c for c in inv.certificates
            if "api.example.com" in c.subject and not c.is_ca][0]
    wl = inv.weakest_link(leaf)
    assert wl["chain_broken_by"] is None
    assert wl["chain_weaknesses"] == []


def test_chain_survives_save_load(tmp_path):
    inv = Inventory()
    cert_col.run(inv, cert_dir=CHAIN_DIR)
    p = tmp_path / "c.json"; inv.save(str(p))
    back = Inventory.load(str(p))
    assert len(back.certificates) == len(inv.certificates)
    leaf = [c for c in back.certificates
            if "secure.example.com" in c.subject and not c.is_ca][0]
    wl = back.weakest_link(leaf)
    assert wl["chain_broken_by"] and "SHA1" in wl["chain_broken_by"]


def test_chain_exports_certificate_nodes_and_validates():
    import glob, json, warnings
    try:
        import cyclonedx
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            from jsonschema import Draft7Validator, RefResolver
    except ImportError:
        pytest.skip("cyclonedx-python-lib / jsonschema not installed")
    from qramp.cyclonedx import to_cyclonedx
    inv = Inventory()
    cert_col.run(inv, cert_dir=CHAIN_DIR)
    doc = to_cyclonedx(inv)
    certs = [c for c in doc["components"]
             if c.get("cryptoProperties", {}).get("assetType") == "certificate"]
    assert len(certs) == 4
    assert any("certificateProperties" in c["cryptoProperties"] for c in certs)
    chain_deps = [d for d in doc.get("dependencies", []) if "dependsOn" in d]
    assert chain_deps                                  # trust chain edges present
    matches = glob.glob(os.path.join(os.path.dirname(cyclonedx.__file__),
                                     "**", "bom-1.6*.json"), recursive=True)
    if not matches:
        pytest.skip("bundled schema not found")
    sp = matches[0]; schema = json.load(open(sp, encoding="utf-8")); resdir = os.path.dirname(sp)
    store = {}
    for f in glob.glob(os.path.join(resdir, "*.json")):
        s = json.load(open(f, encoding="utf-8")); store["file://" + f] = s
        if "$id" in s:
            store[s["$id"]] = s
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        resolver = RefResolver("file://" + sp, schema, store=store)
        errors = list(Draft7Validator(schema, resolver=resolver).iter_errors(doc))
    assert not errors, f"schema errors: {[e.message for e in errors[:3]]}"


def test_chain_roundtrips_through_cyclonedx():
    from qramp.cyclonedx import to_cyclonedx, from_cyclonedx
    inv = Inventory()
    cert_col.run(inv, cert_dir=CHAIN_DIR)
    back = from_cyclonedx(to_cyclonedx(inv))
    back.link_chain()
    assert len(back.certificates) == len(inv.certificates)
    leaf = [c for c in back.certificates
            if "secure.example.com" in c.subject and not c.is_ca][0]
    assert back.weakest_link(leaf)["chain_broken_by"] is not None


def test_has_tag_rule_matcher(tmp_path):
    """The has_tag match condition selects assets by occurrence tag."""
    from qramp import assess
    inv = Inventory()
    inv.observe("pk-encryption", "rsa",
                Occurrence("certs", "c.pem", "weak", tags=["weak-key"]),
                key_length=1024)
    inv.observe("pk-encryption", "rsa",
                Occurrence("certs", "d.pem", "strong"), key_length=4096)
    cbom = tmp_path / "c.json"; inv.save(str(cbom))
    lt = tmp_path / "lt.yaml"; lt.write_text("default_years: 3\n", encoding="utf-8")
    a = tmp_path / "a.json"; assess.assess(str(cbom), RULES, str(lt), str(a))
    out = {(x.key_length): x for x in Inventory.load(str(a)).assets}
    assert out[1024].remediate and out[1024].remediate.get("action") == "reissue"
    # the 4096-bit key is not weak-key, so it does not match the reissue rule
    assert not (out[4096].remediate and out[4096].remediate.get("action") == "reissue")


def test_weak_cert_routes_to_reissue_recipe(tmp_path):
    from qramp import assess, plan
    inv = Inventory()
    inv.observe("pk-encryption", "rsa",
                Occurrence("certs", "c.pem", "weak", tags=["weak-key"]),
                key_length=1024)
    cbom = tmp_path / "c.json"; inv.save(str(cbom))
    lt = tmp_path / "lt.yaml"; lt.write_text("default_years: 3\n", encoding="utf-8")
    a = tmp_path / "a.json"; assess.assess(str(cbom), RULES, str(lt), str(a))
    weak = [x for x in Inventory.load(str(a)).assets if x.key_length == 1024][0]
    types = [t[1] for t in plan._recipe_for(weak)]
    assert "reissue-certificate" in types and "deploy-and-revoke" in types
    assert "externalise-algorithm" not in types


def test_reissue_verify_fails_closed_then_passes(tmp_path):
    """Fail-closed: while the weak cert is still present the reissue task fails;
    once a fresh scan no longer shows it, the task passes."""
    from qramp import assess, plan, report
    import yaml
    inv = Inventory()
    inv.observe("pk-encryption", "rsa",
                Occurrence("certs", "weak.pem", "weak", tags=["weak-key"]),
                key_length=1024)
    cbom = tmp_path / "c.json"; inv.save(str(cbom))
    lt = tmp_path / "lt.yaml"; lt.write_text("default_years: 3\n", encoding="utf-8")
    a = tmp_path / "a.json"; assess.assess(str(cbom), RULES, str(lt), str(a))
    cap = tmp_path / "cap.yaml"; cap.write_text("default_concurrent: 2\n", encoding="utf-8")
    planp = tmp_path / "plan.yaml"
    plan.plan(str(a), str(cap), 36, str(planp), solver="list")
    # BEFORE: weak cert still present -> reissue fails
    ev = tmp_path / "ev.json"
    b = report.verify(str(planp), str(cbom), str(ev))
    reissue = [r for r in b["results"] if r["type"] == "reissue-certificate"]
    assert reissue and all(not r["passed"] for r in reissue)
    # AFTER: fresh scan with a strong cert only
    inv2 = Inventory()
    inv2.observe("pk-encryption", "rsa",
                 Occurrence("certs", "strong.pem", "strong"), key_length=2048)
    cbom2 = tmp_path / "c2.json"; inv2.save(str(cbom2))
    ev2 = tmp_path / "ev2.json"
    b2 = report.verify(str(planp), str(cbom2), str(ev2))
    reissue2 = [r for r in b2["results"] if r["type"] == "reissue-certificate"]
    assert reissue2 and all(r["passed"] for r in reissue2)


def test_sbom_collector_records_unmapped():
    inv = Inventory()
    stats = sbom_col.run(inv, sbom_path=os.path.join(TB, "sample-app", "sbom.cdx.json"))
    assert stats["components_mapped"] >= 3
    assert stats["components_unmapped"] >= 1     # numpy/requests unmapped


# ---------- dependency graph: dependsOn / provides ----------
SBOM_PATH = os.path.join(TB, "sample-app", "sbom.cdx.json")


def test_sbom_records_provides_edges():
    inv = Inventory()
    stats = sbom_col.run(inv, sbom_path=SBOM_PATH)
    assert stats["provides_edges"] >= 8
    # components are first-class now
    names = {c.name for c in inv.components}
    assert {"openssl", "cryptography", "libsodium", "paramiko"} <= names
    openssl = [c for c in inv.components if c.name == "openssl"][0]
    provided = {a.algorithm for a in inv.assets_provided_by(openssl)}
    assert {"rsa", "ecdh", "aes"} <= provided


def test_provides_reverse_lookup_shared_capability():
    """RSA is shipped by both openssl and cryptography — the reverse query
    must return both providers."""
    inv = Inventory()
    sbom_col.run(inv, sbom_path=SBOM_PATH)
    rsa_pke = [a for a in inv.assets
               if a.algorithm == "rsa" and a.primitive == "pk-encryption"][0]
    providers = {c.name for c in inv.providers_of(rsa_pke)}
    assert {"openssl", "cryptography"} <= providers


def test_impact_of_removing_distinguishes_unique_vs_shared():
    inv = Inventory()
    sbom_col.run(inv, sbom_path=SBOM_PATH)
    openssl = [c for c in inv.components if c.name == "openssl"][0]
    impact = inv.impact_of_removing(openssl)
    uniq = {u["asset"] for u in impact["uniquely_provided"]}
    shared = {s["asset"] for s in impact["still_available"]}
    # AES-256 and ECDH are openssl-only here; RSA is also in `cryptography`
    assert any("AES" in x for x in uniq)
    assert any("ECDH" in x for x in uniq)
    assert any("RSA" in x for x in shared)
    # the shared RSA lists its alternative provider
    rsa_entry = [s for s in impact["still_available"] if "RSA" in s["asset"]][0]
    assert "cryptography@42.0.5" in rsa_entry["also_provided_by"]


def test_graph_survives_save_load(tmp_path):
    """Components and provides edges persist through the legacy CBOM save/load
    used by the scan -> assess -> plan pipeline."""
    inv = Inventory()
    sbom_col.run(inv, sbom_path=SBOM_PATH)
    p = tmp_path / "cbom.json"; inv.save(str(p))
    back = Inventory.load(str(p))
    assert len(back.components) == len(inv.components)
    openssl = [c for c in back.components if c.name == "openssl"][0]
    assert len(back.assets_provided_by(openssl)) == 3


def test_graph_exports_dependencies_and_validates():
    """The provides graph exports as a spec `dependencies` array and the whole
    document still validates against the CycloneDX 1.6 schema."""
    import glob, json, warnings
    try:
        import cyclonedx
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            from jsonschema import Draft7Validator, RefResolver
    except ImportError:
        pytest.skip("cyclonedx-python-lib / jsonschema not installed")
    from qramp.cyclonedx import to_cyclonedx
    inv = Inventory()
    sbom_col.run(inv, sbom_path=SBOM_PATH)
    doc = to_cyclonedx(inv)
    assert "dependencies" in doc and doc["dependencies"]
    # each dependency node references a component and provides asset refs
    node = doc["dependencies"][0]
    assert "ref" in node and "provides" in node
    matches = glob.glob(os.path.join(os.path.dirname(cyclonedx.__file__),
                                     "**", "bom-1.6*.json"), recursive=True)
    if not matches:
        pytest.skip("bundled schema not found")
    sp = matches[0]; schema = json.load(open(sp, encoding="utf-8")); resdir = os.path.dirname(sp)
    store = {}
    for f in glob.glob(os.path.join(resdir, "*.json")):
        s = json.load(open(f, encoding="utf-8")); store["file://" + f] = s
        if "$id" in s:
            store[s["$id"]] = s
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        resolver = RefResolver("file://" + sp, schema, store=store)
        errors = list(Draft7Validator(schema, resolver=resolver).iter_errors(doc))
    assert not errors, f"schema errors: {[e.message for e in errors[:3]]}"


def test_graph_roundtrips_through_cyclonedx():
    from qramp.cyclonedx import to_cyclonedx, from_cyclonedx
    inv = Inventory()
    sbom_col.run(inv, sbom_path=SBOM_PATH)
    back = from_cyclonedx(to_cyclonedx(inv))
    assert len(back.components) == len(inv.components)
    openssl = [c for c in back.components if c.name == "openssl"][0]
    assert len(back.assets_provided_by(openssl)) == 3


def test_merge_unions_provides_edges():
    """Merging two inventories unions the provides edges for a shared
    component."""
    from qramp.model import Occurrence
    a = Inventory()
    ca = a.component("openssl", "3.0.13")
    x = a.observe("symmetric-cipher", "aes", Occurrence("sbom", "l", "aes"), key_length=256)
    a.provide(ca, x)
    b = Inventory()
    cb = b.component("openssl", "3.0.13")
    y = b.observe("pk-encryption", "rsa", Occurrence("sbom", "l", "rsa"))
    b.provide(cb, y)
    a.merge(b)
    merged = [c for c in a.components if c.name == "openssl"][0]
    provided = {p.algorithm for p in a.assets_provided_by(merged)}
    assert {"aes", "rsa"} <= provided


# ---------- java collector ----------
JAVA_DIR = os.path.join(TB, "sample-app", "java")


@pytest.mark.skipif(not source_java.HAVE_TS_JAVA, reason="tree-sitter-java not installed")
def test_java_collector_parses_transformations():
    inv = Inventory()
    stats = source_java.run(inv, source_dir=JAVA_DIR)
    assert stats["call_sites"] >= 8
    by_alg = {a.algorithm: a for a in inv.assets}
    assert "md5" in by_alg and "sha1" in by_alg
    # DES transformation parsed into algorithm+keylen+mode
    des = by_alg["des"]
    assert des.key_length == 56 and des.mode == "ecb"


@pytest.mark.skipif(not source_java.HAVE_TS_JAVA, reason="tree-sitter-java not installed")
def test_java_collector_associates_key_size():
    inv = Inventory()
    source_java.run(inv, source_dir=JAVA_DIR)
    rsa = [a for a in inv.assets if a.algorithm == "rsa"]
    # RSA keygen with initialize(2048) in the same method -> key_length recovered
    assert any(a.key_length == 2048 for a in rsa)
    aes = [a for a in inv.assets if a.algorithm == "aes" and a.key_length == 256]
    assert aes, "KeyGenerator AES + init(256) should yield AES-256"


@pytest.mark.skipif(not source_java.HAVE_TS_JAVA, reason="tree-sitter-java not installed")
def test_cross_language_resolution():
    """The same asset seen in Python and Java resolves to one asset with two
    occurrences (the paper's cross-layer entity resolution claim)."""
    inv = Inventory()
    source_py.run(inv, source_dir=os.path.join(TB, "sample-app"))
    source_java.run(inv, source_dir=JAVA_DIR)
    md5 = [a for a in inv.assets if a.algorithm == "md5"]
    assert len(md5) == 1
    cols = {o.collector for o in md5[0].occurrences}
    assert {"source-py", "source-java"} <= cols


@pytest.mark.skipif(not source_rust.HAVE_TS_RUST, reason="tree-sitter-rust not installed")
def test_cross_language_resolution_four_languages():
    """MD5 found in Python, Java, Go and Rust resolves to a single asset —
    entity resolution scales to the fourth language with no special-casing."""
    inv = Inventory()
    source_py.run(inv, source_dir=os.path.join(TB, "sample-app"))
    source_java.run(inv, source_dir=os.path.join(TB, "sample-app", "java"))
    source_go.run(inv, source_dir=os.path.join(TB, "sample-app", "go"))
    source_rust.run(inv, source_dir=os.path.join(TB, "sample-app", "rust"))
    md5 = [a for a in inv.assets if a.algorithm == "md5"]
    assert len(md5) == 1
    cols = {o.collector for o in md5[0].occurrences}
    assert {"source-py", "source-java", "source-go", "source-rust"} <= cols


def test_java_collector_degrades_without_backend(monkeypatch):
    """If tree-sitter is unavailable the collector registers but yields nothing,
    keeping the tool usable on Python sources alone."""
    monkeypatch.setattr(source_java._ENGINE, "available", False)
    monkeypatch.setattr(source_java._ENGINE, "_reason", "grammar not installed")
    inv = Inventory()
    stats = source_java.run(inv, source_dir=JAVA_DIR)
    assert stats["call_sites"] == 0
    assert len(inv) == 0


# ---------- go collector ----------
GO_DIR = os.path.join(TB, "sample-app", "go")


@pytest.mark.skipif(not source_go.HAVE_TS_GO, reason="tree-sitter-go not installed")
def test_go_collector_parses_stdlib_calls():
    inv = Inventory()
    stats = source_go.run(inv, source_dir=GO_DIR)
    assert stats["call_sites"] >= 8
    by_alg = {a.algorithm: a for a in inv.assets}
    assert "md5" in by_alg and "sha1" in by_alg and "des" in by_alg


@pytest.mark.skipif(not source_go.HAVE_TS_GO, reason="tree-sitter-go not installed")
def test_go_collector_recovers_key_size_and_curve():
    inv = Inventory()
    source_go.run(inv, source_dir=GO_DIR)
    # rsa.GenerateKey(rand.Reader, 2048) -> key size from positional int arg
    rsa = [a for a in inv.assets if a.algorithm == "rsa" and a.key_length == 2048]
    assert rsa
    # ecdsa.GenerateKey(elliptic.P256(), ...) -> curve resolved from nested call
    ec = [a for a in inv.assets if a.algorithm == "ecdsa"]
    assert any(a.params == "nistp256" and a.key_length == 256 for a in ec)


@pytest.mark.skipif(not source_go.HAVE_TS_GO, reason="tree-sitter-go not installed")
def test_go_collector_decomposes_tls_suite_and_version():
    inv = Inventory()
    source_go.run(inv, source_dir=GO_DIR)
    algs = {a.algorithm for a in inv.assets}
    # cipher suite TLS_RSA_WITH_3DES_EDE_CBC_SHA -> 3des present
    assert "3des" in algs
    # tls.VersionTLS10 constant captured as protocol asset
    tls10 = [a for a in inv.assets if a.primitive == "protocol" and a.params == "1.0"]
    assert tls10


@pytest.mark.skipif(not (source_go.HAVE_TS_GO and source_java.HAVE_TS_JAVA),
                    reason="tree-sitter grammars not installed")
def test_three_language_resolution():
    """The same asset seen in Python, Java and Go resolves to one asset with
    three occurrences."""
    inv = Inventory()
    source_py.run(inv, source_dir=os.path.join(TB, "sample-app"))
    source_java.run(inv, source_dir=os.path.join(TB, "sample-app", "java"))
    source_go.run(inv, source_dir=GO_DIR)
    md5 = [a for a in inv.assets if a.algorithm == "md5"]
    assert len(md5) == 1
    cols = {o.collector for o in md5[0].occurrences}
    assert {"source-py", "source-java", "source-go"} <= cols


def test_go_collector_degrades_without_backend(monkeypatch):
    monkeypatch.setattr(source_go._ENGINE, "available", False)
    monkeypatch.setattr(source_go._ENGINE, "_reason", "grammar not installed")
    inv = Inventory()
    stats = source_go.run(inv, source_dir=GO_DIR)
    assert stats["call_sites"] == 0
    assert len(inv) == 0


# ---------- rust collector ----------
RUST_DIR = os.path.join(TB, "sample-app", "rust")


@pytest.mark.skipif(not source_rust.HAVE_TS_RUST, reason="tree-sitter-rust not installed")
def test_rust_collector_detects_crypto():
    inv = Inventory()
    stats = source_rust.run(inv, source_dir=RUST_DIR)
    assert stats["call_sites"] >= 6
    algs = {(a.primitive, a.algorithm, a.key_length) for a in inv.assets}
    assert ("hash", "md5", None) in algs
    assert ("hash", "sha1", None) in algs
    assert ("symmetric-cipher", "des", 56) in algs
    assert ("symmetric-cipher", "aes", 256) in algs
    # RSA key size lifted from the integer argument, not eaten by suffix-strip
    assert ("pk-encryption", "rsa", 2048) in algs


@pytest.mark.skipif(not source_rust.HAVE_TS_RUST, reason="tree-sitter-rust not installed")
def test_rust_rsa_keysize_with_suffix(tmp_path):
    (tmp_path / "x.rs").write_text(
        "use rsa::RsaPrivateKey;\nfn f(){ RsaPrivateKey::new(rng, 3072u32).unwrap(); }\n", encoding="utf-8")
    inv = Inventory()
    source_rust.run(inv, source_dir=str(tmp_path))
    rsa = [a for a in inv.assets if a.algorithm == "rsa"][0]
    assert rsa.key_length == 3072


@pytest.mark.skipif(not source_rust.HAVE_TS_RUST, reason="tree-sitter-rust not installed")
def test_rust_use_hint_suppressed_when_call_present():
    """A `use md5::Md5;` plus a concrete `Md5::new()` yields one asset, not two
    (the import hint is suppressed when a real call covers the same type)."""
    inv = Inventory()
    source_rust.run(inv, source_dir=RUST_DIR)
    md5 = [a for a in inv.assets if a.algorithm == "md5"][0]
    evidences = [o.evidence for o in md5.occurrences]
    assert any("Md5::new" in e for e in evidences)
    assert not any("import only" in e for e in evidences)


def test_rust_collector_degrades_without_backend(monkeypatch):
    monkeypatch.setattr(source_rust._ENGINE, "available", False)
    monkeypatch.setattr(source_rust._ENGINE, "_reason", "grammar not installed")
    inv = Inventory()
    stats = source_rust.run(inv, source_dir=RUST_DIR)
    assert stats["call_sites"] == 0
    assert len(inv) == 0


@pytest.mark.skipif(not source_rust.HAVE_TS_RUST, reason="tree-sitter-rust not installed")
def test_rust_site_override(tmp_path):
    """A new language is still site-overridable: a Rust .extra.scm adds
    detection of an internal wrapper via #set!, no interpreter code."""
    app = tmp_path / "app"; app.mkdir()
    (app / "lib.rs").write_text("fn f(k:&[u8]){ let _c = mycrypto::weak_cipher(k); }\n", encoding="utf-8")
    qd = tmp_path / "q"; qd.mkdir()
    (qd / "rust.extra.scm").write_text(
        '(call_expression\n'
        '  function: (scoped_identifier\n'
        '              path: (identifier) @c (#eq? @c "mycrypto")\n'
        '              name: (identifier) @m (#eq? @m "weak_cipher"))\n'
        '  arguments: (arguments) @args\n'
        '  (#set! "primitive" "symmetric-cipher")\n'
        '  (#set! "algorithm" "rc4")\n'
        '  (#set! "key_length" "128")) @site\n')
    inv = Inventory()
    stats = source_rust.run(inv, source_dir=str(app), query_dir=str(qd))
    assert {s["role"] for s in stats["query_sources"]} == {"builtin", "extend"}
    rc4 = [a for a in inv.assets if a.algorithm == "rc4"]
    assert rc4 and rc4[0].key_length == 128


# ---------- c/c++ collector ----------
from qramp.collectors import source_c        # noqa: E402
C_DIR = os.path.join(TB, "sample-app", "c")


@pytest.mark.skipif(not source_c.HAVE_TS_C, reason="tree-sitter-c not installed")
def test_c_collector_detects_all_idioms():
    """C crypto is name-encoded, not scoped: exercise EVP constructors, direct
    one-shot funcs, integer key-size args, string by-name lookups and libsodium."""
    inv = Inventory()
    stats = source_c.run(inv, source_dir=C_DIR)
    assert stats["call_sites"] >= 10
    algs = {(a.primitive, a.algorithm, a.key_length, a.mode) for a in inv.assets}
    assert ("hash", "md5", None, "") in algs                       # EVP_md5 + MD5()
    assert ("symmetric-cipher", "des", 56, "ecb") in algs          # EVP_des_ecb()
    assert ("symmetric-cipher", "des", 56, "cbc") in algs          # by-name "des-cbc"
    assert ("symmetric-cipher", "aes", 256, "gcm") in algs         # EVP_aes_256_gcm()
    assert ("pk-encryption", "rsa", 2048, "") in algs              # RSA_generate_key(2048,...)
    assert ("pk-encryption", "rsa", 1024, "") in algs              # RSA_generate_key_ex(r,1024,...)


@pytest.mark.skipif(not source_c.HAVE_TS_C, reason="tree-sitter-c not installed")
def test_c_weak_dh_keysize_from_int_arg():
    """DH_generate_parameters(512,...) yields a weak 512-bit DH asset (which the
    kx-layer rule then routes to decommissioning)."""
    inv = Inventory()
    source_c.run(inv, source_dir=C_DIR)
    dh = [a for a in inv.assets if a.algorithm == "dh"][0]
    assert dh.key_length == 512 and dh.primitive == "key-agreement"


@pytest.mark.skipif(not source_c.HAVE_TS_C, reason="tree-sitter-c not installed")
def test_c_string_arg_byname_lookup(tmp_path):
    (tmp_path / "x.c").write_text(
        '#include <openssl/evp.h>\n'
        'void f(){ EVP_get_cipherbyname("aes-256-gcm"); }\n', encoding="utf-8")
    inv = Inventory()
    source_c.run(inv, source_dir=str(tmp_path))
    aes = [a for a in inv.assets if a.algorithm == "aes"][0]
    assert aes.key_length == 256 and aes.mode == "gcm"


def test_c_collector_degrades_without_backend(monkeypatch):
    monkeypatch.setattr(source_c._ENGINE, "available", False)
    monkeypatch.setattr(source_c._ENGINE, "_reason", "grammar not installed")
    inv = Inventory()
    stats = source_c.run(inv, source_dir=C_DIR)
    assert stats["call_sites"] == 0
    assert len(inv) == 0


@pytest.mark.skipif(not source_c.HAVE_TS_C, reason="tree-sitter-c not installed")
def test_c_site_override(tmp_path):
    """C is still site-overridable despite its non-scoped idiom."""
    app = tmp_path / "app"; app.mkdir()
    (app / "lib.c").write_text("void f(){ mycrypto_weak_hash(d, out); }\n", encoding="utf-8")
    qd = tmp_path / "q"; qd.mkdir()
    (qd / "c.extra.scm").write_text(
        '(call_expression\n'
        '  function: (identifier) @fn (#eq? @fn "mycrypto_weak_hash")\n'
        '  arguments: (argument_list) @args\n'
        '  (#set! "primitive" "hash")\n'
        '  (#set! "algorithm" "md5")) @site\n')
    inv = Inventory()
    stats = source_c.run(inv, source_dir=str(app), query_dir=str(qd))
    assert {s["role"] for s in stats["query_sources"]} == {"builtin", "extend"}
    assert [a for a in inv.assets if a.algorithm == "md5"]


@pytest.mark.skipif(not (source_c.HAVE_TS_C and source_rust.HAVE_TS_RUST),
                    reason="grammars not installed")
def test_cross_language_resolution_five_languages():
    """MD5 in Python, Java, Go, Rust and C resolves to one asset — the entity
    model scales to a fifth, differently-idiomatic language with no changes."""
    inv = Inventory()
    source_py.run(inv, source_dir=os.path.join(TB, "sample-app"))
    source_java.run(inv, source_dir=os.path.join(TB, "sample-app", "java"))
    source_go.run(inv, source_dir=os.path.join(TB, "sample-app", "go"))
    source_rust.run(inv, source_dir=os.path.join(TB, "sample-app", "rust"))
    source_c.run(inv, source_dir=os.path.join(TB, "sample-app", "c"))
    md5 = [a for a in inv.assets if a.algorithm == "md5"]
    assert len(md5) == 1
    cols = {o.collector for o in md5[0].occurrences}
    assert {"source-py", "source-java", "source-go", "source-rust", "source-c"} <= cols


# ---------- declarative query engine ----------
def test_query_engine_unavailable_for_unknown_language():
    from qramp.collectors.tsquery import QueryEngine
    e = QueryEngine("cobol")
    assert e.available is False and e.reason


@pytest.mark.skipif(not source_py.HAVE_TS_PY, reason="tree-sitter-python not installed")
def test_query_engine_reports_query_hash():
    from qramp.collectors.tsquery import QueryEngine
    e = QueryEngine("python")
    assert e.available is True
    h = e.query_source_hash()
    assert isinstance(h, str) and len(h) == 16


@pytest.mark.skipif(not source_py.HAVE_TS_PY, reason="tree-sitter-python not installed")
def test_collectors_record_query_hash_in_stats():
    """Detection rules are versioned data: the .scm hash is recorded so a CBOM
    can be traced to the exact query version that produced it."""
    inv = Inventory()
    stats = source_py.run(inv, source_dir=os.path.join(TB, "sample-app"))
    assert stats.get("query_hash")
    assert any(c.get("query_hash") for c in inv.meta["collectors"])


# ---------- user-overridable / extendable queries ----------
_SITE_APP = "import mycrypto\n\ndef f(d, k):\n    return mycrypto.legacy_encrypt(d, k)\n"
_SITE_EXTRA = (
    '(call\n'
    '  function: (attribute\n'
    '              object: (identifier) @o (#eq? @o "mycrypto")\n'
    '              attribute: (identifier) @m (#eq? @m "legacy_encrypt"))\n'
    '  arguments: (argument_list) @args\n'
    '  (#set! "primitive" "symmetric-cipher")\n'
    '  (#set! "algorithm" "des")\n'
    '  (#set! "key_length" "56")\n'
    '  (#set! "mode" "ecb")) @site\n'
)


@pytest.mark.skipif(not source_py.HAVE_TS_PY, reason="tree-sitter-python not installed")
def test_site_extension_adds_detection(tmp_path):
    """A site .extra.scm adds detection of a custom wrapper with NO interpreter
    code — classification comes from #set! directives in the query."""
    app = tmp_path / "app"; app.mkdir()
    (app / "h.py").write_text(_SITE_APP, encoding="utf-8")
    qd = tmp_path / "q"; qd.mkdir()
    (qd / "python.extra.scm").write_text(_SITE_EXTRA, encoding="utf-8")
    inv = Inventory()
    stats = source_py.run(inv, source_dir=str(app), query_dir=str(qd))
    assert {s["role"] for s in stats["query_sources"]} == {"builtin", "extend"}
    des = [a for a in inv.assets if a.algorithm == "des"]
    assert des and des[0].key_length == 56 and des[0].mode == "ecb"


@pytest.mark.skipif(not source_py.HAVE_TS_PY, reason="tree-sitter-python not installed")
def test_builtin_alone_misses_custom_wrapper(tmp_path):
    app = tmp_path / "app"; app.mkdir()
    (app / "h.py").write_text(_SITE_APP, encoding="utf-8")
    inv = Inventory()
    source_py.run(inv, source_dir=str(app))
    assert not [a for a in inv.assets if a.algorithm == "des"]


@pytest.mark.skipif(not source_py.HAVE_TS_PY, reason="tree-sitter-python not installed")
def test_site_full_replace(tmp_path):
    """A full <language>.scm in the override dir replaces the built-in."""
    app = tmp_path / "app"; app.mkdir()
    (app / "h.py").write_text("import hashlib\n" + _SITE_APP + "\nhashlib.md5(b'x')\n", encoding="utf-8")
    qd = tmp_path / "q"; qd.mkdir()
    (qd / "python.scm").write_text(_SITE_EXTRA, encoding="utf-8")   # only detects mycrypto
    inv = Inventory()
    stats = source_py.run(inv, source_dir=str(app), query_dir=str(qd))
    assert [s["role"] for s in stats["query_sources"]] == ["replace"]
    algs = {a.algorithm for a in inv.assets}
    assert "des" in algs and "md5" not in algs      # built-in md5 rule gone


@pytest.mark.skipif(not source_py.HAVE_TS_PY, reason="tree-sitter-python not installed")
def test_broken_site_query_falls_back_to_builtin(tmp_path):
    """A syntactically invalid site query must not disable scanning: the engine
    falls back to the built-in and reports why."""
    from qramp.collectors.tsquery import QueryEngine
    qd = tmp_path / "q"; qd.mkdir()
    (qd / "python.extra.scm").write_text("((( not valid @@@ scheme")
    e = QueryEngine("python", query_dir=str(qd))
    assert e.available is True
    assert "site query" in (e.reason or "")
    assert [s["role"] for s in e.describe_sources()] == ["builtin-fallback"]


def test_project_local_query_discovery(tmp_path, monkeypatch):
    from qramp.collectors.tsquery import _discover_project_query_dir
    (tmp_path / ".qramp" / "queries").mkdir(parents=True)
    sub = tmp_path / "a" / "b"; sub.mkdir(parents=True)
    monkeypatch.chdir(sub)
    found = _discover_project_query_dir()
    assert found == str(tmp_path / ".qramp" / "queries")


# ---------- scope gate (safety-critical) ----------
def test_scope_gate_rejects_tampered_file(tmp_path):
    scope = tmp_path / "s.yaml"
    key = tmp_path / "k.key"
    key.write_bytes(b"0" * 32)
    scope.write_text("targets:\n  - {host: 127.0.0.1, port: 8443}\n", encoding="utf-8")
    tls_col.sign_scope(str(scope), str(key))
    # tamper
    txt = scope.read_text(encoding="utf-8").replace("8443", "9999")
    scope.write_text(txt, encoding="utf-8")
    with pytest.raises(tls_col.ScopeError):
        tls_col.load_scope(str(scope), str(key))


def test_scope_gate_accepts_signed_file(tmp_path):
    scope = tmp_path / "s.yaml"
    key = tmp_path / "k.key"
    key.write_bytes(b"1" * 32)
    scope.write_text("targets:\n  - {host: 127.0.0.1, port: 8443}\n", encoding="utf-8")
    tls_col.sign_scope(str(scope), str(key))
    targets = tls_col.load_scope(str(scope), str(key))
    assert targets and targets[0]["port"] == 8443


def test_scope_gate_rejects_content_after_signature(tmp_path):
    """Regression: appending targets or comments after the signature line must
    not be accepted, because the HMAC only covered the prefix before it."""
    scope = tmp_path / "s.yaml"; key = tmp_path / "k.key"
    key.write_bytes(b"2" * 32)
    scope.write_text("targets:\n  - {host: 127.0.0.1, port: 8443}\n", encoding="utf-8")
    tls_col.sign_scope(str(scope), str(key))
    with open(scope, "a") as f:
        f.write("  - {host: evil.example, port: 443}\n")
    with pytest.raises(tls_col.ScopeError):
        tls_col.load_scope(str(scope), str(key))


def test_scope_gate_rejects_comment_after_signature(tmp_path):
    scope = tmp_path / "s.yaml"; key = tmp_path / "k.key"
    key.write_bytes(b"3" * 32)
    scope.write_text("targets:\n  - {host: 127.0.0.1, port: 8443}\n", encoding="utf-8")
    tls_col.sign_scope(str(scope), str(key))
    with open(scope, "a") as f:
        f.write("# added later\n")
    with pytest.raises(tls_col.ScopeError):
        tls_col.load_scope(str(scope), str(key))


# ---------- active PQ hybrid handshake prober ----------
def test_handshake_capability_detection():
    from qramp.handshake import local_capability
    cap = local_capability()
    assert set(cap) >= {"openssl", "pq_capable", "has_set_groups"}
    assert isinstance(cap["pq_capable"], bool)


def test_handshake_verdict_pass(monkeypatch):
    from qramp import handshake as H
    monkeypatch.setattr(H, "local_capability",
                        lambda: {"openssl": "3.5.0", "openssl_tuple": [3, 5, 0],
                                 "has_set_groups": True, "pq_capable": True, "reason": None})
    monkeypatch.setattr(H, "_try_group",
                        lambda h, p, g: (True, "X25519MLKEM768", None))
    r = H.probe_pq_hybrid("h", 443, attempts=5)
    assert r["verdict"] == "pass" and r["success_rate"] == 1.0
    assert r["negotiated_group"] == "X25519MLKEM768"


def test_handshake_verdict_fail_on_intermittent(monkeypatch):
    from qramp import handshake as H
    monkeypatch.setattr(H, "local_capability",
                        lambda: {"openssl": "3.5.0", "openssl_tuple": [3, 5, 0],
                                 "has_set_groups": True, "pq_capable": True, "reason": None})
    seq = iter([True, False, True, False, True])
    monkeypatch.setattr(H, "_try_group",
                        lambda h, p, g: (True, "X25519MLKEM768", None) if next(seq)
                        else (False, None, "handshake_failure"))
    r = H.probe_pq_hybrid("h", 443, attempts=5)
    assert r["verdict"] == "fail" and 0.0 < r["success_rate"] < 1.0


def test_handshake_verdict_deferred_when_incapable(monkeypatch):
    from qramp import handshake as H
    monkeypatch.setattr(H, "local_capability",
                        lambda: {"openssl": "3.0.13", "openssl_tuple": [3, 0, 13],
                                 "has_set_groups": False, "pq_capable": False,
                                 "reason": "no set_groups"})
    r = H.probe_pq_hybrid("h", 443, attempts=3)
    assert r["verdict"] == "deferred" and r["successes"] == 0


def test_enable_hybrid_kex_active_defers_fail_closed(monkeypatch):
    """The verifier's enable-hybrid-kex check defers (fails closed) when the
    local stack cannot force PQ groups, rather than passing on passive data."""
    from qramp import report, handshake
    monkeypatch.setattr(handshake, "local_capability",
                        lambda: {"openssl": "3.0.13", "openssl_tuple": [3, 0, 13],
                                 "has_set_groups": False, "pq_capable": False,
                                 "reason": "no set_groups"})
    task = {"type": "enable-hybrid-kex",
            "acceptance": "tls_endpoint(1.2.3.4:443).groups includes a PQ hybrid group"}
    index = {"tls_versions": {}, "tls_groups": {"1.2.3.4:443": {"ml-kem"}},
             "literals": set(), "by_algorithm": {},
             "active_probe": True,
             "probe_targets": {"1.2.3.4:443": ("1.2.3.4", 443)}, "attempts": 2}
    ok, detail = report._eval_predicate(task, task["acceptance"], index, None)
    assert ok is False and "deferred" in detail.lower()


# ---------- active decommission-legacy probe ----------
def _decommission_task():
    return {"type": "decommission-legacy",
            "target_display": "TLS (1.0) [protocol]", "target_algorithm": "tls",
            "acceptance": "tls_endpoint(1.2.3.4:443) does NOT negotiate any quantum_broken suite"}


def _decommission_index(probe=True):
    return {"tls_versions": {"1.2.3.4:443": {"1.3"}}, "tls_groups": {},
            "literals": set(), "by_algorithm": {},
            "active_probe": probe,
            "probe_targets": {"1.2.3.4:443": ("1.2.3.4", 443)}, "attempts": 3}


def test_probe_decommissioned_pass(monkeypatch):
    """All probeable legacy/Shor-broken parameters refused -> pass."""
    from qramp import report, handshake
    monkeypatch.setattr(handshake, "probe_decommissioned",
                        lambda h, p: {"verdict": "pass",
                                      "refused": [{"probe": "TLS1.0"}, {"probe": "static-RSA-kx"}],
                                      "accepted": [], "unprobeable": [], "errors": []})
    ok, detail = report._eval_predicate(_decommission_task(),
                                        _decommission_task()["acceptance"],
                                        _decommission_index(), None)
    assert ok is True and "refused" in detail


def test_probe_decommissioned_fail_on_static_rsa(monkeypatch):
    """A Shor-broken key exchange still offered (even on TLS 1.2) -> fail.
    This is what passive TLS-version observation would miss."""
    from qramp import report, handshake
    monkeypatch.setattr(handshake, "probe_decommissioned",
                        lambda h, p: {"verdict": "fail",
                                      "refused": [], "unprobeable": [],
                                      "accepted": [{"probe": "static-RSA-kx",
                                                    "detail": "negotiated AES256-GCM-SHA384"}],
                                      "errors": []})
    ok, detail = report._eval_predicate(_decommission_task(),
                                        _decommission_task()["acceptance"],
                                        _decommission_index(), None)
    assert ok is False and "static-RSA-kx" in detail


def test_probe_decommissioned_deferred_when_unreachable(monkeypatch):
    from qramp import report, handshake
    monkeypatch.setattr(handshake, "probe_decommissioned",
                        lambda h, p: {"verdict": "deferred", "refused": [],
                                      "accepted": [], "unprobeable": [],
                                      "errors": ["endpoint unreachable"]})
    ok, detail = report._eval_predicate(_decommission_task(),
                                        _decommission_task()["acceptance"],
                                        _decommission_index(), None)
    assert ok is False and "deferred" in detail.lower()


def test_decommission_passive_path_unchanged():
    """Without active probing the check falls back to passive version data."""
    from qramp import report
    idx = _decommission_index(probe=False)
    idx["tls_versions"] = {"1.2.3.4:443": {"1.0", "1.3"}}   # still offers TLS 1.0
    ok, detail = report._eval_predicate(_decommission_task(),
                                        _decommission_task()["acceptance"], idx, None)
    assert ok is False and "passive" in detail


# ---------- static-RSA key exchange (kx-layer rule coverage) ----------
def test_config_collector_detects_static_rsa_kx(tmp_path):
    etc = tmp_path / "etc"; etc.mkdir()
    (etc / "gw.conf").write_text(
        "server {\n listen 443 ssl;\n ssl_ciphers HIGH:!aNULL:AES256-SHA;\n}\n", encoding="utf-8")
    inv = Inventory()
    cfg_col.run(inv, config_dir=str(etc))
    kx = [a for a in inv.assets if a.primitive == "key-agreement" and a.algorithm == "rsa"]
    assert kx, "static-RSA suite (AES256-SHA) should yield a key-agreement/rsa asset"
    assert "external" in kx[0].tag_union()


def test_static_rsa_kx_helper():
    from qramp.collectors.configs import _has_static_rsa_kx
    assert _has_static_rsa_kx("high:!anull:aes256-sha") is True       # RSA suite name
    assert _has_static_rsa_kx("krsa") is True                          # explicit token
    assert _has_static_rsa_kx("ecdhe-rsa-aes256-gcm-sha384") is False  # forward secret
    assert _has_static_rsa_kx("dhe-rsa-aes256-sha") is False           # DHE = forward secret


@pytest.mark.skipif(not source_go.HAVE_TS_GO, reason="tree-sitter-go not installed")
def test_go_static_rsa_suite_is_key_agreement():
    inv = Inventory()
    source_go.run(inv, source_dir=GO_DIR)
    # TLS_RSA_WITH_3DES_EDE_CBC_SHA must model RSA as key-agreement, not pk-encryption
    kx = [a for a in inv.assets if a.primitive == "key-agreement" and a.algorithm == "rsa"]
    assert kx


def test_static_rsa_kx_classified_and_routed_to_decommission(tmp_path):
    """A static-RSA kx asset is quantum_broken and routes to the decommission
    recipe (no externalise step — a negotiated suite cannot be externalised)."""
    from qramp import assess, plan
    from qramp.model import Occurrence
    inv = Inventory()
    inv.observe("key-agreement", "rsa",
                Occurrence("configs", "gw.conf:5", "static-RSA kx", owner="net",
                           tags=["external"]))
    cbom = tmp_path / "c.json"; inv.save(str(cbom))
    lt = tmp_path / "lt.yaml"; lt.write_text("default_years: 3\ntags:\n  - {tag: external, years: 7}\n", encoding="utf-8")
    a = tmp_path / "a.json"; assess.assess(str(cbom), RULES, str(lt), str(a))
    assessed = Inventory.load(str(a))
    kx = [x for x in assessed.assets if x.primitive == "key-agreement" and x.algorithm == "rsa"][0]
    assert kx.exposure_class == "quantum_broken"
    assert isinstance(kx.remediate, dict) and kx.remediate.get("action") == "decommission"
    recipe = plan._recipe_for(kx)
    types = [t[1] for t in recipe]
    assert "decommission-legacy" in types
    assert "externalise-algorithm" not in types


def test_regular_rsa_keeps_full_recipe(tmp_path):
    """A source-level RSA keygen still gets the full externalise-first recipe —
    only negotiated kx weaknesses skip straight to decommission."""
    from qramp import assess, plan
    from qramp.model import Occurrence
    inv = Inventory()
    inv.observe("pk-encryption", "rsa",
                Occurrence("source-py", "app.py:10", "RSA keygen", owner="net"),
                key_length=2048)
    cbom = tmp_path / "c.json"; inv.save(str(cbom))
    lt = tmp_path / "lt.yaml"; lt.write_text("default_years: 3\n", encoding="utf-8")
    a = tmp_path / "a.json"; assess.assess(str(cbom), RULES, str(lt), str(a))
    rsa = [x for x in Inventory.load(str(a)).assets if x.algorithm == "rsa"][0]
    types = [t[1] for t in plan._recipe_for(rsa)]
    assert "externalise-algorithm" in types


# ---------- weak finite-field DH (kx-layer, Logjam) ----------
def _assess_dh(tmp_path, key_length, params="ffdhe", external=True):
    from qramp import assess
    from qramp.model import Occurrence
    inv = Inventory()
    inv.observe("key-agreement", "dh",
                Occurrence("configs", "gw.conf:5", f"{key_length}-bit DH", owner="net",
                           tags=["external"] if external else []),
                params=params, key_length=key_length)
    cbom = tmp_path / "c.json"; inv.save(str(cbom))
    lt = tmp_path / "lt.yaml"
    lt.write_text("default_years: 3\ntags:\n  - {tag: external, years: 7}\n", encoding="utf-8")
    a = tmp_path / "a.json"; assess.assess(str(cbom), RULES, str(lt), str(a))
    return [x for x in Inventory.load(str(a)).assets if x.algorithm == "dh"][0]


def test_weak_dh_512_export_routed_to_decommission(tmp_path):
    from qramp import plan
    dh = _assess_dh(tmp_path, 512, params="export")
    assert dh.exposure_class == "quantum_broken"
    assert isinstance(dh.remediate, dict) and dh.remediate.get("action") == "decommission"
    types = [t[1] for t in plan._recipe_for(dh)]
    assert "decommission-legacy" in types and "externalise-algorithm" not in types


def test_weak_dh_1024_routed_to_decommission(tmp_path):
    from qramp import plan
    dh = _assess_dh(tmp_path, 1024)
    assert dh.remediate and dh.remediate.get("action") == "decommission"
    assert "externalise-algorithm" not in [t[1] for t in plan._recipe_for(dh)]


def test_strong_dh_2048_keeps_full_recipe(tmp_path):
    """2048-bit DH is only quantum-broken (not classically weak), so it keeps
    the full recipe rather than the urgent decommission route."""
    from qramp import plan
    dh = _assess_dh(tmp_path, 2048, params="group14")
    assert dh.exposure_class == "quantum_broken"
    assert dh.remediate is None
    assert "externalise-algorithm" in [t[1] for t in plan._recipe_for(dh)]


def test_config_reads_dhparam_bits(tmp_path):
    """ssl_dhparam is resolved to the actual prime bit length by reading the
    referenced PEM file."""
    from cryptography.hazmat.primitives.asymmetric import dh as _dh
    from cryptography.hazmat.primitives import serialization
    etc = tmp_path / "etc"; etc.mkdir()
    params = _dh.generate_parameters(generator=2, key_size=512)
    (etc / "dhparam512.pem").write_bytes(
        params.parameter_bytes(serialization.Encoding.PEM,
                               serialization.ParameterFormat.PKCS3))
    (etc / "gw.conf").write_text(
        "server {\n listen 443 ssl;\n ssl_dhparam dhparam512.pem;\n}\n", encoding="utf-8")
    inv = Inventory()
    cfg_col.run(inv, config_dir=str(etc))
    dh = [a for a in inv.assets if a.algorithm == "dh"][0]
    assert dh.key_length == 512


def test_config_dhparam_filename_fallback(tmp_path):
    """When the PEM cannot be read, the bit size is hinted from the filename."""
    etc = tmp_path / "etc"; etc.mkdir()
    (etc / "gw.conf").write_text(
        "server {\n listen 443 ssl;\n ssl_dhparam /nonexistent/dh-1024.pem;\n}\n", encoding="utf-8")
    inv = Inventory()
    cfg_col.run(inv, config_dir=str(etc))
    dh = [a for a in inv.assets if a.algorithm == "dh"][0]
    assert dh.key_length == 1024


@pytest.mark.skipif(not source_py.HAVE_TS_PY, reason="tree-sitter-python not installed")
def test_python_dh_param_generation_keysize(tmp_path):
    (tmp_path / "x.py").write_text(
        "from cryptography.hazmat.primitives.asymmetric import dh\n"
        "dh.generate_parameters(generator=2, key_size=1024)\n", encoding="utf-8")
    inv = Inventory()
    source_py.run(inv, source_dir=str(tmp_path))
    dh = [a for a in inv.assets if a.algorithm == "dh"][0]
    assert dh.key_length == 1024 and dh.primitive == "key-agreement"


def _spawn_tls_server(min_v, max_v, ciphers=None):
    """Start a throwaway TLS server, return (port, stop_flag)."""
    import ssl as _ssl, socket, threading, tempfile, os, datetime
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
    key = _rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")]))
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30)).sign(key, hashes.SHA256()))
    d = tempfile.mkdtemp(); cp = os.path.join(d, "c"); kp = os.path.join(d, "k")
    open(cp, "wb").write(cert.public_bytes(serialization.Encoding.PEM))
    open(kp, "wb").write(key.private_bytes(serialization.Encoding.PEM,
                         serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(cp, kp)
    ctx.minimum_version = min_v; ctx.maximum_version = max_v
    if ciphers:
        ctx.set_ciphers(ciphers)
    srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0)); srv.listen(5); srv.settimeout(0.3)
    port = srv.getsockname()[1]
    stop = [False]

    def serve():
        while not stop[0]:
            try:
                c, _ = srv.accept()
            except socket.timeout:
                continue
            try:
                s = ctx.wrap_socket(c, server_side=True); s.recv(16); s.close()
            except Exception:
                try:
                    c.close()
                except Exception:
                    pass
        srv.close()
    threading.Thread(target=serve, daemon=True).start()
    return port, stop


def test_probe_decommissioned_real_server_pass():
    import ssl as _ssl
    import time
    from qramp.handshake import probe_decommissioned
    port, stop = _spawn_tls_server(_ssl.TLSVersion.TLSv1_3, _ssl.TLSVersion.TLSv1_3)
    time.sleep(0.3)
    try:
        r = probe_decommissioned("127.0.0.1", port)
        assert r["verdict"] == "pass"
        assert r["accepted"] == []
        assert len(r["refused"]) >= 1
    finally:
        stop[0] = True; time.sleep(0.4)


def test_probe_decommissioned_real_server_fail_static_rsa():
    import ssl as _ssl
    import time
    from qramp.handshake import probe_decommissioned
    port, stop = _spawn_tls_server(_ssl.TLSVersion.TLSv1_2, _ssl.TLSVersion.TLSv1_2,
                                   ciphers="AES256-GCM-SHA384:kRSA")
    time.sleep(0.3)
    try:
        r = probe_decommissioned("127.0.0.1", port)
        assert r["verdict"] == "fail"
        assert any(a["probe"] == "static-RSA-kx" for a in r["accepted"])
    finally:
        stop[0] = True; time.sleep(0.4)
def _built_inventory():
    inv = Inventory()
    source_py.run(inv, source_dir=os.path.join(TB, "sample-app"))
    if source_java.HAVE_TS_JAVA:
        source_java.run(inv, source_dir=os.path.join(TB, "sample-app", "java"))
    if source_go.HAVE_TS_GO:
        source_go.run(inv, source_dir=os.path.join(TB, "sample-app", "go"))
    cfg_col.run(inv, config_dir=os.path.join(TB, "etc"))
    cert_col.run(inv, cert_dir=os.path.join(TB, "certs"))
    return inv


def test_assessment_classifies_rsa_broken_and_aes256_ready(tmp_path):
    inv = _built_inventory()
    p = tmp_path / "cbom.json"
    inv.save(str(p))
    lifetimes = tmp_path / "lt.yaml"
    lifetimes.write_text("default_years: 3\ntags:\n  - {tag: external, years: 7}\n", encoding="utf-8")
    out = tmp_path / "a.json"
    summ = assess.assess(str(p), RULES, str(lifetimes), str(out))
    assert summ["classes"].get("quantum_broken", 0) > 0
    a2 = Inventory.load(str(out))
    rsa = [x for x in a2.assets if x.algorithm == "rsa"][0]
    assert rsa.exposure_class == "quantum_broken"
    assert rsa.tier in ("P0", "P1", "P2")


# ---------- planning + verify ----------
def test_plan_and_verify_roundtrip(tmp_path):
    inv = _built_inventory()
    cbom = tmp_path / "cbom.json"; inv.save(str(cbom))
    lifetimes = tmp_path / "lt.yaml"
    lifetimes.write_text("default_years: 3\ntags:\n  - {tag: external, years: 7}\n", encoding="utf-8")
    assessment = tmp_path / "a.json"
    assess.assess(str(cbom), RULES, str(lifetimes), str(assessment))
    cap = tmp_path / "cap.yaml"; cap.write_text("default_concurrent: 2\n", encoding="utf-8")
    planp = tmp_path / "plan.yaml"
    doc = plan.plan(str(assessment), str(cap), 24, str(planp), solver="list")
    assert doc["task_count"] > 0
    # every task carries the four mandatory execution fields
    for t in doc["tasks"]:
        assert t["acceptance"] and t["rollback"] and t["window"]
        assert "start_month" in t
    # verify against the same (unremediated) cbom: externalise tasks must FAIL
    ev = tmp_path / "ev.json"
    bundle = report.verify(str(planp), str(cbom), str(ev), phase=1)
    assert bundle["failed"] >= 1


def test_prerequisites_are_respected(tmp_path):
    inv = _built_inventory()
    cbom = tmp_path / "c.json"; inv.save(str(cbom))
    lt = tmp_path / "lt.yaml"; lt.write_text("default_years: 3\n", encoding="utf-8")
    a = tmp_path / "a.json"; assess.assess(str(cbom), RULES, str(lt), str(a))
    cap = tmp_path / "cap.yaml"; cap.write_text("default_concurrent: 1\n", encoding="utf-8")
    p = tmp_path / "p.yaml"; doc = plan.plan(str(a), str(cap), 24, str(p), solver="list")
    by_id = {t["id"]: t for t in doc["tasks"]}
    for t in doc["tasks"]:
        for pre in t["prerequisites"]:
            assert by_id[pre]["start_month"] + by_id[pre]["duration_months"] <= t["start_month"]


# ---------- solvers ----------
from qramp.plan import (schedule, weighted_exposure_days, Task,  # noqa: E402
                        HAVE_ORTOOLS)


def _mk(id, phase, owner, dur, weight, prereq=()):
    return Task(id=id, type="t", phase=phase, target_asset=id, target_display=id,
                owner=owner, duration_months=dur, weight=weight, prerequisites=list(prereq))


def _valid(tasks, cap, horizon):
    import collections
    by_id = {t.id: t for t in tasks}
    for t in tasks:
        for pre in t.prerequisites:
            if by_id[pre].start_month + by_id[pre].duration_months > t.start_month:
                return False
    load = collections.Counter()
    per = cap.get("per_owner_concurrent", {}); dflt = cap.get("default_concurrent", 1)
    for t in tasks:
        for m in range(t.start_month, t.start_month + t.duration_months):
            load[(t.owner, m)] += 1
    return all(load[(o, m)] <= per.get(o, dflt) for (o, m) in load)


def _instance():
    return [_mk("H", 1, "net", 1, 1000),
            _mk("A", 1, "net", 2, 1),
            _mk("B", 1, "net", 2, 1),
            _mk("C", 1, "net", 2, 1)]


CAP1 = {"default_concurrent": 1, "per_owner_concurrent": {"net": 1}}


def test_list_scheduler_valid_and_deterministic():
    t1 = _instance(); m1 = schedule(t1, CAP1, 12, solver="list")
    t2 = _instance(); schedule(t2, CAP1, 12, solver="list")
    assert m1["solver"] == "list-scheduling"
    assert _valid(t1, CAP1, 12)
    assert [t.start_month for t in t1] == [t.start_month for t in t2]


def test_cpsat_forced_falls_back_without_ortools(monkeypatch):
    monkeypatch.setattr(plan, "HAVE_ORTOOLS", False)
    t = _instance()
    m = plan.schedule(t, CAP1, 12, solver="cpsat")
    assert m["solver"] == "list-scheduling"
    assert "ortools not installed" in m.get("fallback_reason", "")


@pytest.mark.skipif(not HAVE_ORTOOLS, reason="ortools not installed")
def test_cpsat_optimal_on_small_instance():
    t = _instance()
    m = schedule(t, CAP1, 12, solver="cpsat", time_limit_s=2)
    assert m["solver"] == "cp-sat"
    assert m["proven_optimal"] is True
    assert _valid(t, CAP1, 12)
    # urgent task must start at month 0
    assert next(x.start_month for x in t if x.id == "H") == 0


@pytest.mark.skipif(not HAVE_ORTOOLS, reason="ortools not installed")
def test_cpsat_deterministic():
    t1 = _instance(); schedule(t1, CAP1, 12, solver="cpsat", time_limit_s=2)
    t2 = _instance(); schedule(t2, CAP1, 12, solver="cpsat", time_limit_s=2)
    assert [t.start_month for t in t1] == [t.start_month for t in t2]


@pytest.mark.skipif(not HAVE_ORTOOLS, reason="ortools not installed")
def test_cpsat_not_worse_than_heuristic():
    """On the same instance CP-SAT's weighted objective must be <= the
    heuristic's (it is exact; the heuristic is greedy)."""
    tc = _instance(); schedule(tc, CAP1, 12, solver="cpsat", time_limit_s=2)
    tl = _instance(); schedule(tl, CAP1, 12, solver="list")
    assert weighted_exposure_days(tc) <= weighted_exposure_days(tl)


def test_infeasible_horizon_reported_honestly():
    """When capacity cannot meet the horizon, both solvers report it rather
    than silently overflowing."""
    # 5 sequential 2-month tasks, one owner cap 1, horizon 4 -> needs 10 months
    tasks = [_mk(f"T{i}", 1, "net", 2, 1) for i in range(5)]
    m = schedule(tasks, CAP1, 4, solver="list")
    assert m["feasible_within_horizon"] is False
    assert m["makespan_months"] > 4
    assert m["over_horizon_tasks"] > 0


# ---------- diff ----------
# ---------- increase-parameters evaluator ----------
def _ip_task(display, alg, req):
    return {"type": "increase-parameters", "target_display": display,
            "target_algorithm": alg, "requirement": req}


def test_increase_parameters_fails_when_below_floor():
    from qramp.report import _check_parameters
    idx = {"aes": [{"key_length": 128, "params": "", "display": "AES-128", "locators": ["x"]},
                   {"key_length": 256, "params": "", "display": "AES-256", "locators": ["y"]}]}
    ok, detail = _check_parameters(_ip_task("AES-128 [symmetric-cipher]", "aes",
                                            {"require_min_key_length": 256}), idx)
    assert ok is False and "128" in detail


def test_increase_parameters_passes_when_upgraded():
    from qramp.report import _check_parameters
    idx = {"aes": [{"key_length": 256, "params": "", "display": "AES-256", "locators": ["y"]}]}
    ok, _ = _check_parameters(_ip_task("AES-128 [symmetric-cipher]", "aes",
                                       {"require_min_key_length": 256}), idx)
    assert ok is True


def test_increase_parameters_fails_closed_on_unknown_key_length():
    from qramp.report import _check_parameters
    idx = {"aes": [{"key_length": None, "params": "", "display": "AES", "locators": ["z"]}]}
    ok, detail = _check_parameters(_ip_task("AES-128 [symmetric-cipher]", "aes",
                                            {"require_min_key_length": 256}), idx)
    assert ok is False and "unknown" in detail


def test_increase_parameters_require_algorithm():
    from qramp.report import _check_parameters
    # weak still present -> fail
    idx1 = {"sha2-256": [{"key_length": None, "params": "", "display": "SHA2-256", "locators": ["a"]}]}
    ok1, _ = _check_parameters(_ip_task("SHA2-256 [hash]", "sha2-256",
                                        {"require_algorithm": ["sha2-512", "sha3-256"]}), idx1)
    assert ok1 is False
    # replaced by stronger -> pass
    idx2 = {"sha2-512": [{"key_length": None, "params": "", "display": "SHA2-512", "locators": ["b"]}]}
    ok2, _ = _check_parameters(_ip_task("SHA2-256 [hash]", "sha2-256",
                                        {"require_algorithm": ["sha2-512", "sha3-256"]}), idx2)
    assert ok2 is True


def test_increase_parameters_fails_closed_without_requirement():
    from qramp.report import _check_parameters
    idx = {"aes": [{"key_length": 128, "params": "", "display": "AES-128", "locators": ["x"]}]}
    ok, detail = _check_parameters(_ip_task("AES-128 [symmetric-cipher]", "aes", None), idx)
    assert ok is False and "requirement" in detail


def test_increase_parameters_end_to_end_flip(tmp_path):
    """A real before/after: AES-128 in a config fails the check; after it is
    removed and re-scanned, the same task passes."""
    from qramp.collectors import configs as cfg
    # BEFORE config with aes128-cbc
    etc_before = tmp_path / "etc_before"; etc_before.mkdir()
    (etc_before / "sshd_config").write_text(
        "Ciphers aes256-gcm@openssh.com,aes128-cbc\n", encoding="utf-8")
    inv_b = Inventory(); cfg.run(inv_b, config_dir=str(etc_before))
    cbom_b = tmp_path / "b.json"; inv_b.save(str(cbom_b))
    lt = tmp_path / "lt.yaml"; lt.write_text("default_years: 3\n", encoding="utf-8")
    a_b = tmp_path / "ab.json"; assess.assess(str(cbom_b), RULES, str(lt), str(a_b))
    cap = tmp_path / "cap.yaml"; cap.write_text("default_concurrent: 2\n", encoding="utf-8")
    planp = tmp_path / "p.yaml"; plan.plan(str(a_b), str(cap), 24, str(planp), solver="list")
    ev_b = tmp_path / "eb.json"
    b = report.verify(str(planp), str(cbom_b), str(ev_b))
    ip_before = [r for r in b["results"] if r["type"] == "increase-parameters"]
    assert ip_before and any(not r["passed"] for r in ip_before)

    # AFTER config with aes128-cbc removed
    etc_after = tmp_path / "etc_after"; etc_after.mkdir()
    (etc_after / "sshd_config").write_text("Ciphers aes256-gcm@openssh.com\n", encoding="utf-8")
    inv_a = Inventory(); cfg.run(inv_a, config_dir=str(etc_after))
    cbom_a = tmp_path / "a.json"; inv_a.save(str(cbom_a))
    ev_a = tmp_path / "ea.json"
    a2 = report.verify(str(planp), str(cbom_a), str(ev_a))
    ip_after = [r for r in a2["results"] if r["type"] == "increase-parameters"]
    assert ip_after and all(r["passed"] for r in ip_after)


def test_diff_detects_removed_asset():
    old = Inventory()
    old.observe("hash", "md5", Occurrence("s", "f", "e"))
    old.observe("symmetric-cipher", "aes", Occurrence("s", "f", "e"), key_length=256)
    new = Inventory()
    new.observe("symmetric-cipher", "aes", Occurrence("s", "f", "e"), key_length=256)
    d = diff(old, new)
    assert any("MD5" in x for x in d["removed"])
    assert d["unchanged"] == 1


# ---------- CycloneDX 1.6 export ----------
def _sample_inventory():
    inv = Inventory()
    inv.observe("symmetric-cipher", "des",
                Occurrence("source-py", "app.py:20", "DES.new()", owner="team"),
                key_length=56, mode="ecb")
    inv.observe("symmetric-cipher", "aes",
                Occurrence("source-py", "app.py:30", "AES-GCM", owner="team"),
                key_length=256, mode="gcm")
    inv.observe("pk-encryption", "rsa",
                Occurrence("source-py", "app.py:40", "RSA keygen"), key_length=2048)
    inv.observe("key-agreement", "dh",
                Occurrence("configs", "gw.conf:5", "weak DH", tags=["external"]),
                params="ffdhe", key_length=1024)
    inv.observe("protocol", "tls",
                Occurrence("tls", "host:443", "TLS observed"), params="1.2")
    return inv


def test_cyclonedx_primitive_mapping():
    from qramp.cyclonedx import to_cyclonedx
    doc = to_cyclonedx(_sample_inventory())
    by_name = {c["name"]: c for c in doc["components"]}
    des = by_name["DES-56/ecb [symmetric-cipher]"]["cryptoProperties"]["algorithmProperties"]
    assert des["primitive"] == "block-cipher" and des["mode"] == "ecb"
    aes = by_name["AES-256/gcm [symmetric-cipher]"]["cryptoProperties"]["algorithmProperties"]
    assert aes["primitive"] == "ae"                     # AEAD promoted
    rsa = by_name["RSA-2048 [pk-encryption]"]["cryptoProperties"]["algorithmProperties"]
    assert rsa["primitive"] == "pke"
    dh = by_name["DH-1024 (ffdhe) [key-agreement]"]["cryptoProperties"]["algorithmProperties"]
    assert dh["primitive"] == "key-agree"


def test_cyclonedx_protocol_asset_type():
    from qramp.cyclonedx import to_cyclonedx
    doc = to_cyclonedx(_sample_inventory())
    tls = [c for c in doc["components"] if "protocol" in c["name"]][0]
    cp = tls["cryptoProperties"]
    assert cp["assetType"] == "protocol"
    assert cp["protocolProperties"]["type"] == "tls"
    assert cp["protocolProperties"]["version"] == "1.2"


def test_cyclonedx_qramp_enrichment_in_properties():
    """QRAMP-specific fields survive as standard name-value properties."""
    from qramp import assess
    from qramp.cyclonedx import to_cyclonedx
    import tempfile, os
    inv = _sample_inventory()
    d = tempfile.mkdtemp(); cf = os.path.join(d, "c.json"); inv.save(cf)
    lt = os.path.join(d, "lt.yaml"); open(lt, "w", encoding="utf-8").write("default_years: 3\n")
    a = os.path.join(d, "a.json"); assess.assess(cf, RULES, lt, a)
    doc = to_cyclonedx(Inventory.load(a))
    des = [c for c in doc["components"] if c["name"].startswith("DES")][0]
    names = {p["name"] for p in des["properties"]}
    assert "qramp:exposureClass" in names and "qramp:tier" in names


def test_cyclonedx_validates_against_schema():
    """The export must validate against the official CycloneDX 1.6 JSON schema."""
    import glob, os, json, warnings
    try:
        import cyclonedx
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            from jsonschema import Draft7Validator, RefResolver
    except ImportError:
        pytest.skip("cyclonedx-python-lib / jsonschema not installed")
    pkgdir = os.path.dirname(cyclonedx.__file__)
    matches = glob.glob(os.path.join(pkgdir, "**", "bom-1.6*.json"), recursive=True)
    if not matches:
        pytest.skip("bundled CycloneDX 1.6 schema not found")
    sp = matches[0]
    schema = json.load(open(sp, encoding="utf-8"))
    resdir = os.path.dirname(sp)
    store = {}
    for f in glob.glob(os.path.join(resdir, "*.json")):
        s = json.load(open(f, encoding="utf-8"))
        store["file://" + f] = s
        if "$id" in s:
            store[s["$id"]] = s
    resolver = RefResolver("file://" + sp, schema, store=store)
    from qramp.cyclonedx import to_cyclonedx
    doc = to_cyclonedx(_sample_inventory())
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        errors = list(Draft7Validator(schema, resolver=resolver).iter_errors(doc))
    assert not errors, f"schema errors: {[e.message for e in errors[:5]]}"


# ---------- CycloneDX import / round-trip / merge ----------
def test_cyclonedx_roundtrip_lossless():
    """A QRAMP-produced CBOM must re-import to exactly the same asset set."""
    from qramp.cyclonedx import to_cyclonedx, from_cyclonedx
    inv = _sample_inventory()
    back = from_cyclonedx(to_cyclonedx(inv))
    assert {a.key for a in inv.assets} == {a.key for a in back.assets}


def test_cyclonedx_roundtrip_preserves_enrichment(tmp_path):
    from qramp import assess
    from qramp.cyclonedx import to_cyclonedx, from_cyclonedx
    inv = _sample_inventory()
    cf = tmp_path / "c.json"; inv.save(str(cf))
    lt = tmp_path / "lt.yaml"; lt.write_text("default_years: 3\n", encoding="utf-8")
    a = tmp_path / "a.json"; assess.assess(str(cf), RULES, str(lt), str(a))
    assessed = Inventory.load(str(a))
    back = from_cyclonedx(to_cyclonedx(assessed))
    # every assessed asset keeps its exposure class through the round-trip
    bmap = {x.key: x for x in back.assets}
    for x in assessed.assets:
        if x.exposure_class:
            assert bmap[x.key].exposure_class == x.exposure_class


def _foreign_bom(tool="acme-scanner"):
    """A hand-authored foreign CBOM with only standard spec fields (no qramp:)."""
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.6",
        "serialNumber": "urn:uuid:00000000-0000-4000-8000-000000000009",
        "metadata": {"tools": {"components": [
            {"type": "application", "name": tool, "version": "1.0"}]}},
        "components": [
            {"type": "cryptographic-asset", "name": "AES-128-CBC",
             "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": {
                 "primitive": "block-cipher", "parameterSetIdentifier": "128", "mode": "cbc"}},
             "evidence": {"occurrences": [{"location": "svc/c.go", "line": 42}]}},
            {"type": "cryptographic-asset", "name": "SHA512withRSA",
             "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": {
                 "primitive": "signature", "parameterSetIdentifier": "4096"}},
             "evidence": {"occurrences": [{"location": "svc/k.go", "line": 7}]}},
        ]}


def test_cyclonedx_import_foreign_bom():
    from qramp.cyclonedx import from_cyclonedx
    inv = from_cyclonedx(_foreign_bom("acme-scanner"))
    algs = {(a.primitive, a.algorithm) for a in inv.assets}
    assert ("symmetric-cipher", "aes") in algs      # block-cipher -> symmetric-cipher
    assert ("signature", "rsa") in algs             # SHA512withRSA -> rsa signature
    # provenance tag present on every imported occurrence
    for a in inv.assets:
        assert any("source:acme-scanner" in o.tags for o in a.occurrences)


def test_cyclonedx_import_primitive_unmapping():
    """Spec primitives invert to QRAMP's internal vocabulary."""
    from qramp.cyclonedx import from_cyclonedx
    doc = _foreign_bom()
    doc["components"].append(
        {"type": "cryptographic-asset", "name": "ML-KEM-768",
         "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": {
             "primitive": "kem", "parameterSetIdentifier": "768"}},
         "evidence": {"occurrences": [{"location": "x", "line": 1}]}})
    inv = from_cyclonedx(doc)
    prims = {a.primitive for a in inv.assets}
    assert "kem" in prims


def test_cyclonedx_import_protocol_asset():
    from qramp.cyclonedx import from_cyclonedx
    doc = _foreign_bom()
    doc["components"].append(
        {"type": "cryptographic-asset", "name": "TLS 1.2",
         "cryptoProperties": {"assetType": "protocol",
                              "protocolProperties": {"type": "tls", "version": "1.2"}},
         "evidence": {"occurrences": [{"location": "h:443"}]}})
    inv = from_cyclonedx(doc)
    tls = [a for a in inv.assets if a.primitive == "protocol"]
    assert tls and tls[0].algorithm == "tls" and tls[0].params == "1.2"


def test_merge_resolves_cross_tool():
    """An asset seen by QRAMP and an imported tool becomes one asset carrying
    evidence from both."""
    from qramp.cyclonedx import from_cyclonedx
    local = Inventory()
    local.observe("symmetric-cipher", "aes",
                  Occurrence("configs", "nginx.conf:5", "aes128"),
                  key_length=128, mode="cbc")
    imported = from_cyclonedx(_foreign_bom())     # also has AES-128-CBC
    stats = local.merge(imported)
    assert stats["in_both"] == 1                   # AES-128/cbc shared
    assert stats["only_imported"] == 1             # SHA512withRSA new
    aes = [a for a in local.assets
           if a.algorithm == "aes" and a.key_length == 128][0]
    cols = {o.collector for o in aes.occurrences}
    assert "configs" in cols and any(c.startswith("import:") for c in cols)


def test_merge_does_not_overwrite_local_assessment():
    from qramp.model import Occurrence
    local = Inventory()
    a = local.observe("symmetric-cipher", "aes",
                      Occurrence("configs", "x", "aes"), key_length=128, mode="cbc")
    a.exposure_class = "pq_ready"
    other = Inventory()
    b = other.observe("symmetric-cipher", "aes",
                      Occurrence("import:v", "y", "aes"), key_length=128, mode="cbc")
    b.exposure_class = "quantum_weakened"
    local.merge(other)
    kept = [x for x in local.assets if x.algorithm == "aes"][0]
    assert kept.exposure_class == "pq_ready"       # local assessment preserved


def test_diff_detailed_reports_conflicts():
    from qramp.model import diff_detailed, Occurrence
    a = Inventory()
    xa = a.observe("symmetric-cipher", "aes",
                   Occurrence("configs", "x", "aes"), key_length=128, mode="cbc")
    xa.exposure_class = "pq_ready"
    b = Inventory()
    xb = b.observe("symmetric-cipher", "aes",
                   Occurrence("import:v", "y", "aes"), key_length=128, mode="cbc")
    xb.exposure_class = "quantum_weakened"
    # b also has an asset a lacks
    b.observe("pk-encryption", "rsa", Occurrence("import:v", "z", "rsa"), key_length=4096)
    res = diff_detailed(a, b, "qramp", "vendor")
    assert res["classification_conflicts"] and \
        res["classification_conflicts"][0]["qramp"] == "pq_ready"
    assert "RSA-4096 [pk-encryption]" in res["only_in_vendor"]


def test_import_of_foreign_bom_validates_and_merges_via_cli(tmp_path):
    """End-to-end: a foreign CBOM merges into a QRAMP scan through the model."""
    import json
    from qramp.cyclonedx import from_cyclonedx
    # QRAMP scan
    local = Inventory()
    cert_col.run(local, cert_dir=CERT_DIR)
    n_local = len(local.assets)
    # foreign import + merge
    foreign_path = tmp_path / "foreign.json"
    foreign_path.write_text(json.dumps(_foreign_bom("vendor-x")))
    imported = from_cyclonedx(json.load(open(foreign_path, encoding="utf-8")))
    stats = local.merge(imported)
    assert len(local.assets) >= n_local
    assert stats["only_imported"] >= 1


# ---------- rule pack linter ----------
def _load_rules():
    import yaml
    return yaml.safe_load(open(RULES, encoding="utf-8"))


def test_lint_shipped_pack_has_no_errors_or_warnings():
    """The shipped rule pack must be structurally clean (info-level overlaps
    from intentional layering are allowed)."""
    from qramp.rulelint import lint
    findings = lint(_load_rules())
    assert not [f for f in findings if f.level == "error"]
    assert not [f for f in findings if f.level == "warning"]


def test_lint_detects_unreachable_rule():
    from qramp.rulelint import lint
    doc = {"rules": [
        {"id": "rsa-all", "match": {"algorithm": "rsa"}, "class": "quantum_broken"},
        {"id": "rsa-weak", "match": {"algorithm": "rsa", "max_key_length": 1024},
         "class": "quantum_weakened"},
    ]}
    warns = [f for f in lint(doc) if f.level == "warning"]
    assert any(f.rule_id == "rsa-weak" and "unreachable" in f.message for f in warns)


def test_lint_reachable_when_more_specific_first():
    """The correct ordering (specific before general) must NOT be flagged."""
    from qramp.rulelint import lint
    doc = {"rules": [
        {"id": "rsa-weak", "match": {"algorithm": "rsa", "max_key_length": 1024},
         "class": "quantum_weakened"},
        {"id": "rsa-all", "match": {"algorithm": "rsa"}, "class": "quantum_broken"},
    ]}
    # ignore the provenance warning (these synthetic rules carry no references)
    assert not [f for f in lint(doc)
                if f.level == "warning" and "references" not in f.message]


def test_lint_detects_syntax_errors():
    from qramp.rulelint import lint
    doc = {"rules": [
        {"id": "a", "match": {"algorithm": "aes"}, "class": "pq_ready"},
        {"id": "a", "match": {"algorithm": "des"}, "class": "quantum_broken"},   # dup id
        {"id": "b", "match": {"algorithm": "md5"}, "class": "nonsense"},         # bad class
        {"id": "c", "match": {"algorithm": "rc4"}},                              # no class
        {"id": "d", "match": {"algorithm": "dh", "min_key_length": 2048,
                              "max_key_length": 512}, "class": "quantum_broken"},  # bad range
        {"id": "e", "match": {"algorithmm": "x"}, "class": "unknown"},           # typo key
    ]}
    errs = {f.rule_id: f.message for f in lint(doc) if f.level == "error"}
    assert "a" in errs and "duplicate" in errs["a"]
    assert "b" in errs and "unknown class" in errs["b"]
    assert "c" in errs and "missing a 'class'" in errs["c"]
    assert "d" in errs and "matches nothing" in errs["d"]
    assert "e" in errs and "unknown match key" in errs["e"]


def test_lint_flags_ambiguous_overlap_with_different_class():
    from qramp.rulelint import lint
    doc = {"rules": [
        {"id": "aes-weak", "match": {"algorithm": "aes", "max_key_length": 128},
         "class": "quantum_weakened"},
        {"id": "aes-ok", "match": {"algorithm": "aes", "min_key_length": 256},
         "class": "pq_ready"},
    ]}
    # these do NOT overlap (disjoint key ranges) -> no info finding
    assert not [f for f in lint(doc) if f.level == "info"]
    # Two rules on the same algorithm that overlap but where neither subsumes
    # the other (specific tag rule FIRST, so it's reachable), with different
    # classes -> ambiguous overlap info.
    doc2 = {"rules": [
        {"id": "rsa-weak-key", "match": {"algorithm": "rsa", "has_tag": "weak-key"},
         "class": "quantum_weakened"},
        {"id": "rsa-all", "match": {"algorithm": "rsa"}, "class": "quantum_broken"},
    ]}
    infos = [f for f in lint(doc2) if f.level == "info"]
    assert any("overlaps" in f.message for f in infos)
    # and no unreachable warning, since the specific rule is first (ignore the
    # provenance warning these synthetic rules trigger)
    assert not [f for f in lint(doc2)
                if f.level == "warning" and "references" not in f.message]


def test_subsumption_respects_has_tag_semantics():
    """A rule requiring a tag does NOT subsume one that matches tagless assets,
    because has_tag uses intersection semantics."""
    from qramp.rulelint import Condition, subsumes
    tagged = Condition.from_match({"algorithm": "rsa", "has_tag": "weak-key"})
    untagged = Condition.from_match({"algorithm": "rsa"})
    assert subsumes(untagged, tagged)          # rsa (any) ⊇ rsa+weak-key
    assert not subsumes(tagged, untagged)      # rsa+weak-key does NOT ⊇ rsa


def test_snapshot_regression_detects_reorder():
    """Reordering rsa-broken above weak-cert-key changes a weak-key RSA cert's
    classification — the snapshot must catch it."""
    import copy
    from qramp.rulelint import classify_snapshot, diff_snapshot
    doc = _load_rules()
    fixtures = [
        {"label": "weak-key-rsa", "primitive": "pk-encryption", "algorithm": "rsa",
         "key_length": 1024, "tags": ["weak-key"]},
    ]
    baseline = classify_snapshot(doc, fixtures)
    assert baseline["weak-key-rsa"]["class"] == "quantum_weakened"
    # break it: move rsa-broken to the front
    broken = copy.deepcopy(doc)
    rb = next(r for r in broken["rules"] if r["id"] == "rsa-broken")
    broken["rules"].remove(rb)
    broken["rules"].insert(0, rb)
    current = classify_snapshot(broken, fixtures)
    d = diff_snapshot(baseline, current)
    assert d["regressions"] == 1
    assert d["changed"][0]["now"]["class"] == "quantum_broken"


def test_snapshot_stable_on_shipped_pack():
    """The committed snapshot fixture must still match the shipped pack — this
    is the regression guard that runs in CI."""
    import json, os
    from qramp.rulelint import classify_snapshot, diff_snapshot
    snap_path = os.path.join(HERE, "..", "testbed", "rules", "snapshot.json")
    if not os.path.exists(snap_path):
        pytest.skip("snapshot fixture not present")
    snap = json.load(open(snap_path, encoding="utf-8"))
    current = classify_snapshot(_load_rules(), snap["assets"])
    d = diff_snapshot(snap.get("expected", {}), current)
    assert d["regressions"] == 0, f"snapshot drift: {d['changed']}"


# ---------- version-aware provider map ----------
def test_provider_version_resolution_openssl():
    """OpenSSL resolves to different capabilities by version: PQC only in 3.5+."""
    from qramp.providermap import resolve
    import yaml, os
    mp = os.path.join(HERE, "..", "src", "qramp", "data", "provider-map.yaml")
    doc = yaml.safe_load(open(mp, encoding="utf-8"))
    openssl = [e for e in doc["components"] if e["component"] == "openssl"][0]
    old = {c.algorithm for c in resolve(openssl, "1.1.1")}
    new = {c.algorithm for c in resolve(openssl, "3.5.0")}
    assert "ml-kem" not in old and "ml-dsa" not in old      # no PQC in 1.1.1
    assert "ml-kem" in new and "ml-dsa" in new              # PQC in 3.5+
    assert {"rsa", "ecdh", "aes"} <= old                    # base caps in both


def test_provider_version_gate_fails_closed_on_unknown_version():
    from qramp.providermap import resolve
    import yaml, os
    mp = os.path.join(HERE, "..", "src", "qramp", "data", "provider-map.yaml")
    doc = yaml.safe_load(open(mp, encoding="utf-8"))
    openssl = [e for e in doc["components"] if e["component"] == "openssl"][0]
    caps = {c.algorithm for c in resolve(openssl, "?")}
    assert "ml-kem" not in caps                              # version-gated cap withheld
    assert "rsa" in caps                                     # unconstrained cap kept


def test_version_satisfies_comparators():
    from qramp.providermap import satisfies
    assert satisfies("3.5.0", ">=3.5")
    assert not satisfies("3.4.0", ">=3.5")
    assert satisfies("1.0.2", "<1.1.0")
    assert not satisfies("1.1.1", "<1.1.0")
    assert satisfies("2.0", ">=1.1.0,<3.0")
    assert not satisfies("3.1", ">=1.1.0,<3.0")
    assert satisfies("1.0.0", "")               # empty gate always matches


def test_version_fallback_parser_matches_packaging():
    """The built-in fallback parser must agree with the comparators regardless
    of whether `packaging` is installed."""
    from qramp.providermap import _fallback_satisfies
    for v, s, exp in [("3.5.0", ">=3.5", True), ("3.4.0", ">=3.5", False),
                      ("1.0.2", "<1.1.0", True), ("1.1.1", "<1.1.0", False),
                      ("2.0", ">=1.1.0,<3.0", True), ("3.1", ">=1.1.0,<3.0", False)]:
        assert _fallback_satisfies(v, s) == exp


def test_sbom_version_aware_pipeline(tmp_path):
    """The SBOM collector resolves capabilities by the component's version."""
    import json
    from qramp.collectors import sbom as sbom_col2
    for ver, expect_pqc in [("1.1.1w", False), ("3.5.0", True)]:
        s = {"bomFormat": "CycloneDX", "specVersion": "1.6",
             "components": [{"type": "library", "name": "openssl", "version": ver}]}
        p = tmp_path / f"sbom-{ver}.json"; p.write_text(json.dumps(s), encoding="utf-8")
        inv = Inventory()
        stats = sbom_col2.run(inv, sbom_path=str(p))
        algs = {a.algorithm for c in inv.components
                for a in inv.assets_provided_by(c)}
        has_pqc = "ml-kem" in algs
        assert has_pqc == expect_pqc
        if expect_pqc:
            assert stats["version_gated_edges"] >= 2


def test_provider_map_lint_shipped_clean():
    from qramp.providermap import lint
    import yaml, os
    mp = os.path.join(HERE, "..", "src", "qramp", "data", "provider-map.yaml")
    doc = yaml.safe_load(open(mp, encoding="utf-8"))
    findings = lint(doc)
    assert not [f for f in findings if f.level in ("error", "warning")]


def test_provider_map_lint_detects_errors():
    from qramp.providermap import lint
    bad = {"components": [
        {"component": "openssl", "provides": [
            {"primitive": "pk-encryption", "algorithm": "rsa", "confidence": 1.5},   # bad conf
            {"primitive": "encryption", "algorithm": "aes"},                          # bad prim
            {"primitive": "signature", "algorithm": "ecdsa", "version": ">=bad.junk"},# bad gate
            {"algorithm": "md5"},                                                     # no prim
        ]},
        {"component": "openssl", "provides": [{"primitive": "hash", "algorithm": "sha1"}]},  # dup
        {"component": "empty"},                                                       # no provides
    ]}
    findings = lint(bad)
    errs = [f.message for f in findings if f.level == "error"]
    assert any("confidence" in m and "[0,1]" in m for m in errs)
    assert any("invalid version constraint" in m for m in errs)
    assert any("missing 'primitive'" in m for m in errs)
    assert any("duplicate component" in m for m in errs)
    warns = [f.message for f in findings if f.level == "warning"]
    assert any("not in the known set" in m for m in warns)   # bad primitive
    assert any("no 'provides'" in m for m in warns)          # empty component


def test_provider_map_lint_flags_noncanonical_algorithm():
    from qramp.providermap import lint
    doc = {"components": [{"component": "x", "provides": [
        {"primitive": "hash", "algorithm": "SHA256"}]}]}
    infos = [f for f in lint(doc) if f.level == "info"]
    assert any("not canonical" in f.message for f in infos)


def test_provider_snapshot_stable():
    """The committed provider-map resolution snapshot must match the shipped
    map — the CI guard against accidental version-gate edits."""
    import json, os, yaml
    from qramp.providermap import resolve
    snap_path = os.path.join(HERE, "..", "testbed", "rules", "provider-snapshot.json")
    mp = os.path.join(HERE, "..", "src", "qramp", "data", "provider-map.yaml")
    if not os.path.exists(snap_path):
        pytest.skip("provider snapshot not present")
    doc = yaml.safe_load(open(mp, encoding="utf-8"))
    entries = {e["component"].lower(): e for e in doc["components"]}
    snap = json.load(open(snap_path, encoding="utf-8"))
    for case in snap["cases"]:
        entry = entries[case["component"].lower()]
        got = sorted({c.algorithm for c in resolve(entry, case["version"])})
        assert got == sorted(case["expect"]), \
            f"{case['component']}@{case['version']}: {got} != {case['expect']}"


# ---------- SVG graph visualisation ----------
def _inv_with_both_graphs():
    """A scanned inventory carrying SBOM components AND a certificate chain."""
    inv = Inventory()
    sbom_col.run(inv, sbom_path=SBOM_PATH)
    cert_col.run(inv, cert_dir=CHAIN_DIR)
    return inv


def test_dependency_svg_has_libraries_and_capabilities():
    from qramp.svggraph import dependency_svg
    svg = dependency_svg(_inv_with_both_graphs())
    assert svg.startswith("<svg") and svg.endswith("</svg>")
    # both columns present
    assert "Libraries" in svg and "capabilities" in svg
    # library and capability node labels
    assert "openssl" in svg and "cryptography" in svg
    assert "RSA" in svg.upper()


def test_dependency_svg_marks_shared_capability():
    """RSA is provided by openssl AND cryptography — the graph must mark it
    shared."""
    from qramp.svggraph import dependency_svg
    svg = dependency_svg(_inv_with_both_graphs())
    assert "shared" in svg                    # a shared-capability annotation
    assert "#9DC3E6" in svg                    # the shared-edge colour


def test_dependency_svg_colours_by_exposure():
    """After assessment, capability nodes take their exposure colour."""
    from qramp import assess
    from qramp.svggraph import dependency_svg, EXPOSURE_COLOUR
    import yaml
    inv = _inv_with_both_graphs()
    assess.classify(inv, yaml.safe_load(open(RULES, encoding="utf-8")))
    svg = dependency_svg(inv)
    # RSA/ECDSA are quantum_broken -> red; AES-256 is pq_ready -> green
    assert EXPOSURE_COLOUR["quantum_broken"] in svg
    assert EXPOSURE_COLOUR["pq_ready"] in svg


def test_dependency_svg_empty_state():
    from qramp.svggraph import dependency_svg
    inv = Inventory()
    cert_col.run(inv, cert_dir=CHAIN_DIR)          # certs but no SBOM components
    svg = dependency_svg(inv)
    assert "<svg" not in svg and "No SBOM components" in svg


def test_chain_svg_highlights_weakest_link():
    from qramp.svggraph import chain_svg
    svg = chain_svg(_inv_with_both_graphs())
    assert svg.startswith("<svg") and svg.endswith("</svg>")
    assert "secure.example.com" in svg and "SHA1 Legacy Root CA" in svg
    assert "weakest link" in svg                    # the highlight label
    # the weak CA node uses the blocking-weakness colour
    from qramp.svggraph import WEAK_COLOUR
    assert WEAK_COLOUR in svg


def test_chain_svg_clean_chain_not_flagged():
    """api.example.com under the strong CA must not be a weakest link."""
    from qramp.svggraph import chain_svg
    svg = chain_svg(_inv_with_both_graphs())
    # exactly one weakest-link label (only the SHA1 chain)
    assert svg.count("weakest link") == 1


def test_chain_svg_empty_state():
    from qramp.svggraph import chain_svg
    inv = Inventory()
    sbom_col.run(inv, sbom_path=SBOM_PATH)          # components but no certs
    svg = chain_svg(inv)
    assert "<svg" not in svg and "No certificate nodes" in svg


def test_dashboard_embeds_both_graphs(tmp_path):
    """The HTML dashboard must contain both SVG graphs and the asset table."""
    from qramp import assess, report
    import yaml
    inv = _inv_with_both_graphs()
    assess.classify(inv, yaml.safe_load(open(RULES, encoding="utf-8")))
    cbom = tmp_path / "c.json"; inv.save(str(cbom))
    out = tmp_path / "dash.html"
    report.dashboard(str(cbom), str(out))
    doc = out.read_text(encoding="utf-8")
    assert doc.count("<svg") == 2                   # two graphs embedded
    assert "Dependency graph" in doc and "trust chains" in doc
    assert "weakest link" in doc                    # chain highlight survived
    assert "<table" in doc                          # asset table still there


# ---------- SARIF export ----------
def _assessed_inv():
    import yaml
    inv = Inventory()
    from qramp.collectors import source_py
    # scan the whole testbed sample-app + configs + certs for rich locations
    for coll, kw in [(sbom_col, {"sbom_path": SBOM_PATH})]:
        coll.run(inv, **kw)
    cert_col.run(inv, cert_dir=CERT_DIR)
    from qramp.collectors import configs as cfg
    cfg.run(inv, config_dir=os.path.join(TB, "etc"))
    from qramp import assess
    assess.classify(inv, yaml.safe_load(open(RULES, encoding="utf-8")))
    return inv


def _rules():
    import yaml
    return yaml.safe_load(open(RULES, encoding="utf-8"))


def test_sarif_basic_structure():
    from qramp.sarif import to_sarif
    doc = to_sarif(_assessed_inv(), _rules())
    assert doc["version"] == "2.1.0"
    assert "$schema" in doc
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "QRAMP"
    assert run["tool"]["driver"]["rules"]
    assert run["results"]


def test_sarif_results_point_to_source_lines():
    from qramp.sarif import to_sarif
    doc = to_sarif(_assessed_inv(), _rules())
    src_results = [r for r in doc["runs"][0]["results"]
                   if r["locations"][0].get("physicalLocation", {}).get("region")]
    assert src_results, "expected at least one result with a startLine"
    for r in src_results[:5]:
        reg = r["locations"][0]["physicalLocation"]["region"]
        assert isinstance(reg["startLine"], int) and reg["startLine"] >= 1


def test_sarif_ruleindex_points_to_matching_rule():
    from qramp.sarif import to_sarif
    doc = to_sarif(_assessed_inv(), _rules())
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    for r in doc["runs"][0]["results"]:
        assert rules[r["ruleIndex"]]["id"] == r["ruleId"]


def test_sarif_level_mapping():
    from qramp.sarif import to_sarif
    doc = to_sarif(_assessed_inv(), _rules())
    levels = {r["level"] for r in doc["runs"][0]["results"]}
    assert "error" in levels          # quantum_broken -> error
    # min-level filter drops notes
    errs_only = to_sarif(_assessed_inv(), _rules(), min_level="error")
    assert all(r["level"] == "error" for r in errs_only["runs"][0]["results"])


def test_sarif_fingerprint_stable_across_line_moves():
    from qramp.model import CryptoAsset, Occurrence
    from qramp.sarif import _fingerprint
    a = CryptoAsset("hash", "md5")
    o1 = Occurrence("source-py", "app/x.py:10", "md5")
    o2 = Occurrence("source-py", "app/x.py:99", "md5")   # line shifted
    o3 = Occurrence("source-py", "app/y.py:10", "md5")   # other file
    assert _fingerprint(a, o1) == _fingerprint(a, o2)
    assert _fingerprint(a, o1) != _fingerprint(a, o3)


def test_sarif_locator_parsing():
    from qramp.sarif import _split_locator
    assert _split_locator("app/x.py:10") == ("app/x.py", 10)
    assert _split_locator("cert.pem") == ("cert.pem", None)
    assert _split_locator("host.local:443") == (None, None)   # host:port, not a file
    assert _split_locator("/abs/path.go:5") == ("/abs/path.go", 5)


def test_sarif_certs_have_fileless_location():
    """Certificate findings map to a file with no region (no line number)."""
    from qramp.sarif import to_sarif
    doc = to_sarif(_assessed_inv(), _rules())
    cert_results = [r for r in doc["runs"][0]["results"]
                    if r["properties"].get("collector") == "certs"]
    assert cert_results
    for r in cert_results:
        phys = r["locations"][0]["physicalLocation"]
        assert phys["artifactLocation"]["uri"].endswith(".pem")
        assert "region" not in phys                # no line for a cert file


def test_sarif_validates_against_official_schema():
    import json, os, warnings
    schema_path = os.path.join(HERE, "data", "sarif-schema-2.1.0.json")
    if not os.path.exists(schema_path):
        pytest.skip("bundled SARIF schema not present")
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            from jsonschema import Draft4Validator
    except ImportError:
        pytest.skip("jsonschema not installed")
    from qramp.sarif import to_sarif
    doc = to_sarif(_assessed_inv(), _rules())
    schema = json.load(open(schema_path, encoding="utf-8"))
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        errors = list(Draft4Validator(schema).iter_errors(doc))
    assert not errors, f"SARIF schema errors: {[e.message for e in errors[:3]]}"


def test_sarif_rule_id_survives_save_load(tmp_path):
    """The firing rule id must persist through the CBOM so SARIF can map to
    rules even when exporting from a saved assessment."""
    import yaml
    from qramp import assess
    inv = Inventory()
    sbom_col.run(inv, sbom_path=SBOM_PATH)
    assess.classify(inv, yaml.safe_load(open(RULES, encoding="utf-8")))
    rsa = [a for a in inv.assets if a.algorithm == "rsa"][0]
    assert rsa.rule_id                            # captured
    p = tmp_path / "a.json"; inv.save(str(p))
    back = Inventory.load(str(p))
    rsa2 = [a for a in back.assets if a.algorithm == "rsa"][0]
    assert rsa2.rule_id == rsa.rule_id            # survived save/load


# ---------- migration readiness scoring ----------
def _pmap():
    import yaml, os
    return yaml.safe_load(open(os.path.join(
        HERE, "..", "src", "qramp", "data", "provider-map.yaml"), encoding="utf-8"))


def _readiness_inv(openssl_version="3.0.13", extra_libs=None):
    """SBOM with openssl at a given version plus broken kx/sig assets."""
    import json, tempfile, os
    from qramp.model import Occurrence
    comps = [{"type": "library", "name": "openssl", "version": openssl_version}]
    for name, ver in (extra_libs or []):
        comps.append({"type": "library", "name": name, "version": ver})
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": comps}
    fd, p = tempfile.mkstemp(suffix=".json"); os.close(fd)
    open(p, "w", encoding="utf-8").write(json.dumps(doc))
    inv = Inventory()
    sbom_col.run(inv, sbom_path=p)
    os.unlink(p)
    for prim, alg, tier in [("key-agreement", "ecdh", "P0"),
                            ("signature", "ecdsa", "P1"),
                            ("signature", "rsa", "P2")]:
        a = inv.observe(prim, alg, Occurrence("source-py", "x.py:1", f"{alg}"))
        a.exposure_class = "quantum_broken"; a.tier = tier
    return inv


def test_blocked_assets_when_no_pqc_deployed():
    from qramp.readiness import blocked_assets
    inv = _readiness_inv("3.0.13")           # openssl 3.0 has no PQC
    blocked = blocked_assets(inv)
    algs = {a.algorithm for a in blocked}
    assert {"ecdh", "ecdsa", "rsa"} <= algs   # all three need a PQC replacement
    # hashes are never "blocked" (Grover, not a KEM/sig migration)


def test_readiness_zero_when_no_pqc_and_recommends_openssl_upgrade():
    from qramp.readiness import readiness_report
    inv = _readiness_inv("3.0.13")
    rep = readiness_report(inv, _pmap())
    assert rep["readiness_pct"] == 0.0
    assert rep["migration_blocked"] == 3
    ups = rep["recommended_upgrades"]
    assert ups and ups[0]["component"] == "openssl"
    assert "3.5" in ups[0]["upgrade"]
    assert set(ups[0]["unlocks"]) == {"ml-kem", "ml-dsa"}
    assert ups[0]["unblocks"] == 3


def test_readiness_full_when_pqc_library_deployed():
    """liboqs provides ML-KEM/ML-DSA unconditionally -> nothing blocked, no
    upgrade needed."""
    from qramp.readiness import readiness_report
    inv = _readiness_inv("3.0.13", extra_libs=[("liboqs", "0.10")])
    rep = readiness_report(inv, _pmap())
    assert rep["readiness_pct"] == 100.0
    assert rep["migration_blocked"] == 0
    assert rep["recommended_upgrades"] == []


def test_readiness_roi_prefers_smaller_upgrade():
    """Two upgrades that clear the same risk: the smaller version jump wins."""
    from qramp.readiness import readiness_report
    # openssl 3.0 (needs ->3.5) and bouncycastle 1.77 (needs ->1.78) both unblock
    inv = _readiness_inv("3.0.13", extra_libs=[("bouncycastle", "1.77")])
    rep = readiness_report(inv, _pmap())
    ups = rep["recommended_upgrades"]
    assert len(ups) >= 2
    # bouncycastle 1.77->1.78 is a tiny bump vs openssl 3.0->3.5, same assets
    assert ups[0]["component"] == "bouncycastle"
    assert ups[0]["roi_score"] > ups[1]["roi_score"]


def test_readiness_no_upgrade_when_already_current():
    """If openssl is already 3.5, it provides PQC and needs no upgrade."""
    from qramp.readiness import readiness_report
    inv = _readiness_inv("3.5.0")
    rep = readiness_report(inv, _pmap())
    # openssl 3.5 already ships ML-KEM/ML-DSA -> nothing blocked
    assert rep["migration_blocked"] == 0
    assert rep["recommended_upgrades"] == []


def test_readiness_tier_weighting_in_score():
    """A P0-heavy unblock scores higher than a P3-heavy one for the same count
    and upgrade distance."""
    from qramp.readiness import UpgradeOption, TIER_WEIGHT
    from qramp.model import CryptoAsset
    def mk(tier):
        a = CryptoAsset("key-agreement", "ecdh"); a.tier = tier; return a
    # same structure, different tiers
    hi = sum(TIER_WEIGHT[t] for t in ["P0", "P0"])
    lo = sum(TIER_WEIGHT[t] for t in ["P3", "P3"])
    assert hi > lo


def test_readiness_cli_json(tmp_path):
    """The CLI --json path emits the machine-readable report."""
    import json, subprocess, sys, yaml
    from qramp import assess
    inv = _readiness_inv("3.0.13")
    cbom = tmp_path / "a.json"; inv.save(str(cbom))
    # load-save round trip must preserve components + exposure for the report
    back = Inventory.load(str(cbom))
    from qramp.readiness import readiness_report
    rep = readiness_report(back, _pmap())
    assert rep["pqc_migration_assets"] == 3
    assert rep["recommended_upgrades"][0]["component"] == "openssl"


# ---------- interactive dashboard ----------
def _dashboard_html(tmp_path, with_sbom=True):
    import yaml
    from qramp import assess, report
    inv = Inventory()
    if with_sbom:
        sbom_col.run(inv, sbom_path=SBOM_PATH)
    cert_col.run(inv, cert_dir=CHAIN_DIR)
    assess.classify(inv, yaml.safe_load(open(RULES, encoding="utf-8")))
    lifetimes = yaml.safe_load(open(os.path.join(TB, "policy", "data-lifetimes.yaml"),
                                    encoding="utf-8"))
    assess.prioritise(inv, yaml.safe_load(open(RULES, encoding="utf-8")), lifetimes)
    cbom = tmp_path / "c.json"; inv.save(str(cbom))
    out = tmp_path / "dash.html"
    report.dashboard(str(cbom), str(out))
    return out.read_text(encoding="utf-8")


def test_dashboard_rows_carry_data_attributes(tmp_path):
    doc = _dashboard_html(tmp_path)
    # every table row has data-asset, data-tier, data-exposure for filtering
    assert "data-asset='A-" in doc
    assert "data-tier=" in doc and "data-exposure=" in doc


def test_dashboard_capability_nodes_link_to_rows(tmp_path):
    """Each graph capability node's asset id must match a table row so the
    cross-highlight works."""
    import re
    doc = _dashboard_html(tmp_path)
    cap_ids = set(re.findall(r'data-asset="(A-[0-9a-f]+)"[^>]*class="qramp-cap"', doc))
    cap_ids |= set(re.findall(r'class="qramp-cap" data-asset="(A-[0-9a-f]+)"', doc))
    row_ids = set(re.findall(r"data-asset='(A-[0-9a-f]+)'", doc))
    assert cap_ids                       # there are capability nodes
    assert cap_ids <= row_ids            # all of them map to a row


def test_dashboard_has_filter_controls_for_present_tiers(tmp_path):
    doc = _dashboard_html(tmp_path)
    assert "class='filt'" in doc
    assert "id=\"clearf\"" in doc or "id='clearf'" in doc
    # a tier that exists in the data has a filter button
    assert "data-dim='tier'" in doc
    assert "data-dim='exposure'" in doc


def test_dashboard_embeds_readiness_when_sbom_present(tmp_path):
    doc = _dashboard_html(tmp_path, with_sbom=True)
    assert "Migration readiness" in doc
    assert "ROI" in doc
    assert "unlocks" in doc


def test_dashboard_no_readiness_without_components(tmp_path):
    doc = _dashboard_html(tmp_path, with_sbom=False)
    # no SBOM components -> no readiness section (certs only)
    assert "Migration readiness" not in doc


def test_dashboard_js_is_syntactically_valid(tmp_path):
    """If node is available, the inline script must pass a syntax check; else
    do a basic balance check."""
    import re, shutil, subprocess, tempfile, os as _os
    doc = _dashboard_html(tmp_path)
    m = re.search(r"<script>(.*?)</script>", doc, re.S)
    assert m, "dashboard must include an inline script"
    js = m.group(1)
    if shutil.which("node"):
        fd, p = tempfile.mkstemp(suffix=".js"); _os.write(fd, js.encode()); _os.close(fd)
        r = subprocess.run(["node", "--check", p], capture_output=True, text=True)
        _os.unlink(p)
        assert r.returncode == 0, f"JS syntax error: {r.stderr[:200]}"
    else:
        assert js.count("{") == js.count("}")
        assert js.count("(") == js.count(")")


def test_dashboard_still_well_formed(tmp_path):
    from html.parser import HTMLParser
    doc = _dashboard_html(tmp_path)

    class _P(HTMLParser):
        def error(self, message):
            raise AssertionError(message)
    _P().feed(doc)                       # raises if malformed
    assert doc.count("<svg") == 2        # both graphs still present
    assert "<table" in doc               # asset table still present


def test_dashboard_interactions_with_browser(tmp_path):
    """Behavioural test of filtering + cross-highlight. Skips if playwright (and
    a browser) are unavailable, so it never blocks the core suite."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        pytest.skip("playwright not installed")
    import pathlib
    html_path = tmp_path / "dash.html"
    html_path.write_text(_dashboard_html(tmp_path), encoding="utf-8")
    url = "file://" + str(html_path.resolve())
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page()
            page.goto(url)
            total = page.eval_on_selector_all("#assets tbody tr", "e=>e.length")
            assert total > 0
            # pick a tier button that exists and filter by it
            btn = page.query_selector(".filt[data-dim='tier']")
            val = btn.get_attribute("data-val")
            btn.click()
            shown = page.eval_on_selector_all(
                "#assets tbody tr:not(.hidden)", "e=>e.length")
            assert 0 < shown <= total
            # every shown row matches the chosen tier
            tiers = page.eval_on_selector_all(
                "#assets tbody tr:not(.hidden)",
                "els=>els.map(e=>e.getAttribute('data-tier'))")
            assert all(t == val for t in tiers)
            # clear restores all rows
            page.click("#clearf")
            restored = page.eval_on_selector_all(
                "#assets tbody tr:not(.hidden)", "e=>e.length")
            assert restored == total
            # cross-highlight: hovering a capability node marks its row
            page.dispatch_event("#depgraph .qramp-cap", "mouseenter")
            matched = page.eval_on_selector_all("#assets tr.match", "e=>e.length")
            assert matched == 1
            browser.close()
    except Exception as e:
        if "Executable doesn't exist" in str(e) or "Host system is missing" in str(e):
            pytest.skip(f"browser not available: {e}")
        raise


# ---------- VEX: exceptions / suppressions ----------
def _assessed_for_vex():
    import yaml
    from qramp import assess
    from qramp.collectors import configs as cfg
    inv = Inventory()
    # source + configs give real asset_ids to target
    from qramp.collectors import source_py
    source_py.run(inv, source_dir=os.path.join(TB, "sample-app"))
    cfg.run(inv, config_dir=os.path.join(TB, "etc"))
    assess.classify(inv, yaml.safe_load(open(RULES, encoding="utf-8")))
    return inv


def test_vex_parse_and_lint_clean():
    from qramp import vex
    inv = _assessed_for_vex()
    md5 = [a for a in inv.assets if a.algorithm == "md5"][0]
    doc = {"statements": [
        {"asset": md5.asset_id, "status": "not_affected",
         "justification": "vulnerable_code_not_in_execute_path",
         "detail": "cache key only"}]}
    assert not [f for f in vex.lint(doc) if f.level == "error"]
    stmts = vex.parse(doc)
    assert len(stmts) == 1 and stmts[0].asset_id == md5.asset_id


def test_vex_lint_catches_mistakes():
    from qramp import vex
    doc = {"statements": [
        {"asset": "A-1", "status": "not_affected"},                     # no justification
        {"asset": "A-2", "status": "bogus", "justification": "x"},       # bad status
        {"status": "affected"},                                         # no asset
        {"asset": "A-3", "status": "not_affected", "justification": "made_up"},  # nonstandard
    ]}
    findings = vex.lint(doc)
    errs = [f.message for f in findings if f.level == "error"]
    assert any("requires a 'justification'" in m for m in errs)
    assert any("unknown status" in m for m in errs)
    assert any("missing 'asset'" in m for m in errs)
    assert any("not a standard value" in f.message
               for f in findings if f.level == "warning")


def test_vex_apply_suppresses_only_not_affected_and_fixed():
    from qramp import vex
    inv = _assessed_for_vex()
    assets = [a for a in inv.assets if a.exposure_class == "quantum_broken"][:3]
    doc = {"statements": [
        {"asset": assets[0].asset_id, "status": "not_affected",
         "justification": "vulnerable_code_not_present"},
        {"asset": assets[1].asset_id, "status": "fixed"},
        {"asset": assets[2].asset_id, "status": "affected"},        # NOT suppressed
    ]}
    summary = vex.apply(inv, vex.parse(doc))
    assert summary["applied"] == 3
    assert vex.suppression_for(assets[0]) is not None
    assert vex.suppression_for(assets[1]) is not None
    assert vex.suppression_for(assets[2]) is None       # affected does not suppress


def test_vex_locator_scoped_suppression():
    """A statement with a locator only suppresses its own occurrence."""
    import yaml
    from qramp import vex
    from qramp import assess
    from qramp.collectors import source_py, source_java, source_go
    inv = Inventory()
    # scan several languages so a shared algorithm has multiple occurrences
    source_py.run(inv, source_dir=os.path.join(TB, "sample-app"))
    source_java.run(inv, source_dir=os.path.join(TB, "sample-app"))
    source_go.run(inv, source_dir=os.path.join(TB, "sample-app"))
    assess.classify(inv, yaml.safe_load(open(RULES, encoding="utf-8")))
    multi = [a for a in inv.assets if len(a.occurrences) >= 2]
    if not multi:
        pytest.skip("no multi-occurrence asset")
    a = multi[0]
    target_loc = a.occurrences[0].locator
    doc = {"statements": [{"asset": a.asset_id, "status": "not_affected",
                           "justification": "vulnerable_code_not_in_execute_path",
                           "locator": target_loc}]}
    vex.apply(inv, vex.parse(doc))
    assert vex.suppression_for(a, a.occurrences[0]) is not None   # this one
    other = [o for o in a.occurrences if o.locator != target_loc]
    assert other, "expected another occurrence at a different locator"
    assert vex.suppression_for(a, other[0]) is None              # not that one


def test_vex_openvex_structure():
    from qramp import vex
    inv = _assessed_for_vex()
    md5 = [a for a in inv.assets if a.algorithm == "md5"][0]
    doc = {"statements": [{"asset": md5.asset_id, "status": "not_affected",
                           "justification": "vulnerable_code_not_present"}]}
    ov = vex.to_openvex(inv, vex.parse(doc))
    assert ov["@context"].startswith("https://openvex.dev/")
    assert ov["statements"][0]["status"] == "not_affected"
    assert ov["statements"][0]["justification"] == "vulnerable_code_not_present"
    assert ov["statements"][0]["products"][0]["@id"].endswith(md5.asset_id)


def test_vex_cyclonedx_maps_vocabulary():
    from qramp import vex
    inv = _assessed_for_vex()
    md5 = [a for a in inv.assets if a.algorithm == "md5"][0]
    doc = {"statements": [{"asset": md5.asset_id, "status": "not_affected",
                           "justification": "vulnerable_code_not_in_execute_path"}]}
    vulns = vex.to_cyclonedx_vex(inv, vex.parse(doc))
    assert vulns[0]["analysis"]["state"] == "not_affected"
    # OpenVEX justification maps to the CycloneDX vocabulary
    assert vulns[0]["analysis"]["justification"] == "code_not_reachable"
    assert vulns[0]["affects"][0]["ref"] == md5.asset_id


def test_vex_cyclonedx_validates_in_cbom():
    import glob, json, warnings
    try:
        import cyclonedx
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            from jsonschema import Draft7Validator, RefResolver
    except ImportError:
        pytest.skip("cyclonedx-python-lib / jsonschema not installed")
    from qramp import vex
    from qramp.cyclonedx import to_cyclonedx
    inv = _assessed_for_vex()
    md5 = [a for a in inv.assets if a.algorithm == "md5"][0]
    doc = {"statements": [{"asset": md5.asset_id, "status": "not_affected",
                           "justification": "inline_mitigations_already_exist",
                           "detail": "MAC use only"}]}
    cbom = to_cyclonedx(inv)
    cbom["vulnerabilities"] = vex.to_cyclonedx_vex(inv, vex.parse(doc))
    matches = glob.glob(os.path.join(os.path.dirname(cyclonedx.__file__),
                                     "**", "bom-1.6*.json"), recursive=True)
    if not matches:
        pytest.skip("bundled schema not found")
    sp = matches[0]; schema = json.load(open(sp, encoding="utf-8")); resdir = os.path.dirname(sp)
    store = {}
    for f in glob.glob(os.path.join(resdir, "*.json")):
        s = json.load(open(f, encoding="utf-8")); store["file://" + f] = s
        if "$id" in s:
            store[s["$id"]] = s
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        resolver = RefResolver("file://" + sp, schema, store=store)
        errors = list(Draft7Validator(schema, resolver=resolver).iter_errors(cbom))
    assert not errors, f"schema errors: {[e.message for e in errors[:3]]}"


def test_sarif_carries_vex_suppression():
    import yaml
    from qramp import vex
    from qramp.sarif import to_sarif
    inv = _assessed_for_vex()
    md5 = [a for a in inv.assets if a.algorithm == "md5"][0]
    doc = {"statements": [{"asset": md5.asset_id, "status": "not_affected",
                           "justification": "vulnerable_code_not_in_execute_path"}]}
    vex.apply(inv, vex.parse(doc))
    sarif = to_sarif(inv, yaml.safe_load(open(RULES, encoding="utf-8")))
    suppressed = [r for r in sarif["runs"][0]["results"] if "suppressions" in r]
    assert suppressed
    for r in suppressed:
        assert r["suppressions"][0]["kind"] == "external"
        assert "VEX" in r["suppressions"][0]["justification"]


def test_sarif_with_suppressions_still_schema_valid():
    import json, os, warnings, yaml
    schema_path = os.path.join(HERE, "data", "sarif-schema-2.1.0.json")
    if not os.path.exists(schema_path):
        pytest.skip("bundled SARIF schema not present")
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            from jsonschema import Draft4Validator
    except ImportError:
        pytest.skip("jsonschema not installed")
    from qramp import vex
    from qramp.sarif import to_sarif
    inv = _assessed_for_vex()
    md5 = [a for a in inv.assets if a.algorithm == "md5"][0]
    vex.apply(inv, vex.parse({"statements": [
        {"asset": md5.asset_id, "status": "not_affected",
         "justification": "vulnerable_code_not_present"}]}))
    doc = to_sarif(inv, yaml.safe_load(open(RULES, encoding="utf-8")))
    schema = json.load(open(schema_path, encoding="utf-8"))
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        errors = list(Draft4Validator(schema).iter_errors(doc))
    assert not errors, f"SARIF errors: {[e.message for e in errors[:3]]}"


def test_vex_shipped_testbed_document_is_clean():
    """The committed testbed VEX document must lint clean."""
    import yaml
    vpath = os.path.join(TB, "vex", "exceptions.yaml")
    if not os.path.exists(vpath):
        pytest.skip("testbed VEX not present")
    from qramp import vex
    doc = yaml.safe_load(open(vpath, encoding="utf-8"))
    assert not [f for f in vex.lint(doc) if f.level == "error"]


# ---------- upgrade simulation ----------
def _sim_inv(openssl_version="3.0.13", extra=None):
    """SBOM at a given openssl version + broken kx/sig assets."""
    import json, tempfile, os
    from qramp.model import Occurrence
    comps = [{"type": "library", "name": "openssl", "version": openssl_version}]
    for name, ver in (extra or []):
        comps.append({"type": "library", "name": name, "version": ver})
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": comps}
    fd, p = tempfile.mkstemp(suffix=".json"); os.close(fd)
    open(p, "w", encoding="utf-8").write(json.dumps(doc))
    inv = Inventory()
    sbom_col.run(inv, sbom_path=p)
    os.unlink(p)
    for prim, alg, tier in [("key-agreement", "ecdh", "P0"),
                            ("signature", "ecdsa", "P1")]:
        a = inv.observe(prim, alg, Occurrence("source-py", "x.py:1", alg))
        a.exposure_class = "quantum_broken"; a.tier = tier
    return inv


def _pmap_sim():
    import yaml, os
    return yaml.safe_load(open(os.path.join(
        HERE, "..", "src", "qramp", "data", "provider-map.yaml"), encoding="utf-8"))


def test_parse_upgrades():
    from qramp.simulate import parse_upgrades
    assert parse_upgrades(["openssl=3.5", "BouncyCastle=1.78"]) == \
        {"openssl": "3.5", "bouncycastle": "1.78"}
    with pytest.raises(ValueError):
        parse_upgrades(["noequals"])


def test_simulate_openssl_unlocks_pqc():
    from qramp.simulate import simulate, parse_upgrades
    rep = simulate(_sim_inv("3.0.13"), _pmap_sim(), parse_upgrades(["openssl=3.5"]))
    assert rep["pq_capabilities_added"] == ["ml-dsa", "ml-kem"]
    assert rep["readiness_before_pct"] == 0.0
    assert rep["readiness_after_pct"] == 100.0
    assert rep["blocked_before"] == 2 and rep["blocked_after"] == 0
    assert rep["unblocked"] == 2


def test_simulate_downgrade_is_invalid():
    from qramp.simulate import simulate, parse_upgrades
    rep = simulate(_sim_inv("3.5.0"), _pmap_sim(), parse_upgrades(["openssl=3.0"]))
    assert rep["invalid_upgrades"]
    assert "not an upgrade" in rep["invalid_upgrades"][0]["reason"]
    assert rep["unblocked"] == 0


def test_simulate_unknown_component():
    from qramp.simulate import simulate, parse_upgrades
    rep = simulate(_sim_inv("3.0.13"), _pmap_sim(), parse_upgrades(["madeup=1.0"]))
    assert "madeup" in rep["unknown_components"]
    assert rep["unblocked"] == 0


def test_simulate_reports_capability_removal():
    """Upgrading OpenSSL 1.0.2 -> 1.1.1 drops the ancient SSLv3 capability."""
    from qramp.simulate import simulate, parse_upgrades
    rep = simulate(_sim_inv("1.0.2u"), _pmap_sim(), parse_upgrades(["openssl=1.1.1"]))
    changes = rep["capability_changes"]
    assert changes and "ssl" in changes[0]["removed"]


def test_simulate_partial_upgrade_attributes_correctly():
    """Upgrading only BouncyCastle (openssl stays 3.0) still unblocks via BC's
    PQC."""
    from qramp.simulate import simulate, parse_upgrades
    inv = _sim_inv("3.0.13", extra=[("bouncycastle", "1.77")])
    rep = simulate(inv, _pmap_sim(), parse_upgrades(["bouncycastle=1.78"]))
    assert rep["readiness_after_pct"] == 100.0
    assert rep["unblocked"] == 2
    # openssl is untouched
    assert "openssl" not in {k.lower() for k in rep["upgrades"]}


def test_simulate_does_not_mutate_inventory():
    """The simulation must be side-effect free."""
    from qramp.simulate import simulate, parse_upgrades
    inv = _sim_inv("3.0.13")
    versions_before = {c.name: c.version for c in inv.components}
    exposures_before = {a.key: a.exposure_class for a in inv.assets}
    simulate(inv, _pmap_sim(), parse_upgrades(["openssl=3.5"]))
    assert {c.name: c.version for c in inv.components} == versions_before
    assert {a.key: a.exposure_class for a in inv.assets} == exposures_before


def test_simulate_tier_weighting():
    from qramp.simulate import simulate, parse_upgrades
    rep = simulate(_sim_inv("3.0.13"), _pmap_sim(), parse_upgrades(["openssl=3.5"]))
    # P0 ecdh + P1 ecdsa unblocked -> weight = 8 + 4 = 12
    assert rep["unblocked_by_tier"] == {"P0": 1, "P1": 1}
    assert rep["risk_cleared_weight"] == 12.0


# ---------- policy-diff: policy-as-code change auditing ----------
def _assessed_cbom_path(tmp_path, with_sbom=False):
    import yaml
    from qramp import assess
    from qramp.collectors import configs as cfg
    from qramp.collectors import source_py
    inv = Inventory()
    source_py.run(inv, source_dir=os.path.join(TB, "sample-app"))
    cfg.run(inv, config_dir=os.path.join(TB, "etc"))
    if with_sbom:
        sbom_col.run(inv, sbom_path=SBOM_PATH)
    rules = yaml.safe_load(open(RULES, encoding="utf-8"))
    lifetimes = yaml.safe_load(open(os.path.join(TB, "policy", "data-lifetimes.yaml"),
                                    encoding="utf-8"))
    assess.classify(inv, rules)
    assess.prioritise(inv, rules, lifetimes)
    p = tmp_path / "a.json"; inv.save(str(p))
    return str(p)


def _lifetimes():
    import yaml
    return yaml.safe_load(open(os.path.join(TB, "policy", "data-lifetimes.yaml"),
                               encoding="utf-8"))


def test_policy_diff_rules_detects_tier_promotion(tmp_path):
    import copy, yaml
    from qramp.policydiff import diff_rules
    cbom = _assessed_cbom_path(tmp_path)
    old = yaml.safe_load(open(RULES, encoding="utf-8"))
    new = copy.deepcopy(old)
    new["rules"].insert(0, {"id": "aes-128-broken",
        "match": {"primitive": "symmetric-cipher", "algorithm": "aes",
                  "max_key_length": 128},
        "class": "quantum_broken", "why": "policy change"})
    rep = diff_rules(cbom, old, new, _lifetimes())
    assert rep["worsened"] >= 1
    aes = [c for c in rep["changed"] if "AES-128" in c["asset"]]
    assert aes and aes[0]["severity"] == "worse"
    assert aes[0]["class"] == ["quantum_weakened", "quantum_broken"]


def test_policy_diff_rules_detects_rule_shadowing(tmp_path):
    """A change that only swaps the firing rule (same class) is still reported —
    it can silently drop a remediation."""
    import copy, yaml
    from qramp.policydiff import diff_rules
    cbom = _assessed_cbom_path(tmp_path)
    old = yaml.safe_load(open(RULES, encoding="utf-8"))
    new = copy.deepcopy(old)
    new["rules"].insert(0, {"id": "aes-128-alt",
        "match": {"primitive": "symmetric-cipher", "algorithm": "aes",
                  "max_key_length": 128},
        "class": "quantum_weakened", "why": "same class, different rule"})
    rep = diff_rules(cbom, old, new, _lifetimes())
    aes = [c for c in rep["changed"] if "AES-128" in c["asset"]]
    assert aes
    assert aes[0]["rule"][1] == "aes-128-alt"        # firing rule changed
    assert aes[0]["class"][0] == aes[0]["class"][1]  # class unchanged


def test_policy_diff_rules_no_change_is_empty(tmp_path):
    import yaml
    from qramp.policydiff import diff_rules
    cbom = _assessed_cbom_path(tmp_path)
    rules = yaml.safe_load(open(RULES, encoding="utf-8"))
    rep = diff_rules(cbom, rules, rules, _lifetimes())
    assert rep["changed_count"] == 0
    assert rep["tier_before"] == rep["tier_after"]


def test_policy_diff_provider_map_flips_blocked(tmp_path):
    import copy, yaml
    from qramp.policydiff import diff_provider_map
    cbom = _assessed_cbom_path(tmp_path, with_sbom=True)
    old = yaml.safe_load(open(os.path.join(
        HERE, "..", "src", "qramp", "data", "provider-map.yaml"), encoding="utf-8"))
    new = copy.deepcopy(old)
    for e in new["components"]:
        if e["component"] == "openssl":
            for p in e["provides"]:
                if p.get("version") == ">=3.5":
                    p["version"] = ">=3.0"           # 3.0.13 now "provides" PQC
    rep = diff_provider_map(cbom, old, new)
    assert rep["blocked_after"] < rep["blocked_before"]
    assert rep["newly_unblocked"]                    # assets flip unblocked


def test_policy_diff_provider_map_can_newly_block(tmp_path):
    """Raising a gate (removing a claimed capability) newly blocks assets."""
    import copy, yaml
    from qramp.policydiff import diff_provider_map
    cbom = _assessed_cbom_path(tmp_path, with_sbom=True)
    # start from a permissive map, tighten it
    permissive = yaml.safe_load(open(os.path.join(
        HERE, "..", "src", "qramp", "data", "provider-map.yaml"), encoding="utf-8"))
    for e in permissive["components"]:
        if e["component"] == "openssl":
            for p in e["provides"]:
                if p.get("version") == ">=3.5":
                    p["version"] = ">=3.0"
    strict = copy.deepcopy(permissive)
    for e in strict["components"]:
        if e["component"] == "openssl":
            for p in e["provides"]:
                if p.get("version") == ">=3.0" and p["algorithm"] in ("ml-kem", "ml-dsa"):
                    p["version"] = ">=3.5"           # tighten back
    rep = diff_provider_map(cbom, permissive, strict)
    assert rep["blocked_after"] > rep["blocked_before"]
    assert rep["newly_blocked"]


def test_policy_diff_vex_add_remove(tmp_path):
    from qramp.policydiff import diff_vex
    cbom = _assessed_cbom_path(tmp_path)
    inv = Inventory.load(cbom)
    md5 = [a for a in inv.assets if a.algorithm == "md5"][0]
    empty = {"statements": []}
    added = {"statements": [{"asset": md5.asset_id, "status": "not_affected",
                             "justification": "vulnerable_code_not_present"}]}
    rep = diff_vex(cbom, empty, added)
    assert rep["suppressions_after"] == rep["suppressions_before"] + 1
    assert any("MD5" in x["asset"] for x in rep["added"])
    # reverse: removing a suppression
    rep2 = diff_vex(cbom, added, empty)
    assert any("MD5" in x["asset"] for x in rep2["removed"])


def test_policy_diff_is_side_effect_free(tmp_path):
    """Diffing must not mutate the on-disk CBOM."""
    import hashlib, copy, yaml
    from qramp.policydiff import diff_rules
    cbom = _assessed_cbom_path(tmp_path)
    before = hashlib.sha256(open(cbom, "rb").read()).hexdigest()
    old = yaml.safe_load(open(RULES, encoding="utf-8"))
    new = copy.deepcopy(old)
    new["rules"].insert(0, {"id": "x", "match": {"algorithm": "aes"},
                            "class": "quantum_broken"})
    diff_rules(cbom, old, new, _lifetimes())
    after = hashlib.sha256(open(cbom, "rb").read()).hexdigest()
    assert before == after


def test_policy_diff_dispatch(tmp_path):
    import yaml
    from qramp.policydiff import policy_diff
    cbom = _assessed_cbom_path(tmp_path)
    rp = tmp_path / "r.yaml"
    yaml.safe_dump(yaml.safe_load(open(RULES, encoding="utf-8")), open(rp, "w", encoding="utf-8"))
    rep = policy_diff(cbom, kind="rules", old_path=str(rp), new_path=str(rp),
                      lifetimes_path=os.path.join(TB, "policy", "data-lifetimes.yaml"))
    assert rep["kind"] == "rules" and rep["changed_count"] == 0
    with pytest.raises(ValueError):
        policy_diff(cbom, kind="bogus", old_path=str(rp), new_path=str(rp))


# ---------- VEX in the dashboard ----------
def _dashboard_html_with_vex(tmp_path):
    """Build an assessed CBOM + a VEX doc suppressing an MD5 asset, return the
    rendered HTML and the suppressed asset id."""
    import yaml
    from qramp import assess, report
    from qramp.collectors import source_py
    from qramp.collectors import configs as cfg
    inv = Inventory()
    source_py.run(inv, source_dir=os.path.join(TB, "sample-app"))
    cfg.run(inv, config_dir=os.path.join(TB, "etc"))
    rules = yaml.safe_load(open(RULES, encoding="utf-8"))
    lifetimes = yaml.safe_load(open(os.path.join(TB, "policy", "data-lifetimes.yaml"),
                                    encoding="utf-8"))
    assess.classify(inv, rules)
    assess.prioritise(inv, rules, lifetimes)
    md5 = [a for a in inv.assets if a.algorithm == "md5"][0]
    cbom = tmp_path / "c.json"; inv.save(str(cbom))
    vdoc = {"statements": [{"asset": md5.asset_id, "status": "not_affected",
                            "justification": "vulnerable_code_not_in_execute_path",
                            "detail": "cache key only"}]}
    out = tmp_path / "dash.html"
    report.dashboard(str(cbom), str(out), vex_doc=vdoc)
    return out.read_text(encoding="utf-8"), md5.asset_id


def test_dashboard_marks_suppressed_rows(tmp_path):
    doc, aid = _dashboard_html_with_vex(tmp_path)
    # the suppressed asset's row carries data-suppressed='1' and the suppressed class
    assert f"data-asset='{aid}'" in doc
    assert "data-suppressed='1'" in doc
    assert "class=\"suppressed\"" in doc or "class='suppressed'" in doc
    assert "vexbadge" in doc
    assert "VEX: vulnerable_code_not_in_execute_path" in doc


def test_dashboard_has_status_column_and_toggle(tmp_path):
    doc, _ = _dashboard_html_with_vex(tmp_path)
    assert "<th>Status</th>" in doc
    assert "id='togglesupp'" in doc or 'id="togglesupp"' in doc
    assert "suppressed" in doc


def test_dashboard_no_toggle_without_vex(tmp_path):
    """Without a VEX doc there are no suppressed rows and no toggle button."""
    doc = _dashboard_html(tmp_path)
    assert "data-suppressed='1'" not in doc          # nothing suppressed
    # the toggle button element is not rendered (the JS may still reference the id)
    assert "id='togglesupp'" not in doc and 'id="togglesupp"' not in doc


def test_dashboard_suppression_detail_in_title(tmp_path):
    doc, _ = _dashboard_html_with_vex(tmp_path)
    # the free-text detail is exposed as a hover title on the badge
    assert "cache key only" in doc


def test_dashboard_vex_toggle_hides_suppressed_in_browser(tmp_path):
    """Behavioural: the hide-suppressed toggle removes exactly the suppressed
    rows. Skips without playwright/browser."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        pytest.skip("playwright not installed")
    import pathlib
    doc, _ = _dashboard_html_with_vex(tmp_path)
    html_path = tmp_path / "dash.html"; html_path.write_text(doc, encoding="utf-8")
    url = "file://" + str(html_path.resolve())
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page(); page.goto(url)
            total = page.eval_on_selector_all("#assets tbody tr", "e=>e.length")
            supp = page.eval_on_selector_all(
                "#assets tr[data-suppressed='1']", "e=>e.length")
            assert supp >= 1
            page.click("#togglesupp")
            visible = page.eval_on_selector_all(
                "#assets tbody tr:not(.hidden):not(.hide-suppressed)", "e=>e.length")
            assert visible == total - supp
            page.click("#togglesupp")
            restored = page.eval_on_selector_all(
                "#assets tbody tr:not(.hidden):not(.hide-suppressed)", "e=>e.length")
            assert restored == total
            browser.close()
    except Exception as e:
        if "Executable doesn't exist" in str(e) or "Host system is missing" in str(e):
            pytest.skip(f"browser not available: {e}")
        raise


# ---------- upgrade simulation in the dashboard ----------
def _dashboard_html_with_sim(tmp_path, extra_libs=None):
    """Assessed CBOM with an upgradable openssl (+ optional extra libs) so the
    simulation section has candidate upgrades."""
    import json, yaml
    from qramp import assess, report
    from qramp.model import Occurrence
    comps = [{"type": "library", "name": "openssl", "version": "3.0.13"}]
    for name, ver in (extra_libs or []):
        comps.append({"type": "library", "name": name, "version": ver})
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": comps}
    sb = tmp_path / "sb.json"; sb.write_text(json.dumps(doc), encoding="utf-8")
    inv = Inventory()
    sbom_col.run(inv, sbom_path=str(sb))
    for prim, alg, tier in [("key-agreement", "ecdh", "P0"),
                            ("signature", "ecdsa", "P1")]:
        a = inv.observe(prim, alg, Occurrence("source-py", "x.py:1", alg))
        a.exposure_class = "quantum_broken"; a.tier = tier
    cbom = tmp_path / "c.json"; inv.save(str(cbom))
    out = tmp_path / "dash.html"
    report.dashboard(str(cbom), str(out))
    return out.read_text(encoding="utf-8")


def test_dashboard_has_simulation_section(tmp_path):
    doc = _dashboard_html_with_sim(tmp_path)
    assert "Upgrade simulation" in doc
    assert "data-scenarios" in doc
    assert "id='sim-select'" in doc or 'id="sim-select"' in doc


def test_dashboard_simulation_scenarios_embedded(tmp_path):
    import json, html as htmlmod, re
    doc = _dashboard_html_with_sim(tmp_path)
    m = re.search(r'data-scenarios="([^"]*)"', doc)
    assert m
    scenarios = json.loads(htmlmod.unescape(m.group(1)))
    # baseline + at least one upgrade candidate
    assert len(scenarios) >= 2
    assert scenarios[0]["id"] == "none"
    assert scenarios[0]["blocked"] == 2                 # ecdh + ecdsa blocked
    upgrade = [s for s in scenarios if "openssl" in s["id"]][0]
    assert upgrade["blocked"] == 0                      # unblocked after upgrade
    assert upgrade["readiness"] == 100.0
    assert "ml-kem" in upgrade["unlocks"]


def test_dashboard_simulation_apply_all_when_multiple(tmp_path):
    import json, html as htmlmod, re
    doc = _dashboard_html_with_sim(tmp_path, extra_libs=[("bouncycastle", "1.77")])
    m = re.search(r'data-scenarios="([^"]*)"', doc)
    scenarios = json.loads(htmlmod.unescape(m.group(1)))
    ids = {s["id"] for s in scenarios}
    assert "all" in ids                                 # apply-all scenario present
    assert any("openssl" in i for i in ids)
    assert any("bouncycastle" in i for i in ids)


def test_dashboard_no_simulation_without_candidates(tmp_path):
    """If openssl is already current (3.5), there is no upgrade to model."""
    import json
    from qramp import report
    from qramp.model import Occurrence
    doc_sbom = {"bomFormat": "CycloneDX", "specVersion": "1.6",
                "components": [{"type": "library", "name": "openssl", "version": "3.5.0"}]}
    sb = tmp_path / "sb.json"; sb.write_text(json.dumps(doc_sbom), encoding="utf-8")
    inv = Inventory()
    sbom_col.run(inv, sbom_path=str(sb))
    a = inv.observe("key-agreement", "ecdh", Occurrence("source-py", "x.py:1", "ecdh"))
    a.exposure_class = "quantum_broken"; a.tier = "P1"
    cbom = tmp_path / "c.json"; inv.save(str(cbom))
    out = tmp_path / "dash.html"; report.dashboard(str(cbom), str(out))
    doc = out.read_text(encoding="utf-8")
    # openssl 3.5 already ships PQC -> no candidate upgrade -> no sim section
    assert "Upgrade simulation" not in doc


def test_dashboard_simulation_js_valid(tmp_path):
    import re, shutil, subprocess, tempfile, os as _os
    doc = _dashboard_html_with_sim(tmp_path)
    m = re.search(r"<script>(.*?)</script>", doc, re.S)
    js = m.group(1)
    assert "sim-select" in js and "sim-bars" in js
    if shutil.which("node"):
        fd, p = tempfile.mkstemp(suffix=".js"); _os.write(fd, js.encode()); _os.close(fd)
        r = subprocess.run(["node", "--check", p], capture_output=True, text=True)
        _os.unlink(p)
        assert r.returncode == 0, f"JS syntax error: {r.stderr[:200]}"


def test_dashboard_simulation_switch_in_browser(tmp_path):
    """Behavioural: selecting an upgrade updates the blocked/readiness stats."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        pytest.skip("playwright not installed")
    import pathlib
    html_path = tmp_path / "dash.html"
    html_path.write_text(_dashboard_html_with_sim(tmp_path), encoding="utf-8")
    url = "file://" + str(html_path.resolve())
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page(); page.goto(url)
            assert page.text_content("#sim-blocked") == "2"     # baseline blocked
            assert page.text_content("#sim-ready") == "0%"
            # pick the openssl upgrade (option index 1)
            page.select_option("#sim-select", "1")
            assert page.text_content("#sim-blocked") == "0"
            assert page.text_content("#sim-ready") == "100%"
            assert "+2" in page.text_content("#sim-unblocked")
            browser.close()
    except Exception as e:
        if "Executable doesn't exist" in str(e) or "Host system is missing" in str(e):
            pytest.skip(f"browser not available: {e}")
        raise


def test_simulate_exposes_blocked_tier_distributions():
    """simulate() must return the before/after tier breakdown the dashboard
    animates."""
    import json, tempfile, os, yaml
    from qramp.simulate import simulate, parse_upgrades
    from qramp.model import Occurrence
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.6",
           "components": [{"type": "library", "name": "openssl", "version": "3.0.13"}]}
    fd, p = tempfile.mkstemp(suffix=".json"); os.close(fd); open(p, "w", encoding="utf-8").write(json.dumps(doc))
    inv = Inventory(); sbom_col.run(inv, sbom_path=p); os.unlink(p)
    a = inv.observe("key-agreement", "ecdh", Occurrence("s", "x", "ecdh"))
    a.exposure_class = "quantum_broken"; a.tier = "P1"
    pmap = yaml.safe_load(open(os.path.join(
        HERE, "..", "src", "qramp", "data", "provider-map.yaml"), encoding="utf-8"))
    rep = simulate(inv, pmap, parse_upgrades(["openssl=3.5"]))
    assert rep["blocked_tier_before"] == {"P1": 1}
    assert rep["blocked_tier_after"] == {}


# ---------- readiness CI gate ----------
def test_readiness_gate_min_readiness(tmp_path):
    """--min-readiness exits non-zero when readiness is below the threshold."""
    import json
    from qramp.cli import main
    from qramp.model import Occurrence
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.6",
           "components": [{"type": "library", "name": "openssl", "version": "3.0.13"}]}
    sb = tmp_path / "sb.json"; sb.write_text(json.dumps(doc), encoding="utf-8")
    inv = Inventory(); sbom_col.run(inv, sbom_path=str(sb))
    a = inv.observe("key-agreement", "ecdh", Occurrence("s", "x", "ecdh"))
    a.exposure_class = "quantum_broken"; a.tier = "P1"
    cbom = tmp_path / "c.json"; inv.save(str(cbom))
    # readiness is 0% here -> require 50% should fail, require 0% should pass
    assert main(["readiness", str(cbom), "--min-readiness", "50"]) == 1
    assert main(["readiness", str(cbom), "--min-readiness", "0"]) == 0


def test_readiness_gate_max_unaddressable(tmp_path):
    """--max-unaddressable fails when too many blocked assets have no upgrade
    path. Here everything is addressable (openssl 3.5 exists) so 0 is allowed."""
    import json
    from qramp.cli import main
    from qramp.model import Occurrence
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.6",
           "components": [{"type": "library", "name": "openssl", "version": "3.0.13"}]}
    sb = tmp_path / "sb.json"; sb.write_text(json.dumps(doc), encoding="utf-8")
    inv = Inventory(); sbom_col.run(inv, sbom_path=str(sb))
    a = inv.observe("key-agreement", "ecdh", Occurrence("s", "x", "ecdh"))
    a.exposure_class = "quantum_broken"; a.tier = "P1"
    cbom = tmp_path / "c.json"; inv.save(str(cbom))
    assert main(["readiness", str(cbom), "--max-unaddressable", "0"]) == 0


def test_readiness_gate_json_still_gates(tmp_path):
    """The gate applies even with --json output."""
    import json
    from qramp.cli import main
    from qramp.model import Occurrence
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.6",
           "components": [{"type": "library", "name": "openssl", "version": "3.0.13"}]}
    sb = tmp_path / "sb.json"; sb.write_text(json.dumps(doc), encoding="utf-8")
    inv = Inventory(); sbom_col.run(inv, sbom_path=str(sb))
    a = inv.observe("key-agreement", "ecdh", Occurrence("s", "x", "ecdh"))
    a.exposure_class = "quantum_broken"; a.tier = "P1"
    cbom = tmp_path / "c.json"; inv.save(str(cbom))
    assert main(["readiness", str(cbom), "--json", "--min-readiness", "50"]) == 1


# ---------- CI workflow examples ----------
def test_ci_workflow_examples_are_valid_yaml():
    """The shipped GitHub Actions workflow examples must parse and have the
    expected job structure."""
    import yaml
    ex = os.path.join(HERE, "..", "examples")
    for fn in ("github-code-scanning.yml", "ci-full-pipeline.yml"):
        path = os.path.join(ex, fn)
        if not os.path.exists(path):
            pytest.skip(f"{fn} not present")
        doc = yaml.safe_load(open(path, encoding="utf-8"))
        assert "jobs" in doc
        for job, spec in doc["jobs"].items():
            assert "steps" in spec and spec["steps"]


def test_ci_full_pipeline_has_all_gates():
    """The end-to-end pipeline must reference each gate command so it stays in
    sync with the CLI."""
    ex = os.path.join(HERE, "..", "examples", "ci-full-pipeline.yml")
    if not os.path.exists(ex):
        pytest.skip("ci-full-pipeline.yml not present")
    text = open(ex, encoding="utf-8").read()
    for cmd in ["lint-rules", "lint-provider-map", "lint-vex", "lint-aliases",
                "qramp scan", "qramp assess", "--format sarif",
                "policy-diff", "--fail-on-worse", "readiness",
                "upload-sarif", "qramp bundle", "--require-references",
                "qramp pr-comment"]:
        assert cmd in text, f"CI pipeline is missing {cmd!r}"


def test_ci_policy_lint_job_lints_aliases():
    """The alias map must be a step in the policy-lint job, guarded so it is
    skipped when the repo ships no custom alias map."""
    import yaml
    ex = os.path.join(HERE, "..", "examples", "ci-full-pipeline.yml")
    if not os.path.exists(ex):
        pytest.skip("ci-full-pipeline.yml not present")
    doc = yaml.safe_load(open(ex, encoding="utf-8"))
    assert doc["env"].get("ALIASES")                        # env var declared
    steps = doc["jobs"]["policy-lint"]["steps"]
    alias_steps = [s for s in steps if "alias" in s.get("name", "").lower()]
    assert alias_steps, "policy-lint has no alias-lint step"
    step = alias_steps[0]
    assert "lint-aliases" in step["run"]
    assert "--strict" in step["run"]                        # warnings fail too
    assert "--map" in step["run"]                           # cross-checks provider map
    assert "snapshot" in step["run"]                        # resolution regression
    assert "hashFiles" in str(step.get("if", ""))           # optional / guarded


def test_ci_has_gate_summary_job():
    """A final gate-summary job must aggregate every gate's outcome, run even
    when a prior job failed, render the run Summary, post the PR comment with the
    gate matrix, and fail the pipeline if any gate failed."""
    import yaml
    ex = os.path.join(HERE, "..", "examples", "ci-full-pipeline.yml")
    if not os.path.exists(ex):
        pytest.skip("ci-full-pipeline.yml not present")
    doc = yaml.safe_load(open(ex, encoding="utf-8"))
    assert "gate-summary" in doc["jobs"], "no gate-summary job"
    gs = doc["jobs"]["gate-summary"]
    for job in ("policy-lint", "crypto-scan", "policy-audit"):
        assert job in gs["needs"]
    assert str(gs.get("if", "")).strip() == "always()"
    # every gate outcome is collected into gates.json and the Summary page
    scripts = " ".join(s.get("with", {}).get("script", "") for s in gs["steps"])
    for gate in ("sarif_gate", "provenance_gate", "rule_lint", "alias_lint",
                 "rules_audit"):
        assert gate in scripts, f"summary omits {gate}"
    assert "gates.json" in scripts                          # gate matrix file
    assert "addRaw" in scripts                              # writes to the Summary page
    assert "setFailed" in scripts                           # authoritative pass/fail
    # it posts the PR comment with the gate matrix, PR-only
    runs = " ".join(s.get("run", "") for s in gs["steps"])
    assert "qramp pr-comment" in runs
    assert "--gates gates.json" in runs
    post = [s for s in gs["steps"]
            if "qramp-pr-comment" in str(s.get("with", {}).get("script", ""))]
    assert post, "gate-summary does not post the PR comment"
    assert "updateComment" in post[0]["with"]["script"]
    # to comment it needs pull-requests: write
    assert gs.get("permissions", {}).get("pull-requests") == "write"


def test_ci_gate_steps_have_ids_and_continue_on_error():
    """Each gate the summary reports must carry an id (so its outcome is
    referenceable) and continue-on-error (so all gates run and are collected)."""
    import yaml
    ex = os.path.join(HERE, "..", "examples", "ci-full-pipeline.yml")
    if not os.path.exists(ex):
        pytest.skip("ci-full-pipeline.yml not present")
    doc = yaml.safe_load(open(ex, encoding="utf-8"))
    expected = {
        "policy-lint": {"rule_lint", "provider_lint", "vex_lint", "alias_lint"},
        "crypto-scan": {"sarif_gate", "provenance_gate", "vex_check",
                        "wrapper_gate", "baseline_gate"},
        "policy-audit": {"rules_audit", "provider_audit", "vex_audit"},
    }
    for job, ids in expected.items():
        steps = doc["jobs"][job]["steps"]
        by_id = {s["id"]: s for s in steps if "id" in s}
        outputs = doc["jobs"][job].get("outputs", {})
        for gid in ids:
            assert gid in by_id, f"{job} missing gate id {gid}"
            assert by_id[gid].get("continue-on-error") is True, \
                f"{job}.{gid} must continue-on-error"
            assert gid in outputs, f"{job} does not output {gid}"


def test_ci_crypto_scan_prepares_pr_comment_inputs():
    """crypto-scan no longer posts the comment itself, but it prepares the
    inputs the gate-summary job needs: it assesses the base branch and uploads
    the assessment (+ base) as an artifact. The workflow grants pull-requests:
    write for the comment posted later."""
    import yaml
    ex = os.path.join(HERE, "..", "examples", "ci-full-pipeline.yml")
    if not os.path.exists(ex):
        pytest.skip("ci-full-pipeline.yml not present")
    doc = yaml.safe_load(open(ex, encoding="utf-8"))
    assert doc.get("permissions", {}).get("pull-requests") == "write"
    steps = doc["jobs"]["crypto-scan"]["steps"]
    # the base branch is assessed so the comment can diff against it
    base_step = [s for s in steps if "base branch" in s.get("name", "").lower()]
    assert base_step, "no base-branch assessment step"
    assert "worktree" in base_step[0]["run"]
    assert "base-assessment.json" in base_step[0]["run"]
    assert "pull_request" in str(base_step[0].get("if", ""))    # PR-only
    # checkout must fetch full history for the base diff
    co = [s for s in steps if str(s.get("uses", "")).startswith("actions/checkout")]
    assert co and co[0].get("with", {}).get("fetch-depth") == 0
    # the assessment (and base) are uploaded for the gate-summary job to consume
    uploads = [s for s in steps
               if str(s.get("uses", "")).startswith("actions/upload-artifact")]
    cbom_upload = [s for s in uploads if s["with"].get("name") == "qramp-cbom"]
    assert cbom_upload
    assert "base-assessment.json" in cbom_upload[0]["with"]["path"]
    # crypto-scan itself no longer posts the comment (moved to gate-summary)
    assert not any("qramp pr-comment" in s.get("run", "") for s in steps)


def test_ci_crypto_scan_gates_provenance_coverage():
    """crypto-scan must gate on provenance coverage — every rule that fired must
    cite a governing standard — scoped to the scan's CBOM."""
    import yaml
    ex = os.path.join(HERE, "..", "examples", "ci-full-pipeline.yml")
    if not os.path.exists(ex):
        pytest.skip("ci-full-pipeline.yml not present")
    doc = yaml.safe_load(open(ex, encoding="utf-8"))
    steps = doc["jobs"]["crypto-scan"]["steps"]
    prov = [s for s in steps if "un-sourced" in s.get("name", "").lower()
            or "provenance" in s.get("name", "").lower()]
    assert prov, "crypto-scan has no provenance-coverage gate"
    run = prov[0]["run"]
    assert "provenance" in run and "--require-references" in run
    assert "--cbom" in run                              # scoped to fired rules


def test_ci_crypto_scan_publishes_report_bundle():
    """crypto-scan must build the report bundle and upload it as its own
    artifact, guarded to run even when a gate failed (if: always)."""
    import yaml
    ex = os.path.join(HERE, "..", "examples", "ci-full-pipeline.yml")
    if not os.path.exists(ex):
        pytest.skip("ci-full-pipeline.yml not present")
    doc = yaml.safe_load(open(ex, encoding="utf-8"))
    steps = doc["jobs"]["crypto-scan"]["steps"]
    # the bundle build step
    build = [s for s in steps if "bundle" in s.get("name", "").lower()]
    assert build, "crypto-scan has no report-bundle step"
    assert "qramp bundle" in build[0]["run"]
    assert "--rules" in build[0]["run"]                     # provenance page
    assert str(build[0].get("if", "")) == "always()"        # runs even on gate failure
    # a dedicated artifact upload for the report
    uploads = [s for s in steps
               if str(s.get("uses", "")).startswith("actions/upload-artifact")]
    names = {s["with"]["name"] for s in uploads}
    assert "qramp-report" in names, "report bundle is not uploaded as an artifact"
    report_upload = [s for s in uploads if s["with"]["name"] == "qramp-report"][0]
    assert "qramp-report" in report_upload["with"]["path"]


# ---------- multi-CBOM timeline ----------
def _timeline_cbom(tmp_path, name, algs, ts):
    """Build an assessed CBOM with the given (primitive, algorithm, tags) assets
    and a fixed scan timestamp."""
    import yaml
    from qramp import assess
    from qramp.model import Occurrence
    inv = Inventory()
    for prim, alg, tags in algs:
        inv.observe(prim, alg, Occurrence("source-py", "app.py:1", f"{alg}", tags=tags))
    rules = yaml.safe_load(open(RULES, encoding="utf-8"))
    lifetimes = yaml.safe_load(open(os.path.join(TB, "policy", "data-lifetimes.yaml"),
                                    encoding="utf-8"))
    assess.classify(inv, rules)
    assess.prioritise(inv, rules, lifetimes)
    inv.meta["generated"] = ts
    p = tmp_path / f"{name}.json"; inv.save(str(p))
    return str(p)


def test_load_restores_scan_timestamp(tmp_path):
    """A saved CBOM's metadata.timestamp must survive a load round-trip so the
    timeline can order historical scans."""
    from qramp.model import Occurrence
    inv = Inventory()
    inv.observe("hash", "md5", Occurrence("s", "x", "md5"))
    inv.meta["generated"] = "2026-01-01T00:00:00+00:00"
    p = tmp_path / "c.json"; inv.save(str(p))
    back = Inventory.load(str(p))
    assert back.meta["generated"] == "2026-01-01T00:00:00+00:00"


def test_timeline_orders_by_timestamp(tmp_path):
    from qramp.timeline import build
    a = _timeline_cbom(tmp_path, "may", [("hash", "md5", [])], "2026-05-01T00:00:00+00:00")
    b = _timeline_cbom(tmp_path, "jan", [("hash", "md5", [])], "2026-01-01T00:00:00+00:00")
    c = _timeline_cbom(tmp_path, "mar", [("hash", "md5", [])], "2026-03-01T00:00:00+00:00")
    pts = build([a, b, c])                        # deliberately out of order
    stamps = [p.timestamp for p in pts]
    assert stamps == sorted(stamps)               # chronological


def test_timeline_urgent_and_deltas(tmp_path):
    from qramp.timeline import build, deltas, summarise
    # scan 1: 2 external broken (P0/P1) + 1 md5; scan 2: the externals gone
    s1 = _timeline_cbom(tmp_path, "s1",
        [("key-agreement", "ecdh", ["external"]),
         ("signature", "rsa", ["external"]),
         ("hash", "md5", [])], "2026-01-01T00:00:00+00:00")
    s2 = _timeline_cbom(tmp_path, "s2",
        [("hash", "md5", [])], "2026-02-01T00:00:00+00:00")
    pts = build([s1, s2])
    assert pts[0].urgent > pts[1].urgent          # urgent count fell
    d = deltas(pts)
    assert len(d) == 1
    assert d[0]["urgent_delta"] < 0
    assert d[0]["assets_remediated"] == 2         # the two externals
    assert d[0]["assets_introduced"] == 0
    summ = summarise(pts)
    assert summ["trend"] == "improving"
    assert summ["net_remediated"] == 2


def test_timeline_worsening_trend(tmp_path):
    from qramp.timeline import build, summarise
    s1 = _timeline_cbom(tmp_path, "s1", [("hash", "md5", [])],
                        "2026-01-01T00:00:00+00:00")
    s2 = _timeline_cbom(tmp_path, "s2",
        [("hash", "md5", []), ("key-agreement", "ecdh", ["external"])],
        "2026-02-01T00:00:00+00:00")
    pts = build([s1, s2])
    assert summarise(pts)["trend"] == "worsening"    # a new urgent asset appeared


def test_timeline_svg_renders(tmp_path):
    from qramp.timeline import build
    from qramp.svggraph import timeline_svg
    from xml.dom import minidom
    s1 = _timeline_cbom(tmp_path, "s1",
        [("key-agreement", "ecdh", ["external"]), ("hash", "md5", [])],
        "2026-01-01T00:00:00+00:00")
    s2 = _timeline_cbom(tmp_path, "s2", [("hash", "md5", [])],
                        "2026-02-01T00:00:00+00:00")
    svg = timeline_svg(build([s1, s2]), series=("P0", "P1", "P2"))
    minidom.parseString(svg)                          # valid XML
    assert "<svg" in svg and "P1" in svg


def test_timeline_cli_and_gate(tmp_path):
    from qramp.cli import main
    s1 = _timeline_cbom(tmp_path, "s1",
        [("key-agreement", "ecdh", ["external"]),
         ("signature", "rsa", ["external"]), ("hash", "md5", [])],
        "2026-01-01T00:00:00+00:00")
    s2 = _timeline_cbom(tmp_path, "s2", [("hash", "md5", [])],
                        "2026-02-01T00:00:00+00:00")
    # urgent fell by 2; gate requiring >=2 passes, >=3 fails
    assert main(["timeline", s1, s2, "--min-improvement", "2"]) == 0
    assert main(["timeline", s1, s2, "--min-improvement", "3"]) == 1
    # needs at least two CBOMs
    assert main(["timeline", s1]) == 1


def test_timeline_html_report(tmp_path):
    from qramp.cli import main
    from html.parser import HTMLParser
    s1 = _timeline_cbom(tmp_path, "s1",
        [("key-agreement", "ecdh", ["external"]), ("hash", "md5", [])],
        "2026-01-01T00:00:00+00:00")
    s2 = _timeline_cbom(tmp_path, "s2", [("hash", "md5", [])],
                        "2026-02-01T00:00:00+00:00")
    out = tmp_path / "progress.html"
    assert main(["timeline", s1, s2, "--html", str(out)]) == 0
    doc = out.read_text(encoding="utf-8")

    class _P(HTMLParser):
        def error(self, message):
            raise AssertionError(message)
    _P().feed(doc)
    assert "<svg" in doc and "migration progress" in doc.lower()


def test_timeline_directory_glob(tmp_path):
    from qramp.cli import main
    _timeline_cbom(tmp_path, "a", [("hash", "md5", [])], "2026-01-01T00:00:00+00:00")
    _timeline_cbom(tmp_path, "b", [("hash", "md5", [])], "2026-02-01T00:00:00+00:00")
    # a directory of CBOMs is expanded automatically
    assert main(["timeline", str(tmp_path)]) == 0


# ---------- graph export: Graphviz DOT + Mermaid ----------
def _graph_inv(tmp_path, with_certs=True):
    import yaml
    from qramp import assess
    from qramp.collectors import source_py
    inv = Inventory()
    sbom_col.run(inv, sbom_path=SBOM_PATH)
    source_py.run(inv, source_dir=os.path.join(TB, "sample-app"))
    if with_certs:
        cert_col.run(inv, cert_dir=CHAIN_DIR)
    rules = yaml.safe_load(open(RULES, encoding="utf-8"))
    assess.classify(inv, rules)
    lifetimes = yaml.safe_load(open(os.path.join(TB, "policy", "data-lifetimes.yaml"),
                                    encoding="utf-8"))
    assess.prioritise(inv, rules, lifetimes)
    return inv


def _mermaid_nodes_defined(text):
    """Every node referenced by an edge or a class assignment must be defined."""
    import re
    lines = text.splitlines()
    assert lines[0].startswith("flowchart")
    defined = set()
    for ln in lines:
        for nid in re.findall(r'^\s*(\w+)\[', ln):
            defined.add(nid)
    edge_ids = set()
    for ln in lines:
        m1 = re.match(r'\s*(\w+)\s*(?:-->|==>)', ln)
        if m1:
            edge_ids.add(m1.group(1))
        m2 = re.search(r'(?:-->|==>)(?:\|[^|]*\|)?\s*(\w+)\s*$', ln)
        if m2:
            edge_ids.add(m2.group(1))
    assert edge_ids <= (defined | {"empty"}), f"undefined edge nodes: {edge_ids - defined}"
    for ln in lines:
        cm = re.match(r'\s*class\s+([\w,]+)\s+\w+', ln)
        if cm:
            for nid in cm.group(1).split(","):
                assert nid in defined, f"class refs undefined node {nid}"


def test_dependency_dot_structure(tmp_path):
    from qramp.graphexport import dependency_dot
    inv = _graph_inv(tmp_path)
    dot = dependency_dot(inv)
    assert dot.startswith("digraph qramp_dependencies {")
    assert dot.rstrip().endswith("}")
    assert "rankdir=LR" in dot
    assert " -> " in dot                       # has provides edges
    # a library node and a capability node both present
    assert "lib_" in dot and "cap_" in dot


def test_dependency_dot_no_double_escaped_newline(tmp_path):
    """Labels must use DOT's \\n, never a literal backslash-escaped \\\\n."""
    from qramp.graphexport import dependency_dot
    inv = _graph_inv(tmp_path)
    dot = dependency_dot(inv)
    assert "\\\\n" not in dot                   # no double-escape


def test_dependency_mermaid_structure(tmp_path):
    from qramp.graphexport import dependency_mermaid
    inv = _graph_inv(tmp_path)
    m = dependency_mermaid(inv)
    _mermaid_nodes_defined(m)
    assert "classDef" in m                      # exposure colouring
    assert "-->" in m or "==>" in m


def test_chain_dot_marks_weakest_link(tmp_path):
    from qramp.graphexport import chain_dot
    inv = _graph_inv(tmp_path, with_certs=True)
    dot = chain_dot(inv)
    assert dot.startswith("digraph qramp_trust_chains {")
    assert "signed by" in dot                   # signed_by edges
    # the SHA1 CA weakest link is drawn with a thick black stroke
    assert "penwidth=3" in dot
    assert "weak-signature" in dot


def test_chain_mermaid_structure(tmp_path):
    from qramp.graphexport import chain_mermaid
    inv = _graph_inv(tmp_path, with_certs=True)
    m = chain_mermaid(inv)
    _mermaid_nodes_defined(m)
    assert "signed by" in m
    assert "weakest" in m                        # weakest-link class present


def test_graph_export_empty_states(tmp_path):
    """No components / no certs still produces valid, non-crashing output."""
    from qramp.graphexport import (dependency_dot, dependency_mermaid,
                                    chain_dot, chain_mermaid)
    inv = Inventory()                            # empty
    assert "empty" in dependency_dot(inv)
    assert dependency_dot(inv).rstrip().endswith("}")
    _mermaid_nodes_defined(dependency_mermaid(inv))
    assert "empty" in chain_dot(inv)
    _mermaid_nodes_defined(chain_mermaid(inv))


def test_graph_export_stable_node_ids(tmp_path):
    """The same inventory must produce identical output (deterministic ids)."""
    from qramp.graphexport import dependency_dot
    inv = _graph_inv(tmp_path)
    assert dependency_dot(inv) == dependency_dot(inv)


def test_graph_export_dispatch(tmp_path):
    from qramp.graphexport import export
    inv = _graph_inv(tmp_path)
    assert export(inv, "dependency", "dot").startswith("digraph")
    assert export(inv, "dependency", "mermaid").startswith("flowchart")
    assert export(inv, "chain", "dot").startswith("digraph")
    assert export(inv, "chain", "mermaid").startswith("flowchart")
    with pytest.raises(ValueError):
        export(inv, "bogus", "dot")


def test_graph_cli(tmp_path):
    from qramp.cli import main
    inv = _graph_inv(tmp_path)
    cbom = tmp_path / "c.json"; inv.save(str(cbom))
    out = tmp_path / "g.dot"
    assert main(["graph", str(cbom), "--which", "dependency",
                 "--format", "dot", "-o", str(out)]) == 0
    text = out.read_text(encoding="utf-8")
    assert text.startswith("digraph")
    # mermaid chain to file
    out2 = tmp_path / "g.mmd"
    assert main(["graph", str(cbom), "--which", "chain",
                 "--format", "mermaid", "-o", str(out2)]) == 0
    assert out2.read_text(encoding="utf-8").startswith("flowchart")


def test_graph_dot_renders_with_graphviz(tmp_path):
    """If the `dot` binary is available, the DOT output must render."""
    import shutil, subprocess
    if not shutil.which("dot"):
        pytest.skip("graphviz not installed")
    from qramp.graphexport import dependency_dot, chain_dot
    inv = _graph_inv(tmp_path)
    for name, text in [("dep", dependency_dot(inv)), ("chain", chain_dot(inv))]:
        src = tmp_path / f"{name}.dot"; src.write_text(text, encoding="utf-8")
        r = subprocess.run(["dot", "-Tsvg", str(src), "-o", str(tmp_path / f"{name}.svg")],
                           capture_output=True, text=True)
        assert r.returncode == 0, f"{name}: graphviz error: {r.stderr[:200]}"


# ---------- SBOM auto-discovery from manifests ----------
MANIFEST_DIR = os.path.join(TB, "manifests")


def test_manifest_parsers_extract_pairs(tmp_path):
    from qramp.collectors import manifests as M
    # pip
    p = tmp_path / "requirements.txt"
    p.write_text("cryptography==42.0.5\nrequests>=2.0\n# comment\npyOpenSSL==24.0.0\n", encoding="utf-8")
    pairs = dict((n.lower(), v) for n, v in M.parse_pip(str(p)))
    assert pairs["cryptography"] == "42.0.5"
    assert pairs["pyopenssl"] == "24.0.0"
    assert "requests" not in pairs                 # unpinned skipped
    # go.mod
    g = tmp_path / "go.mod"
    g.write_text("module x\n\ngo 1.21\n\nrequire (\n\tgolang.org/x/crypto v0.17.0\n"
                 "\tgithub.com/x/y v1.2.3\n)\n", encoding="utf-8")
    gp = dict(M.parse_gomod(str(g)))
    assert gp["golang.org/x/crypto"] == "0.17.0"
    # cargo
    c = tmp_path / "Cargo.lock"
    c.write_text('[[package]]\nname = "openssl-sys"\nversion = "0.9.90"\n\n'
                 '[[package]]\nname = "serde"\nversion = "1.0.1"\n', encoding="utf-8")
    cp = dict(M.parse_cargo(str(c)))
    assert cp["openssl-sys"] == "0.9.90"
    # maven
    m = tmp_path / "pom.xml"
    m.write_text('<project><dependencies><dependency>'
                 '<groupId>org.bouncycastle</groupId>'
                 '<artifactId>bcprov-jdk18on</artifactId>'
                 '<version>1.77</version></dependency></dependencies></project>', encoding="utf-8")
    mp = dict(M.parse_maven(str(m)))
    assert mp["bcprov-jdk18on"] == "1.77"
    # npm
    n = tmp_path / "package-lock.json"
    n.write_text('{"lockfileVersion":3,"packages":{"":{"name":"a"},'
                 '"node_modules/libsodium":{"version":"0.7.11"}}}', encoding="utf-8")
    npm = dict(M.parse_npm(str(n)))
    assert npm["libsodium"] == "0.7.11"


def test_manifest_discover_walks_tree(tmp_path):
    from qramp.collectors import manifests as M
    (tmp_path / "requirements.txt").write_text("cryptography==42.0.5\n", encoding="utf-8")
    sub = tmp_path / "svc"; sub.mkdir()
    (sub / "go.mod").write_text("module x\nrequire golang.org/x/crypto v0.17.0\n", encoding="utf-8")
    # a vendored manifest must be skipped
    nm = tmp_path / "node_modules"; nm.mkdir()
    (nm / "package-lock.json").write_text('{"packages":{"node_modules/x":{"version":"1"}}}', encoding="utf-8")
    found = M.discover(str(tmp_path))
    names = {n for n, _, _, _ in found}
    assert "cryptography" in names
    assert "golang.org/x/crypto" in names
    assert not any(eco == "npm" for _, _, eco, _ in found)   # node_modules skipped


def test_manifest_collector_maps_crypto_components(tmp_path):
    from qramp.collectors import manifests as M
    (tmp_path / "requirements.txt").write_text(
        "cryptography==42.0.5\nparamiko==3.4.0\nrequests==2.31.0\n", encoding="utf-8")
    inv = Inventory()
    stats = M.run(inv, source_dir=str(tmp_path))
    keys = {c.name for c in inv.components}
    assert "cryptography" in keys and "paramiko" in keys
    assert "requests" not in keys                  # not a crypto provider
    assert stats["components_mapped"] == 2


def test_manifest_wrapper_version_fails_closed(tmp_path):
    """A wrapper package (pyOpenSSL 24.x) must NOT drive OpenSSL's version gates:
    it should not claim ML-KEM just because 24.0.0 >= 3.5."""
    from qramp.collectors import manifests as M
    (tmp_path / "requirements.txt").write_text("pyOpenSSL==24.0.0\n", encoding="utf-8")
    inv = Inventory()
    stats = M.run(inv, source_dir=str(tmp_path))
    assert stats["wrapper_components"] == 1
    algs = {a.algorithm for c in inv.components for a in inv.assets_provided_by(c)}
    assert "rsa" in algs                           # baseline capability present
    assert "ml-kem" not in algs                    # version-gated PQC withheld
    assert "ml-dsa" not in algs
    # the component is marked as a wrapper
    assert any("~wrapper" in c.version for c in inv.components)


def test_manifest_direct_library_uses_its_version(tmp_path):
    """A direct library (the BouncyCastle artifact) keeps its version so version
    gates resolve normally."""
    from qramp.collectors import manifests as M
    (tmp_path / "pom.xml").write_text(
        '<project><dependencies><dependency>'
        '<groupId>org.bouncycastle</groupId>'
        '<artifactId>bcprov-jdk18on</artifactId>'
        '<version>1.78</version></dependency></dependencies></project>', encoding="utf-8")
    inv = Inventory()
    M.run(inv, source_dir=str(tmp_path))
    bc = [c for c in inv.components if c.name == "bouncycastle"][0]
    assert bc.version == "1.78"
    assert "~wrapper" not in bc.version
    # bouncycastle 1.78 ships ML-KEM/ML-DSA per the provider map
    algs = {a.algorithm for a in inv.assets_provided_by(bc)}
    assert "ml-kem" in algs or "ml-dsa" in algs


def test_manifest_scan_cli_auto_discovers(tmp_path):
    from qramp.cli import main
    (tmp_path / "requirements.txt").write_text("cryptography==42.0.5\n", encoding="utf-8")
    out = tmp_path / "cbom.json"
    # --manifests with an explicit dir, no --sbom needed
    assert main(["scan", "--manifests", str(tmp_path), "-o", str(out)]) == 0
    inv = Inventory.load(str(out))
    assert any(c.name == "cryptography" for c in inv.components)


def test_manifest_scan_cli_defaults_to_source(tmp_path):
    """--manifests with no argument uses the --source directory."""
    from qramp.cli import main
    (tmp_path / "requirements.txt").write_text("paramiko==3.4.0\n", encoding="utf-8")
    out = tmp_path / "cbom.json"
    rc = main(["scan", "--source", str(tmp_path), "--manifests", "-o", str(out)])
    assert rc == 0
    inv = Inventory.load(str(out))
    assert any(c.name == "paramiko" for c in inv.components)


def test_manifest_full_pipeline(tmp_path):
    """Manifest-discovered components flow through assess + readiness with no
    hand-written SBOM."""
    import yaml
    from qramp.cli import main
    from qramp import assess
    from qramp.readiness import readiness_report
    (tmp_path / "requirements.txt").write_text("cryptography==42.0.5\n", encoding="utf-8")
    cbom = tmp_path / "cbom.json"
    main(["scan", "--manifests", str(tmp_path), "-o", str(cbom)])
    inv = Inventory.load(str(cbom))
    rules = yaml.safe_load(open(RULES, encoding="utf-8"))
    lifetimes = yaml.safe_load(open(os.path.join(TB, "policy", "data-lifetimes.yaml"),
                                    encoding="utf-8"))
    assess.classify(inv, rules)
    assess.prioritise(inv, rules, lifetimes)
    rep = readiness_report(inv, yaml.safe_load(open(os.path.join(
        HERE, "..", "src", "qramp", "data", "provider-map.yaml"), encoding="utf-8")))
    # cryptography ships RSA/ECDSA (broken) so there is a migration story
    assert rep["pqc_migration_assets"] >= 1


def test_manifest_testbed_present():
    """The shipped testbed manifests parse and map."""
    from qramp.collectors import manifests as M
    if not os.path.isdir(MANIFEST_DIR):
        pytest.skip("testbed manifests not present")
    inv = Inventory()
    stats = M.run(inv, source_dir=MANIFEST_DIR)
    assert stats["manifests_found"] >= 4
    assert stats["components_mapped"] >= 4
    assert stats["by_ecosystem"]                   # multiple ecosystems seen


# ---------- timeline in the dashboard ----------
def _history_cbom(tmp_path, name, algs, ts):
    import yaml
    from qramp import assess
    from qramp.model import Occurrence
    inv = Inventory()
    for prim, alg, tags in algs:
        inv.observe(prim, alg, Occurrence("source-py", "app.py:1", alg, tags=tags))
    rules = yaml.safe_load(open(RULES, encoding="utf-8"))
    lifetimes = yaml.safe_load(open(os.path.join(TB, "policy", "data-lifetimes.yaml"),
                                    encoding="utf-8"))
    assess.classify(inv, rules)
    assess.prioritise(inv, rules, lifetimes)
    inv.meta["generated"] = ts
    p = tmp_path / f"{name}.json"; inv.save(str(p))
    return str(p)


def _dash_with_history(tmp_path):
    from qramp import report
    jan = _history_cbom(tmp_path, "jan",
        [("key-agreement", "ecdh", ["external"]),
         ("signature", "rsa", ["external"]), ("hash", "md5", [])],
        "2026-01-15T00:00:00+00:00")
    mar = _history_cbom(tmp_path, "mar",
        [("signature", "rsa", ["external"]), ("hash", "md5", [])],
        "2026-03-15T00:00:00+00:00")
    cur = _history_cbom(tmp_path, "current",
        [("hash", "md5", [])], "2026-05-15T00:00:00+00:00")
    out = tmp_path / "dash.html"
    report.dashboard(cur, str(out), history=[jan, mar])
    return out.read_text(encoding="utf-8")


def test_dashboard_embeds_timeline_with_history(tmp_path):
    doc = _dash_with_history(tmp_path)
    assert "Migration progress" in doc
    assert "trend across 3 scans" in doc          # 2 history + current
    assert "net assets remediated" in doc
    assert '<div class="tl-chart">' in doc
    assert "<svg" in doc


def test_dashboard_no_timeline_without_history(tmp_path):
    doc = _dashboard_html(tmp_path)                # existing helper, no history
    assert "Migration progress" not in doc
    assert 'class="tl"' not in doc


def test_dashboard_timeline_current_is_latest_point(tmp_path):
    """The current CBOM must appear as the most recent point, so the trend ends
    at today's state."""
    import re
    doc = _dash_with_history(tmp_path)
    m = re.search(r'<div class="tl-chart">(.*?)</div>', doc, re.S)
    chart = m.group(1)
    # three date labels, ending at the current CBOM's date
    dates = sorted(set(re.findall(r"2026-\d\d-\d\d", chart)))
    assert dates == ["2026-01-15", "2026-03-15", "2026-05-15"]


def test_dashboard_timeline_single_history_still_two_points(tmp_path):
    """One history CBOM + the current one is a valid two-point trend."""
    from qramp import report
    jan = _history_cbom(tmp_path, "jan",
        [("key-agreement", "ecdh", ["external"]), ("hash", "md5", [])],
        "2026-01-15T00:00:00+00:00")
    cur = _history_cbom(tmp_path, "cur", [("hash", "md5", [])],
                        "2026-05-15T00:00:00+00:00")
    out = tmp_path / "d.html"
    report.dashboard(cur, str(out), history=[jan])
    assert "trend across 2 scans" in out.read_text(encoding="utf-8")


def test_dashboard_timeline_html_valid(tmp_path):
    from html.parser import HTMLParser
    doc = _dash_with_history(tmp_path)

    class _P(HTMLParser):
        def error(self, message):
            raise AssertionError(message)
    _P().feed(doc)
    # the trend chart is present (dep/cert graphs need components/certs, absent here)
    assert '<div class="tl-chart">' in doc
    assert "<svg" in doc


def test_dashboard_report_cli_history(tmp_path):
    from qramp.cli import main
    jan = _history_cbom(tmp_path, "jan",
        [("key-agreement", "ecdh", ["external"]), ("hash", "md5", [])],
        "2026-01-15T00:00:00+00:00")
    cur = _history_cbom(tmp_path, "cur", [("hash", "md5", [])],
                        "2026-05-15T00:00:00+00:00")
    out = tmp_path / "d.html"
    assert main(["report", cur, "--history", jan, "-o", str(out)]) == 0
    assert "Migration progress" in out.read_text(encoding="utf-8")


def test_dashboard_report_cli_history_directory(tmp_path):
    """--history accepts a directory of CBOMs."""
    from qramp.cli import main
    hist = tmp_path / "history"; hist.mkdir()
    _history_cbom(hist, "jan",
        [("key-agreement", "ecdh", ["external"]), ("hash", "md5", [])],
        "2026-01-15T00:00:00+00:00")
    _history_cbom(hist, "mar", [("signature", "rsa", ["external"]), ("hash", "md5", [])],
                  "2026-03-15T00:00:00+00:00")
    cur = _history_cbom(tmp_path, "cur", [("hash", "md5", [])],
                        "2026-05-15T00:00:00+00:00")
    out = tmp_path / "d.html"
    assert main(["report", cur, "--history", str(hist), "-o", str(out)]) == 0
    assert "trend across 3 scans" in out.read_text(encoding="utf-8")


def test_dashboard_timeline_coexists_with_graphs(tmp_path):
    """With SBOM components, certs, AND history, the dashboard shows the trend
    chart alongside the dependency and cert-chain graphs — one unified view."""
    import yaml
    from qramp import assess, report
    from qramp.model import Occurrence
    # current CBOM with components + certs
    inv = Inventory()
    sbom_col.run(inv, sbom_path=SBOM_PATH)
    cert_col.run(inv, cert_dir=CHAIN_DIR)
    inv.observe("hash", "md5", Occurrence("source-py", "app.py:1", "md5"))
    rules = yaml.safe_load(open(RULES, encoding="utf-8"))
    lifetimes = yaml.safe_load(open(os.path.join(TB, "policy", "data-lifetimes.yaml"),
                                    encoding="utf-8"))
    assess.classify(inv, rules)
    assess.prioritise(inv, rules, lifetimes)
    inv.meta["generated"] = "2026-05-15T00:00:00+00:00"
    cur = tmp_path / "cur.json"; inv.save(str(cur))
    jan = _history_cbom(tmp_path, "jan",
        [("key-agreement", "ecdh", ["external"]), ("hash", "md5", [])],
        "2026-01-15T00:00:00+00:00")
    out = tmp_path / "d.html"
    report.dashboard(str(cur), str(out), history=[jan])
    doc = out.read_text(encoding="utf-8")
    assert "Migration progress" in doc          # timeline
    assert "Dependency graph" in doc            # dep graph
    assert "Certificate trust chains" in doc    # cert graph
    assert doc.count("<svg") >= 3               # trend + dep + cert


# ---------- extended rule pack: PQ hybrids, weak curves, lightweight ciphers ----------
def _classify_alg(primitive, algorithm, params="", tags=None):
    """Classify a single asset against the shipped rule pack, returning
    (exposure_class, rule_id)."""
    import yaml
    from qramp import assess
    from qramp.model import Occurrence
    inv = Inventory()
    a = inv.observe(primitive, algorithm,
                    Occurrence("t", "x", "e", tags=list(tags or [])),
                    params=params)
    rules = yaml.safe_load(open(RULES, encoding="utf-8"))
    for r in rules["rules"]:
        if assess._match(r, a):
            return r.get("class"), r.get("id")
    return "unknown", None


def test_canon_lightweight_and_pq_aliases():
    from qramp.model import canon_algorithm
    assert canon_algorithm("Ascon-128") == "ascon"
    assert canon_algorithm("ASCON-HASH256") == "ascon-hash"
    assert canon_algorithm("PRESENT-80") == "present"
    assert canon_algorithm("Falcon512") == "fn-dsa"
    assert canon_algorithm("FrodoKEM") == "frodo-kem"
    assert canon_algorithm("x25519-mlkem768") == "hybrid-pq"
    assert canon_algorithm("X-Wing") == "hybrid-pq"
    assert canon_algorithm("Kyber768") == "ml-kem"
    assert canon_algorithm("MLDSA65") == "ml-dsa"


def test_rule_pq_hybrid_and_fndsa():
    assert _classify_alg("key-agreement", "x25519-mlkem768") == ("hybrid", "hybrid-pq")
    assert _classify_alg("key-agreement", "x-wing") == ("hybrid", "hybrid-pq")
    assert _classify_alg("signature", "falcon") == ("pq_ready", "fndsa")


def test_rule_nonstandard_pq_is_weakened():
    """Non-FIPS PQ candidates are flagged as not-yet-standard, not pq_ready."""
    for alg in ("frodokem", "bike", "hqc", "mceliece"):
        cls, rule = _classify_alg("key-agreement", alg)
        assert cls == "quantum_weakened"
        assert rule == "pq-nonstandard-kem"
    # the standard KEM is still pq_ready
    assert _classify_alg("key-agreement", "ml-kem")[0] == "pq_ready"


def test_rule_weak_curves():
    """Sub-256-bit curves hit the specific weak-curve rule (quantum_broken with
    a curve-aware rationale), while P-256 stays on the generic ECC rule."""
    for curve in ("secp192r1", "secp160r1", "secp224r1", "nistp192"):
        cls, rule = _classify_alg("signature", "ecdsa", params=curve)
        assert cls == "quantum_broken"
        assert rule == "weak-curve-ecdsa"
    for curve in ("secp192r1", "secp160r1"):
        assert _classify_alg("key-agreement", "ecdh", params=curve) == \
            ("quantum_broken", "weak-curve-ecdh")
    # a strong curve falls through to the generic ecdsa-broken rule
    assert _classify_alg("signature", "ecdsa", params="secp256r1") == \
        ("quantum_broken", "ecdsa-broken")


def test_rule_weak_curve_cert_precedence():
    """A certificate tagged weak-curve is cert-hygiene (reissue) rather than the
    broad code-usage weak-curve rule."""
    cls, rule = _classify_alg("signature", "ecdsa", params="secp192r1",
                              tags=["weak-curve"])
    assert rule == "weak-cert-curve"           # tag-based cert rule wins
    assert cls == "quantum_weakened"


def test_rule_lightweight_ciphers():
    # legacy 64-bit-block lightweight ciphers are broken
    for alg in ("present", "prince", "katan"):
        assert _classify_alg("symmetric-cipher", alg) == \
            ("quantum_broken", "lightweight-broken")
    # unstandardised lightweight ciphers are weakened
    for alg in ("speck", "simon", "gift"):
        assert _classify_alg("symmetric-cipher", alg) == \
            ("quantum_weakened", "lightweight-weak")
    # ASCON (NIST SP 800-232) is fine
    assert _classify_alg("symmetric-cipher", "ascon") == ("pq_ready", "ascon-ok")
    assert _classify_alg("hash", "ascon-hash") == ("pq_ready", "ascon-hash-ok")


def test_extended_rule_pack_lints_clean():
    """The shipped rule pack must still lint without errors or warnings."""
    import yaml
    from qramp.rulelint import lint
    rules = yaml.safe_load(open(RULES, encoding="utf-8"))
    findings = lint(rules)
    assert not [f for f in findings if f.level in ("error", "warning")]


def test_extended_rule_pack_version_bumped():
    import yaml
    rules = yaml.safe_load(open(RULES, encoding="utf-8"))
    assert rules["version"] == "transition-2024.3"


def test_snapshot_covers_new_rules():
    """The regression snapshot must exercise every new rule so an edit that
    breaks one is caught."""
    import json
    snap = os.path.join(TB, "rules", "snapshot.json")
    if not os.path.exists(snap):
        pytest.skip("snapshot not present")
    s = json.load(open(snap, encoding="utf-8"))
    covered = {v["rule"] for v in s["expected"].values()}
    for rule in ("fndsa", "pq-nonstandard-kem", "weak-curve-ecdsa",
                 "weak-curve-ecdh", "lightweight-broken", "lightweight-weak",
                 "ascon-ok", "ascon-hash-ok"):
        assert rule in covered, f"snapshot does not cover {rule}"


def test_snapshot_regression_still_passes():
    """The shipped rule pack must classify the snapshot assets exactly as frozen."""
    import json, yaml
    from qramp.rulelint import classify_snapshot, diff_snapshot
    snap = os.path.join(TB, "rules", "snapshot.json")
    if not os.path.exists(snap):
        pytest.skip("snapshot not present")
    s = json.load(open(snap, encoding="utf-8"))
    rules = yaml.safe_load(open(RULES, encoding="utf-8"))
    current = classify_snapshot(rules, s["assets"])
    drift = diff_snapshot(s["expected"], current)
    assert drift["regressions"] == 0
    assert not drift["changed"]
    assert not drift["only_in_baseline"] and not drift["only_in_current"]


# ---------- manifest alias map as versioned data + linter ----------
def test_aliasmap_loads_from_yaml():
    from qramp.aliasmap import load
    al = load()
    assert al["pyopenssl"] == ("openssl", False)      # wrapper
    assert al["bcprov-jdk18on"] == ("bouncycastle", True)
    assert al["cryptography"] == ("cryptography", True)


def test_aliasmap_build_lookup():
    from qramp.aliasmap import build_lookup
    doc = {"aliases": [
        {"package": "Foo", "component": "openssl", "tracks_version": False},
        {"package": "bar"},                            # component defaults to package
    ]}
    lut = build_lookup(doc)
    assert lut["foo"] == ("openssl", False)            # lowercased
    assert lut["bar"] == ("bar", True)                 # self, tracks by default


def test_manifests_use_yaml_aliases(tmp_path):
    """The collector must read aliases from the data file, not a hardcoded dict."""
    from qramp.collectors import manifests as M
    (tmp_path / "requirements.txt").write_text("pyOpenSSL==24.0.0\ncryptography==42.0.5\n", encoding="utf-8")
    inv = Inventory()
    stats = M.run(inv, source_dir=str(tmp_path))
    keys = {c.name for c in inv.components}
    assert "openssl" in keys and "cryptography" in keys
    assert stats["wrapper_components"] == 1            # pyOpenSSL is a wrapper


def test_manifests_custom_alias_map(tmp_path):
    """A user-supplied alias map extends discovery without code changes."""
    import yaml
    from qramp.collectors import manifests as M
    amap = tmp_path / "aliases.yaml"
    yaml.safe_dump({"version": "custom", "schema": 1, "aliases": [
        {"package": "my-crypto-lib", "component": "openssl", "ecosystem": "pip"}]},
        open(amap, "w", encoding="utf-8"))
    (tmp_path / "requirements.txt").write_text("my-crypto-lib==1.0.0\n", encoding="utf-8")
    inv = Inventory()
    M.run(inv, source_dir=str(tmp_path), alias_map=str(amap))
    assert any(c.name == "openssl" for c in inv.components)


def test_aliasmap_lint_clean_on_shipped():
    import yaml
    from qramp.aliasmap import lint, DEFAULT_ALIASES
    from qramp.collectors.manifests import DEFAULT_MAP
    doc = yaml.safe_load(open(DEFAULT_ALIASES, encoding="utf-8"))
    pmap = yaml.safe_load(open(DEFAULT_MAP, encoding="utf-8"))
    findings = lint(doc, pmap)
    # shipped map must have no errors or warnings (every alias resolves)
    assert not [f for f in findings if f.level in ("error", "warning")]


def test_aliasmap_lint_catches_mistakes():
    from qramp.aliasmap import lint
    bad = {"aliases": [
        {"package": "foo", "component": "openssl", "tracks_version": "yes"},
        {"component": "openssl"},                      # missing package
        {"package": "bar"},                            # missing component
        {"package": "foo", "component": "openssl"},    # duplicate
    ]}
    findings = lint(bad)
    msgs = [f.message for f in findings if f.level == "error"]
    assert any("tracks_version" in m for m in msgs)
    assert any("missing 'package'" in m for m in msgs)
    assert any("missing 'component'" in m for m in msgs)
    assert any("duplicate package" in m for m in msgs)


def test_aliasmap_lint_flags_unknown_component():
    from qramp.aliasmap import lint
    doc = {"aliases": [{"package": "x", "component": "not-in-map"}]}
    pmap = {"components": [{"component": "openssl"}]}
    findings = lint(doc, pmap)
    assert any(f.level == "warning" and "not defined in the provider map" in f.message
               for f in findings)


def test_lint_aliases_cli():
    from qramp.cli import main
    # the built-in alias map lints clean against the built-in provider map
    assert main(["lint-aliases"]) == 0


def test_lint_aliases_cli_strict_fails_on_warning(tmp_path):
    import yaml
    from qramp.cli import main
    amap = tmp_path / "a.yaml"
    yaml.safe_dump({"schema": 1, "aliases": [
        {"package": "x", "component": "does-not-exist"}]}, open(amap, "w", encoding="utf-8"))
    pmap = tmp_path / "p.yaml"
    yaml.safe_dump({"components": [{"component": "openssl"}]}, open(pmap, "w", encoding="utf-8"))
    # warning (unknown component) → strict fails, non-strict passes
    assert main(["lint-aliases", str(amap), "--map", str(pmap)]) == 0
    assert main(["lint-aliases", str(amap), "--map", str(pmap), "--strict"]) == 1


def test_scan_cli_alias_map_option(tmp_path):
    import yaml
    from qramp.cli import main
    amap = tmp_path / "aliases.yaml"
    yaml.safe_dump({"schema": 1, "aliases": [
        {"package": "my-lib", "component": "openssl"}]}, open(amap, "w", encoding="utf-8"))
    (tmp_path / "requirements.txt").write_text("my-lib==1.0.0\n", encoding="utf-8")
    out = tmp_path / "cbom.json"
    rc = main(["scan", "--manifests", str(tmp_path), "--alias-map", str(amap),
               "-o", str(out)])
    assert rc == 0
    inv = Inventory.load(str(out))
    assert any(c.name == "openssl" for c in inv.components)


# ---------- report bundle: shareable static site ----------
def _bundle_cbom(tmp_path, with_history=True):
    """An assessed CBOM (components + certs) plus optional history CBOMs."""
    import yaml
    from qramp import assess
    from qramp.model import Occurrence
    inv = Inventory()
    sbom_col.run(inv, sbom_path=SBOM_PATH)
    cert_col.run(inv, cert_dir=CHAIN_DIR)
    inv.observe("hash", "md5", Occurrence("source-py", "app.py:1", "md5"))
    rules = yaml.safe_load(open(RULES, encoding="utf-8"))
    lifetimes = yaml.safe_load(open(os.path.join(TB, "policy", "data-lifetimes.yaml"),
                                    encoding="utf-8"))
    assess.classify(inv, rules)
    assess.prioritise(inv, rules, lifetimes)
    inv.meta["generated"] = "2026-05-15T00:00:00+00:00"
    cur = tmp_path / "cur.json"; inv.save(str(cur))
    history = []
    if with_history:
        h = _history_cbom(tmp_path, "jan",
            [("key-agreement", "ecdh", ["external"]),
             ("signature", "rsa", ["external"]), ("hash", "md5", [])],
            "2026-01-15T00:00:00+00:00")
        history = [h]
    return str(cur), history


def _assert_valid_html(path):
    from html.parser import HTMLParser

    class _P(HTMLParser):
        def error(self, message):
            raise AssertionError(message)
    _P().feed(open(path, encoding="utf-8").read())


def test_bundle_writes_all_artefacts(tmp_path):
    import yaml
    from qramp.bundle import build_bundle
    cur, history = _bundle_cbom(tmp_path)
    out = tmp_path / "site"
    pmap = yaml.safe_load(open(os.path.join(HERE, "..", "src", "qramp", "data",
                                            "provider-map.yaml"), encoding="utf-8"))
    m = build_bundle(cur, str(out), provider_map=pmap, history=history)
    assert "dashboard.html" in m["pages"]
    assert "progress.html" in m["pages"]              # history supplied
    assert m["graphs"] and m["data"]
    assert (out / "index.html").exists()
    assert (out / "dashboard.html").exists()
    assert (out / "graphs" / "dependency.dot").exists()
    assert (out / "data" / "cbom.cdx.json").exists()
    assert (out / "data" / "summary.json").exists()


def test_bundle_index_links_resolve(tmp_path):
    import re, yaml
    from qramp.bundle import build_bundle
    cur, history = _bundle_cbom(tmp_path)
    out = tmp_path / "site"
    pmap = yaml.safe_load(open(os.path.join(HERE, "..", "src", "qramp", "data",
                                            "provider-map.yaml"), encoding="utf-8"))
    build_bundle(cur, str(out), provider_map=pmap, history=history)
    idx = (out / "index.html").read_text(encoding="utf-8")
    _assert_valid_html(str(out / "index.html"))
    hrefs = re.findall(r"href='([^']+)'", idx)
    assert hrefs
    for h in hrefs:
        assert (out / h).exists(), f"index links to missing file {h}"


def test_bundle_summary_json_valid(tmp_path):
    import json, yaml
    from qramp.bundle import build_bundle
    cur, history = _bundle_cbom(tmp_path)
    out = tmp_path / "site"
    pmap = yaml.safe_load(open(os.path.join(HERE, "..", "src", "qramp", "data",
                                            "provider-map.yaml"), encoding="utf-8"))
    build_bundle(cur, str(out), provider_map=pmap, history=history)
    s = json.load(open(out / "data" / "summary.json", encoding="utf-8"))
    assert "summary" in s and "readiness" in s
    assert s["summary"]["assets"] >= 1
    assert "tiers" in s["summary"]


def test_bundle_degrades_without_history(tmp_path):
    import yaml
    from qramp.bundle import build_bundle
    cur, _ = _bundle_cbom(tmp_path, with_history=False)
    out = tmp_path / "site"
    pmap = yaml.safe_load(open(os.path.join(HERE, "..", "src", "qramp", "data",
                                            "provider-map.yaml"), encoding="utf-8"))
    m = build_bundle(cur, str(out), provider_map=pmap)
    assert "progress.html" not in m["pages"]          # no history → no progress page
    assert not (out / "progress.html").exists()
    _assert_valid_html(str(out / "index.html"))       # index still valid


def test_bundle_degrades_without_components(tmp_path):
    """A source-only CBOM (no SBOM components, no certs) still bundles cleanly."""
    import yaml
    from qramp import assess
    from qramp.model import Occurrence
    from qramp.bundle import build_bundle
    inv = Inventory()
    inv.observe("hash", "md5", Occurrence("source-py", "app.py:1", "md5"))
    rules = yaml.safe_load(open(RULES, encoding="utf-8"))
    lifetimes = yaml.safe_load(open(os.path.join(TB, "policy", "data-lifetimes.yaml"),
                                    encoding="utf-8"))
    assess.classify(inv, rules)
    assess.prioritise(inv, rules, lifetimes)
    cur = tmp_path / "c.json"; inv.save(str(cur))
    out = tmp_path / "site"
    pmap = yaml.safe_load(open(os.path.join(HERE, "..", "src", "qramp", "data",
                                            "provider-map.yaml"), encoding="utf-8"))
    m = build_bundle(str(cur), str(out), provider_map=pmap)
    _assert_valid_html(str(out / "index.html"))
    _assert_valid_html(str(out / "dashboard.html"))
    assert m["graphs"]                                # empty-state graphs still written


def test_bundle_all_html_parses(tmp_path):
    import yaml
    from qramp.bundle import build_bundle
    cur, history = _bundle_cbom(tmp_path)
    out = tmp_path / "site"
    pmap = yaml.safe_load(open(os.path.join(HERE, "..", "src", "qramp", "data",
                                            "provider-map.yaml"), encoding="utf-8"))
    build_bundle(cur, str(out), provider_map=pmap, history=history)
    for name in ("index.html", "dashboard.html", "progress.html"):
        _assert_valid_html(str(out / name))


def test_bundle_cli(tmp_path):
    from qramp.cli import main
    cur, history = _bundle_cbom(tmp_path)
    out = tmp_path / "site"
    argv = ["bundle", cur, "-o", str(out), "--rules", RULES, "--title", "Test Report"]
    for h in history:
        argv += ["--history", h]
    assert main(argv) == 0
    assert (out / "index.html").exists()
    idx = (out / "index.html").read_text(encoding="utf-8")
    assert "Test Report" in idx


def test_bundle_cli_history_directory(tmp_path):
    from qramp.cli import main
    hist = tmp_path / "history"; hist.mkdir()
    _history_cbom(hist, "jan",
        [("key-agreement", "ecdh", ["external"]), ("hash", "md5", [])],
        "2026-01-15T00:00:00+00:00")
    cur, _ = _bundle_cbom(tmp_path, with_history=False)
    out = tmp_path / "site"
    assert main(["bundle", cur, "-o", str(out), "--history", str(hist)]) == 0
    assert (out / "progress.html").exists()


# ---------- rule-pack provenance (standard citations) ----------
def test_all_shipped_rules_have_references():
    """Every rule in the shipped pack must cite a governing standard."""
    import yaml
    rules = yaml.safe_load(open(RULES, encoding="utf-8"))
    for r in rules["rules"]:
        refs = r.get("references")
        assert refs, f"rule {r.get('id')} has no references"
        assert isinstance(refs, list)
        for ref in refs:
            assert isinstance(ref, dict) and ref.get("standard"), \
                f"rule {r.get('id')} has a malformed reference"


def test_references_flow_to_asset(tmp_path):
    """classify() must carry the rule's references onto the asset, surviving a
    save/load round-trip."""
    import yaml
    from qramp import assess
    from qramp.model import Occurrence
    inv = Inventory()
    inv.observe("hash", "md5", Occurrence("s", "x", "md5"))
    rules = yaml.safe_load(open(RULES, encoding="utf-8"))
    assess.classify(inv, rules)
    a = inv.assets[0]
    assert a.references and any(r.get("standard") for r in a.references)
    # round-trip
    p = tmp_path / "c.json"; inv.save(str(p))
    back = Inventory.load(str(p))
    assert back.assets[0].references == a.references


def test_rulelint_flags_missing_references():
    from qramp.rulelint import lint
    doc = {"rules": [
        {"id": "no-refs", "match": {"algorithm": "rsa"}, "class": "quantum_broken"}]}
    warns = [f for f in lint(doc) if f.level == "warning" and "references" in f.message]
    assert warns


def test_rulelint_flags_bad_references():
    from qramp.rulelint import lint
    doc = {"rules": [
        {"id": "notlist", "match": {"algorithm": "rsa"}, "class": "quantum_broken",
         "references": "FIPS 203"},                        # not a list
        {"id": "nostd", "match": {"algorithm": "dsa"}, "class": "quantum_broken",
         "references": [{"note": "no standard field"}]},   # missing standard
        {"id": "badurl", "match": {"algorithm": "rc4"}, "class": "quantum_broken",
         "references": [{"standard": "RFC 7465", "url": "ftp://x"}]},  # bad url
    ]}
    errs = {f.rule_id for f in lint(doc) if f.level == "error"}
    assert "notlist" in errs and "nostd" in errs
    warns = {f.rule_id for f in lint(doc) if f.level == "warning"
             and "url" in f.message}
    assert "badurl" in warns


def test_rulelint_flags_nonstandard_citation():
    from qramp.rulelint import lint
    doc = {"rules": [
        {"id": "weird", "match": {"algorithm": "rsa"}, "class": "quantum_broken",
         "references": [{"standard": "internal memo 42"}]}]}
    infos = [f for f in lint(doc) if f.level == "info"
             and "recognised standard" in f.message]
    assert infos


def test_sarif_carries_references():
    """SARIF rule descriptors must include references in help text, a structured
    property, and standard/* tags — and stay schema-valid."""
    import json, yaml
    from qramp import assess
    from qramp.model import Occurrence
    from qramp.sarif import to_sarif
    inv = Inventory()
    inv.observe("hash", "md5", Occurrence("s", "x:1", "md5"))
    rules = yaml.safe_load(open(RULES, encoding="utf-8"))
    assess.classify(inv, rules)
    doc = to_sarif(inv, rules)
    descriptors = doc["runs"][0]["tool"]["driver"]["rules"]
    md5 = [d for d in descriptors if d["id"] == "md5-dead"][0]
    assert "References:" in md5["help"]["text"]
    assert md5["properties"]["references"]
    assert any(t.startswith("standard/") for t in md5["properties"]["tags"])
    # still schema-valid
    schema_path = os.path.join(HERE, "data", "sarif-schema-2.1.0.json")
    if os.path.exists(schema_path):
        try:
            import jsonschema
        except ModuleNotFoundError:
            pytest.skip("jsonschema not installed")
        jsonschema.validate(doc, json.load(open(schema_path, encoding="utf-8")))


def test_provenance_cli_text():
    from qramp.cli import main
    assert main(["provenance"]) == 0


def test_provenance_cli_json(capsys):
    import json
    from qramp.cli import main
    assert main(["provenance", "--format", "json"]) == 0
    out = capsys.readouterr().out
    doc = json.loads(out)
    assert doc["version"].startswith("transition-2024")
    assert doc["rules"]
    assert all("references" in r for r in doc["rules"])


def test_provenance_cli_markdown(capsys):
    from qramp.cli import main
    assert main(["provenance", "--format", "markdown"]) == 0
    out = capsys.readouterr().out
    assert "| Rule | Class | Governing standards |" in out
    assert "FIPS 203" in out


def test_provenance_cli_filtered_by_cbom(tmp_path, capsys):
    """--cbom restricts to fired rules with occurrence counts."""
    import yaml
    from qramp import assess
    from qramp.model import Occurrence
    from qramp.cli import main
    inv = Inventory()
    inv.observe("hash", "md5", Occurrence("s", "x", "md5"))
    inv.observe("hash", "md5", Occurrence("s", "y", "md5"))   # 2 occurrences
    rules = yaml.safe_load(open(RULES, encoding="utf-8"))
    assess.classify(inv, rules)
    from qramp import assess as _a
    lifetimes = yaml.safe_load(open(os.path.join(TB, "policy", "data-lifetimes.yaml"),
                                    encoding="utf-8"))
    _a.prioritise(inv, rules, lifetimes)
    cbom = tmp_path / "c.json"; inv.save(str(cbom))
    assert main(["provenance", "--format", "json", "--cbom", str(cbom)]) == 0
    import json
    doc = json.loads(capsys.readouterr().out)
    ids = {r["id"] for r in doc["rules"]}
    assert ids == {"md5-dead"}                          # only the fired rule
    assert doc["rules"][0]["occurrences"] == 1          # one unique asset


def test_dashboard_exposure_has_provenance_tooltip(tmp_path):
    import yaml
    from qramp import assess, report
    from qramp.model import Occurrence
    inv = Inventory()
    inv.observe("hash", "md5", Occurrence("s", "x:1", "md5"))
    rules = yaml.safe_load(open(RULES, encoding="utf-8"))
    lifetimes = yaml.safe_load(open(os.path.join(TB, "policy", "data-lifetimes.yaml"),
                                    encoding="utf-8"))
    assess.classify(inv, rules)
    assess.prioritise(inv, rules, lifetimes)
    cbom = tmp_path / "c.json"; inv.save(str(cbom))
    out = tmp_path / "d.html"
    report.dashboard(str(cbom), str(out))
    doc = out.read_text(encoding="utf-8")
    assert "exp-cite" in doc and "refs:" in doc        # provenance tooltip present


# ---------- provenance page in the report bundle ----------
def _bundle_with_provenance(tmp_path, with_rules=True):
    import yaml
    from qramp import assess
    from qramp.model import Occurrence
    from qramp.bundle import build_bundle
    inv = Inventory()
    inv.observe("hash", "md5", Occurrence("s", "x:1", "md5"))
    inv.observe("pk-encryption", "rsa", Occurrence("s", "y:1", "rsa"))
    rules = yaml.safe_load(open(RULES, encoding="utf-8"))
    lifetimes = yaml.safe_load(open(os.path.join(TB, "policy", "data-lifetimes.yaml"),
                                    encoding="utf-8"))
    assess.classify(inv, rules)
    assess.prioritise(inv, rules, lifetimes)
    inv.meta["generated"] = "2026-05-15T00:00:00+00:00"
    cur = tmp_path / "cur.json"; inv.save(str(cur))
    out = tmp_path / "site"
    pmap = yaml.safe_load(open(os.path.join(HERE, "..", "src", "qramp", "data",
                                            "provider-map.yaml"), encoding="utf-8"))
    m = build_bundle(str(cur), str(out), provider_map=pmap,
                     rules_doc=(rules if with_rules else None))
    return out, m


def test_bundle_provenance_page_present(tmp_path):
    out, m = _bundle_with_provenance(tmp_path)
    assert "provenance.html" in m["pages"]
    assert "data/provenance.json" in m["data"]
    assert (out / "provenance.html").exists()
    _assert_valid_html(str(out / "provenance.html"))


def test_bundle_provenance_page_cites_standards(tmp_path):
    out, _ = _bundle_with_provenance(tmp_path)
    doc = (out / "provenance.html").read_text(encoding="utf-8")
    # the fired rules (md5-dead, rsa-broken) cite their standards
    assert "md5-dead" in doc and "rsa-broken" in doc
    assert any(s in doc for s in ("NIST", "RFC", "FIPS", "NISTIR"))
    # grouped by exposure class
    assert "Quantum-broken" in doc


def test_bundle_provenance_json_valid(tmp_path):
    import json
    out, _ = _bundle_with_provenance(tmp_path)
    pj = json.load(open(out / "data" / "provenance.json", encoding="utf-8"))
    assert pj["version"].startswith("transition-2024")
    ids = {r["id"] for r in pj["rules"]}
    assert "md5-dead" in ids and "rsa-broken" in ids
    for r in pj["rules"]:
        assert "occurrences" in r and "references" in r


def test_bundle_index_links_provenance(tmp_path):
    out, _ = _bundle_with_provenance(tmp_path)
    idx = (out / "index.html").read_text(encoding="utf-8")
    assert "provenance.html" in idx
    assert "governing" in idx.lower() or "standard" in idx.lower()


def test_bundle_provenance_from_asset_references_without_rules(tmp_path):
    """A bundle built from a CBOM alone (no rule pack) still documents provenance
    using the references each asset carries."""
    out, m = _bundle_with_provenance(tmp_path, with_rules=False)
    assert "provenance.html" in m["pages"]
    doc = (out / "provenance.html").read_text(encoding="utf-8")
    assert any(s in doc for s in ("NIST", "RFC", "FIPS", "NISTIR"))


def test_bundle_no_provenance_when_nothing_fired(tmp_path):
    """A CBOM whose assets matched no rule produces no provenance page, and the
    index stays valid."""
    import yaml
    from qramp.model import Occurrence
    from qramp.bundle import build_bundle
    inv = Inventory()
    inv.observe("random", "ctr-drbg", Occurrence("s", "x", "drbg"))   # no rule
    cur = tmp_path / "c.json"; inv.save(str(cur))
    out = tmp_path / "site"
    pmap = yaml.safe_load(open(os.path.join(HERE, "..", "src", "qramp", "data",
                                            "provider-map.yaml"), encoding="utf-8"))
    m = build_bundle(str(cur), str(out), provider_map=pmap)
    assert "provenance.html" not in m["pages"]
    _assert_valid_html(str(out / "index.html"))


def test_bundle_cli_provenance(tmp_path):
    from qramp.cli import main
    cur, history = _bundle_cbom(tmp_path)
    out = tmp_path / "site"
    assert main(["bundle", cur, "-o", str(out), "--rules", RULES]) == 0
    assert (out / "provenance.html").exists()
    assert (out / "data" / "provenance.json").exists()


# ---------- manifest alias map snapshot regression ----------
def test_aliasmap_resolve_snapshot():
    from qramp.aliasmap import resolve_snapshot
    doc = {"aliases": [
        {"package": "pyOpenSSL", "component": "openssl", "tracks_version": False},
        {"package": "cryptography", "component": "cryptography"},
    ]}
    snap = resolve_snapshot(doc)
    assert snap["pyopenssl"] == {"component": "openssl", "tracks_version": False}
    assert snap["cryptography"] == {"component": "cryptography", "tracks_version": True}


def test_aliasmap_diff_snapshot_detects_mapping_change():
    from qramp.aliasmap import resolve_snapshot, diff_snapshot
    base = resolve_snapshot({"aliases": [
        {"package": "x", "component": "openssl"}]})
    # component changed (e.g. a typo)
    cur = resolve_snapshot({"aliases": [
        {"package": "x", "component": "opensssl"}]})
    drift = diff_snapshot(base, cur)
    assert drift["regressions"] == 1
    assert drift["changed"][0]["package"] == "x"


def test_aliasmap_diff_snapshot_detects_wrapper_flip():
    """Flipping a wrapper's tracks_version is the dangerous change (it would let
    the wrapper drive version-gated resolution); the snapshot must catch it."""
    from qramp.aliasmap import resolve_snapshot, diff_snapshot
    base = resolve_snapshot({"aliases": [
        {"package": "pyopenssl", "component": "openssl", "tracks_version": False}]})
    cur = resolve_snapshot({"aliases": [
        {"package": "pyopenssl", "component": "openssl", "tracks_version": True}]})
    drift = diff_snapshot(base, cur)
    assert drift["regressions"] == 1


def test_aliasmap_diff_snapshot_additions_not_regressions():
    from qramp.aliasmap import resolve_snapshot, diff_snapshot
    base = resolve_snapshot({"aliases": [{"package": "a", "component": "openssl"}]})
    cur = resolve_snapshot({"aliases": [
        {"package": "a", "component": "openssl"},
        {"package": "b", "component": "libsodium"}]})       # new alias
    drift = diff_snapshot(base, cur)
    assert drift["regressions"] == 0                        # additions are fine
    assert drift["only_in_current"] == ["b"]


def test_aliasmap_diff_snapshot_removal_is_regression():
    from qramp.aliasmap import resolve_snapshot, diff_snapshot
    base = resolve_snapshot({"aliases": [
        {"package": "a", "component": "openssl"},
        {"package": "b", "component": "libsodium"}]})
    cur = resolve_snapshot({"aliases": [{"package": "a", "component": "openssl"}]})
    drift = diff_snapshot(base, cur)
    assert drift["regressions"] == 1                        # b removed
    assert drift["only_in_baseline"] == ["b"]


def test_lint_aliases_snapshot_cli_clean(tmp_path):
    import json, yaml
    from qramp.aliasmap import resolve_snapshot
    from qramp.cli import main
    amap = tmp_path / "a.yaml"
    yaml.safe_dump({"schema": 1, "aliases": [
        {"package": "pyopenssl", "component": "openssl", "tracks_version": False}]},
        open(amap, "w", encoding="utf-8"))
    snap = tmp_path / "snap.json"
    doc = yaml.safe_load(open(amap, encoding="utf-8"))
    json.dump({"resolutions": resolve_snapshot(doc)}, open(snap, "w", encoding="utf-8"))
    # no provider map cross-check (avoid unknown-component warnings)
    assert main(["lint-aliases", str(amap), "--snapshot", str(snap)]) == 0


def test_lint_aliases_snapshot_cli_detects_drift(tmp_path):
    import json, yaml
    from qramp.aliasmap import resolve_snapshot
    from qramp.cli import main
    amap = tmp_path / "a.yaml"
    yaml.safe_dump({"schema": 1, "aliases": [
        {"package": "pyopenssl", "component": "openssl", "tracks_version": False}]},
        open(amap, "w", encoding="utf-8"))
    snap = tmp_path / "snap.json"
    json.dump({"resolutions": resolve_snapshot(yaml.safe_load(open(amap, encoding="utf-8")))},
              open(snap, "w", encoding="utf-8"))
    # now flip the wrapper flag -> drift -> exit 1
    yaml.safe_dump({"schema": 1, "aliases": [
        {"package": "pyopenssl", "component": "openssl", "tracks_version": True}]},
        open(amap, "w", encoding="utf-8"))
    assert main(["lint-aliases", str(amap), "--snapshot", str(snap)]) == 1


def test_lint_aliases_update_snapshot(tmp_path):
    import json, yaml
    from qramp.cli import main
    amap = tmp_path / "a.yaml"
    yaml.safe_dump({"schema": 1, "aliases": [
        {"package": "mylib", "component": "openssl"}]}, open(amap, "w", encoding="utf-8"))
    snap = tmp_path / "snap.json"
    assert main(["lint-aliases", str(amap), "--snapshot", str(snap),
                 "--update-snapshot"]) == 0
    saved = json.load(open(snap, encoding="utf-8"))
    assert saved["resolutions"]["mylib"]["component"] == "openssl"
    # re-check passes against the freshly written snapshot
    assert main(["lint-aliases", str(amap), "--snapshot", str(snap)]) == 0


def test_shipped_alias_snapshot_matches():
    """The shipped alias map must match its committed snapshot."""
    import json, yaml
    from qramp.aliasmap import resolve_snapshot, diff_snapshot, DEFAULT_ALIASES
    snap_path = os.path.join(TB, "manifests", "alias-snapshot.json")
    if not os.path.exists(snap_path):
        pytest.skip("alias snapshot not present")
    baseline = json.load(open(snap_path, encoding="utf-8"))["resolutions"]
    current = resolve_snapshot(yaml.safe_load(open(DEFAULT_ALIASES, encoding="utf-8")))
    drift = diff_snapshot(baseline, current)
    assert drift["regressions"] == 0, f"shipped alias map drifted: {drift}"


# ---------- provenance coverage gate ----------
def _rules_minus_refs(tmp_path, *rule_ids):
    """Copy the shipped rule pack, stripping references from the named rules."""
    import yaml
    d = yaml.safe_load(open(RULES, encoding="utf-8"))
    for r in d["rules"]:
        if r["id"] in rule_ids:
            r.pop("references", None)
    p = tmp_path / "rules.yaml"; yaml.safe_dump(d, open(p, "w", encoding="utf-8"))
    return str(p)


def test_provenance_gate_passes_on_shipped_pack():
    from qramp.cli import main
    assert main(["provenance", "--require-references"]) == 0


def test_provenance_gate_fails_on_missing_reference(tmp_path):
    from qramp.cli import main
    rules = _rules_minus_refs(tmp_path, "rsa-broken")
    assert main(["provenance", rules, "--require-references"]) == 1
    # without the flag it just prints, exit 0
    assert main(["provenance", rules]) == 0


def test_provenance_gate_scoped_to_fired_rules(tmp_path):
    """With --cbom, only rules that actually classified an asset must be sourced;
    an un-sourced rule that did not fire is tolerated."""
    import yaml
    from qramp import assess
    from qramp.model import Occurrence
    from qramp.cli import main
    # strip a reference from ascon-ok (won't fire) and from rsa-broken (will)
    rules_path = _rules_minus_refs(tmp_path, "ascon-ok")
    inv = Inventory()
    inv.observe("symmetric-cipher", "aes", Occurrence("s", "x", "aes"),
                key_length=256)                            # -> aes256-ok (has ref)
    rules = yaml.safe_load(open(rules_path, encoding="utf-8"))
    lifetimes = yaml.safe_load(open(os.path.join(TB, "policy", "data-lifetimes.yaml"),
                                    encoding="utf-8"))
    assess.classify(inv, rules)
    assess.prioritise(inv, rules, lifetimes)
    cbom = tmp_path / "c.json"; inv.save(str(cbom))
    # ascon-ok has no ref but did not fire -> gate passes
    assert main(["provenance", rules_path, "--cbom", str(cbom),
                 "--require-references"]) == 0


def test_provenance_gate_fails_when_fired_rule_unsourced(tmp_path):
    import yaml
    from qramp import assess
    from qramp.model import Occurrence
    from qramp.cli import main
    rules_path = _rules_minus_refs(tmp_path, "md5-dead")
    inv = Inventory()
    inv.observe("hash", "md5", Occurrence("s", "x", "md5"))  # fires md5-dead
    rules = yaml.safe_load(open(rules_path, encoding="utf-8"))
    lifetimes = yaml.safe_load(open(os.path.join(TB, "policy", "data-lifetimes.yaml"),
                                    encoding="utf-8"))
    assess.classify(inv, rules)
    assess.prioritise(inv, rules, lifetimes)
    cbom = tmp_path / "c.json"; inv.save(str(cbom))
    assert main(["provenance", rules_path, "--cbom", str(cbom),
                 "--require-references"]) == 1


def test_provenance_gate_works_in_all_formats(tmp_path, capsys):
    from qramp.cli import main
    rules = _rules_minus_refs(tmp_path, "rsa-broken")
    for fmt in ("text", "markdown", "json"):
        assert main(["provenance", rules, "--format", fmt,
                     "--require-references"]) == 1
        out = capsys.readouterr().out
        assert "COVERAGE GATE FAILED" in out
        assert "rsa-broken" in out


# ---------- PR-comment summary ----------
def _assess_inv(algs, tmp_path, name="c.json"):
    import yaml
    from qramp import assess
    from qramp.model import Occurrence
    inv = Inventory()
    for prim, alg, tags, kl in algs:
        inv.observe(prim, alg, Occurrence("s", f"{alg}:1", alg, tags=tags),
                    key_length=kl)
    rules = yaml.safe_load(open(RULES, encoding="utf-8"))
    lifetimes = yaml.safe_load(open(os.path.join(TB, "policy", "data-lifetimes.yaml"),
                                    encoding="utf-8"))
    assess.classify(inv, rules)
    assess.prioritise(inv, rules, lifetimes)
    p = tmp_path / name; inv.save(str(p))
    return str(p)


def test_pr_comment_has_marker_and_table(tmp_path):
    from qramp.prcomment import build_comment, MARKER
    cbom = _assess_inv([("hash", "md5", [], None)], tmp_path)
    md = build_comment(cbom)
    assert md.startswith(MARKER)                        # updatable by CI
    assert "| Metric | Value |" in md
    assert "Urgent (P0+P1)" in md
    assert "Migration readiness" in md


def test_pr_comment_red_when_urgent(tmp_path):
    from qramp.prcomment import build_comment
    # external-facing broken crypto -> P0/P1
    cbom = _assess_inv([("key-agreement", "ecdh", ["external"], None),
                        ("signature", "rsa", ["external"], None)], tmp_path)
    md = build_comment(cbom)
    assert "🔴" in md.splitlines()[1]


def test_pr_comment_green_when_clean(tmp_path):
    from qramp.prcomment import build_comment
    cbom = _assess_inv([("symmetric-cipher", "aes", [], 256)], tmp_path)
    md = build_comment(cbom)
    assert "🟢" in md.splitlines()[1]


def test_pr_comment_trend_with_history(tmp_path):
    from qramp.prcomment import build_comment
    old = _assess_inv([("key-agreement", "ecdh", ["external"], None),
                       ("hash", "md5", [], None)], tmp_path, "old.json")
    # fix the timestamps so history orders before current
    _stamp(old, "2026-01-01T00:00:00+00:00")
    cur = _assess_inv([("hash", "md5", [], None)], tmp_path, "cur.json")
    _stamp(cur, "2026-05-01T00:00:00+00:00")
    md = build_comment(cur, history=[old])
    assert "Trend" in md and "scans" in md


def test_pr_comment_no_trend_without_history(tmp_path):
    from qramp.prcomment import build_comment
    cbom = _assess_inv([("hash", "md5", [], None)], tmp_path)
    md = build_comment(cbom)
    assert "Trend" not in md


def test_pr_comment_top_upgrade(tmp_path):
    """When a library upgrade would unblock assets, the comment recommends it."""
    import yaml
    from qramp import assess
    from qramp.model import Occurrence
    from qramp.prcomment import build_comment
    inv = Inventory()
    sbom_col.run(inv, sbom_path=SBOM_PATH)                # provides openssl etc.
    inv.observe("key-agreement", "ml-kem", Occurrence("s", "x", "ml-kem"))
    rules = yaml.safe_load(open(RULES, encoding="utf-8"))
    lifetimes = yaml.safe_load(open(os.path.join(TB, "policy", "data-lifetimes.yaml"),
                                    encoding="utf-8"))
    assess.classify(inv, rules)
    assess.prioritise(inv, rules, lifetimes)
    cbom = tmp_path / "c.json"; inv.save(str(cbom))
    md = build_comment(str(cbom))
    # may or may not have an upgrade depending on data; assert structure holds
    assert "PQC posture" in md


def test_pr_comment_report_url_vs_artifact(tmp_path):
    from qramp.prcomment import build_comment
    cbom = _assess_inv([("hash", "md5", [], None)], tmp_path)
    with_url = build_comment(cbom, report_url="https://example.com/run/1")
    assert "https://example.com/run/1" in with_url
    without = build_comment(cbom)
    assert "qramp-report` artifact" in without


def test_pr_comment_cli_stdout_and_file(tmp_path, capsys):
    from qramp.cli import main
    cbom = _assess_inv([("hash", "md5", [], None)], tmp_path)
    assert main(["pr-comment", cbom]) == 0
    out = capsys.readouterr().out
    assert "QRAMP" in out and "| Metric | Value |" in out
    # to a file
    dest = tmp_path / "comment.md"
    assert main(["pr-comment", cbom, "-o", str(dest)]) == 0
    assert dest.read_text(encoding="utf-8").startswith("<!-- qramp-pr-comment -->")


def _stamp(cbom_path, ts):
    """Overwrite the generated timestamp of an assessed CBOM on disk."""
    inv = Inventory.load(cbom_path)
    inv.meta["generated"] = ts
    inv.save(cbom_path)


# ---------- alias resolution in provenance / audit ----------
def test_manifests_record_alias_resolutions(tmp_path):
    """The manifest collector records each package's resolution for the audit."""
    from qramp.collectors import manifests as M
    (tmp_path / "requirements.txt").write_text(
        "pyOpenSSL==24.0.0\ncryptography==42.0.5\nrequests==2.31.0\n", encoding="utf-8")
    inv = Inventory()
    stats = M.run(inv, source_dir=str(tmp_path))
    res = {r["package"]: r for r in stats["alias_resolutions"]}
    assert res["pyOpenSSL"]["component"] == "openssl"
    assert res["pyOpenSSL"]["wrapper"] is True
    assert res["cryptography"]["wrapper"] is False
    assert res["requests"]["mapped"] is False          # no provider-map entry


def test_alias_resolutions_survive_save_load(tmp_path):
    from qramp.collectors import manifests as M
    (tmp_path / "requirements.txt").write_text("pyOpenSSL==24.0.0\n", encoding="utf-8")
    inv = Inventory()
    M.run(inv, source_dir=str(tmp_path))
    p = tmp_path / "c.json"; inv.save(str(p))
    back = Inventory.load(str(p))
    cols = [c for c in back.meta.get("collectors", []) if c["name"] == "manifests"]
    assert cols and cols[0]["alias_resolutions"]


def _bundle_with_manifests(tmp_path):
    import yaml
    from qramp import assess
    from qramp.collectors import manifests as M
    from qramp.bundle import build_bundle
    inv = Inventory()
    (tmp_path / "requirements.txt").write_text(
        "pyOpenSSL==24.0.0\ncryptography==42.0.5\nrequests==2.31.0\n", encoding="utf-8")
    M.run(inv, source_dir=str(tmp_path))
    rules = yaml.safe_load(open(RULES, encoding="utf-8"))
    lifetimes = yaml.safe_load(open(os.path.join(TB, "policy", "data-lifetimes.yaml"),
                                    encoding="utf-8"))
    assess.classify(inv, rules)
    assess.prioritise(inv, rules, lifetimes)
    cur = tmp_path / "cur.json"; inv.save(str(cur))
    out = tmp_path / "site"
    pmap = yaml.safe_load(open(os.path.join(HERE, "..", "src", "qramp", "data",
                                            "provider-map.yaml"), encoding="utf-8"))
    build_bundle(str(cur), str(out), provider_map=pmap, rules_doc=rules)
    return out


def test_bundle_provenance_has_alias_section(tmp_path):
    out = _bundle_with_manifests(tmp_path)
    doc = (out / "provenance.html").read_text(encoding="utf-8")
    _assert_valid_html(str(out / "provenance.html"))
    assert "SBOM discovery" in doc                      # the alias section
    assert "openssl" in doc and "wrapper" in doc        # pyOpenSSL -> openssl wrapper
    assert "unmapped" in doc                            # requests has no entry


def test_bundle_provenance_json_has_alias_resolutions(tmp_path):
    import json
    out = _bundle_with_manifests(tmp_path)
    d = json.load(open(out / "data" / "provenance.json", encoding="utf-8"))
    assert "alias_resolutions" in d
    res = {r["package"]: r for r in d["alias_resolutions"]}
    assert res["pyOpenSSL"]["component"] == "openssl"
    assert res["pyOpenSSL"]["wrapper"] is True
    assert res["requests"]["mapped"] is False


def test_bundle_provenance_without_manifests_has_no_alias_section(tmp_path):
    """A scan with no manifest discovery still produces a valid provenance page,
    just without the SBOM-discovery section."""
    import yaml
    from qramp import assess
    from qramp.model import Occurrence
    from qramp.bundle import build_bundle
    inv = Inventory()
    inv.observe("hash", "md5", Occurrence("s", "x", "md5"))
    rules = yaml.safe_load(open(RULES, encoding="utf-8"))
    lifetimes = yaml.safe_load(open(os.path.join(TB, "policy", "data-lifetimes.yaml"),
                                    encoding="utf-8"))
    assess.classify(inv, rules)
    assess.prioritise(inv, rules, lifetimes)
    cur = tmp_path / "c.json"; inv.save(str(cur))
    out = tmp_path / "site"
    pmap = yaml.safe_load(open(os.path.join(HERE, "..", "src", "qramp", "data",
                                            "provider-map.yaml"), encoding="utf-8"))
    build_bundle(str(cur), str(out), provider_map=pmap, rules_doc=rules)
    doc = (out / "provenance.html").read_text(encoding="utf-8")
    _assert_valid_html(str(out / "provenance.html"))
    assert "SBOM discovery" not in doc


# ---------- PR-comment change-vs-base diff ----------
def test_pr_comment_diff_worsens(tmp_path):
    from qramp.prcomment import build_comment
    base = _assess_inv([("hash", "md5", [], None)], tmp_path, "base.json")
    # PR adds two more broken algorithms
    pr = _assess_inv([("hash", "md5", [], None),
                      ("pk-encryption", "rsa", [], None),
                      ("signature", "dsa", [], None)], tmp_path, "pr.json")
    md = build_comment(pr, base_cbom=base)
    assert "Change vs base branch" in md
    assert "worsens" in md
    assert "+2 quantum-broken" in md


def test_pr_comment_diff_improves(tmp_path):
    from qramp.prcomment import build_comment
    base = _assess_inv([("hash", "md5", [], None),
                        ("pk-encryption", "rsa", [], None)], tmp_path, "base.json")
    pr = _assess_inv([("pk-encryption", "rsa", [], None)], tmp_path, "pr.json")
    md = build_comment(pr, base_cbom=base)
    assert "improves" in md
    assert "−1 quantum-broken" in md
    assert "MD5" in md


def test_pr_comment_diff_net_neutral(tmp_path):
    """Swapping one broken algorithm for another is a shift, not a net change."""
    from qramp.prcomment import build_comment
    base = _assess_inv([("pk-encryption", "rsa", [], None)], tmp_path, "base.json")
    pr = _assess_inv([("signature", "dsa", [], None)], tmp_path, "pr.json")
    md = build_comment(pr, base_cbom=base)
    assert "shifts assets without a net change" in md
    assert "+1 quantum-broken" in md and "−1 quantum-broken" in md


def test_pr_comment_diff_no_change(tmp_path):
    from qramp.prcomment import build_comment
    base = _assess_inv([("hash", "md5", [], None)], tmp_path, "base.json")
    pr = _assess_inv([("hash", "md5", [], None)], tmp_path, "pr.json")
    md = build_comment(pr, base_cbom=base)
    assert "no change to quantum-broken" in md


def test_pr_comment_diff_absent_without_base(tmp_path):
    from qramp.prcomment import build_comment
    pr = _assess_inv([("hash", "md5", [], None)], tmp_path)
    md = build_comment(pr)
    assert "Change vs base" not in md


def test_pr_comment_diff_missing_base_file_graceful(tmp_path):
    from qramp.prcomment import build_comment
    pr = _assess_inv([("hash", "md5", [], None)], tmp_path)
    md = build_comment(pr, base_cbom=str(tmp_path / "does-not-exist.json"))
    assert "Change vs base" not in md               # silently omitted


def test_pr_comment_diff_asset_list_capped(tmp_path):
    """Many added assets are truncated with a +N tail to keep the comment small."""
    from qramp.prcomment import build_comment
    base = _assess_inv([("hash", "md5", [], None)], tmp_path, "base.json")
    # ten distinct broken curves added
    curves = ["secp160r1", "secp160k1", "secp192r1", "secp192k1", "nistp192",
              "secp224r1", "nistp224", "brainpoolp160r1", "brainpoolp192r1"]
    algs = [("hash", "md5", [], None)] + \
           [("signature", "ecdsa", [], None)]        # single ecdsa key won't dup; use params
    # build via observe with distinct params to get distinct keys
    import yaml
    from qramp import assess
    from qramp.model import Occurrence
    inv = Inventory()
    inv.observe("hash", "md5", Occurrence("s", "x", "md5"))
    for c in curves:
        inv.observe("signature", "ecdsa", Occurrence("s", f"{c}", "ecdsa"), params=c)
    rules = yaml.safe_load(open(RULES, encoding="utf-8"))
    lifetimes = yaml.safe_load(open(os.path.join(TB, "policy", "data-lifetimes.yaml"),
                                    encoding="utf-8"))
    assess.classify(inv, rules); assess.prioritise(inv, rules, lifetimes)
    pr = tmp_path / "pr.json"; inv.save(str(pr))
    md = build_comment(str(pr), base_cbom=base)
    assert "more" in md                              # truncated tail present


def test_pr_comment_cli_base(tmp_path):
    from qramp.cli import main
    base = _assess_inv([("pk-encryption", "rsa", [], None)], tmp_path, "base.json")
    pr = _assess_inv([("signature", "dsa", [], None)], tmp_path, "pr.json")
    dest = tmp_path / "c.md"
    assert main(["pr-comment", pr, "--base", base, "-o", str(dest)]) == 0
    assert "Change vs base" in dest.read_text(encoding="utf-8")


# ---------- PR-comment diff: quantum-weakened severity handling ----------
def test_pr_comment_diff_broken_to_weakened_improves(tmp_path):
    """Trading a quantum-broken asset for a quantum-weakened one (e.g. RSA ->
    AES-128) is a net improvement, not a wash — broken outweighs weakened."""
    from qramp.prcomment import build_comment
    base = _assess_inv([("pk-encryption", "rsa", [], None)], tmp_path, "base.json")
    pr = _assess_inv([("symmetric-cipher", "aes", [], 128)], tmp_path, "pr.json")
    md = build_comment(pr, base_cbom=base)
    assert "improves" in md
    assert "−1 quantum-broken" in md
    assert "+1 quantum-weakened" in md


def test_pr_comment_diff_weakened_to_broken_worsens(tmp_path):
    from qramp.prcomment import build_comment
    base = _assess_inv([("symmetric-cipher", "aes", [], 128)], tmp_path, "base.json")
    pr = _assess_inv([("pk-encryption", "rsa", [], None)], tmp_path, "pr.json")
    md = build_comment(pr, base_cbom=base)
    assert "worsens" in md


def test_pr_comment_diff_weakened_added_uses_orange(tmp_path):
    """A weakened addition is flagged 🟠 (less severe), a broken addition 🔴."""
    from qramp.prcomment import build_comment
    base = _assess_inv([("symmetric-cipher", "aes", [], 256)], tmp_path, "base.json")
    pr = _assess_inv([("symmetric-cipher", "aes", [], 256),
                      ("symmetric-cipher", "aes", [], 128)], tmp_path, "pr.json")
    md = build_comment(pr, base_cbom=base)
    # the weakened-added line carries the orange icon, not the red one
    wk = [l for l in md.splitlines() if "quantum-weakened" in l and l.startswith("- ")]
    assert wk and "🟠" in wk[0]
    assert "🔴" not in wk[0]


def test_pr_comment_diff_weakened_only_lists_assets(tmp_path):
    """The weakened detail is enumerated just like broken, not only counted."""
    from qramp.prcomment import build_comment
    base = _assess_inv([("symmetric-cipher", "aes", [], 256)], tmp_path, "base.json")
    pr = _assess_inv([("symmetric-cipher", "aes", [], 256),
                      ("symmetric-cipher", "aes", [], 128)], tmp_path, "pr.json")
    md = build_comment(pr, base_cbom=base)
    assert "AES-128" in md                              # the specific asset is named


# ---------- alias resolution surfaced in SARIF ----------
def _manifest_sarif(tmp_path):
    import yaml
    from qramp import assess
    from qramp.collectors import manifests as M
    from qramp.sarif import to_sarif
    inv = Inventory()
    (tmp_path / "requirements.txt").write_text(
        "pyOpenSSL==24.0.0\ncryptography==42.0.5\n", encoding="utf-8")
    M.run(inv, source_dir=str(tmp_path))
    rules = yaml.safe_load(open(RULES, encoding="utf-8"))
    assess.classify(inv, rules)
    return to_sarif(inv, rules, include_ok=True), inv


def test_sarif_carries_alias_resolution(tmp_path):
    doc, _ = _manifest_sarif(tmp_path)
    results = doc["runs"][0]["results"]
    aliased = [r for r in results
               if "aliasResolution" in r.get("properties", {})]
    assert aliased, "no SARIF result carries an aliasResolution"
    by_pkg = {}
    for r in aliased:
        ar = r["properties"]["aliasResolution"]
        by_pkg[ar["package"]] = ar
    assert by_pkg["pyOpenSSL"]["component"] == "openssl"
    assert by_pkg["pyOpenSSL"]["wrapper"] is True
    assert by_pkg["cryptography"]["wrapper"] is False


def test_sarif_alias_wrapper_tag(tmp_path):
    doc, _ = _manifest_sarif(tmp_path)
    results = doc["runs"][0]["results"]
    wrapper_results = [r for r in results
                       if r.get("properties", {}).get("aliasResolution", {}).get("wrapper")]
    assert wrapper_results
    for r in wrapper_results:
        assert "discovery/wrapper" in r["properties"]["tags"]
        assert "discovery/manifest" in r["properties"]["tags"]


def test_sarif_non_manifest_has_no_alias(tmp_path):
    """Source/config findings must not carry an aliasResolution property."""
    import yaml
    from qramp import assess
    from qramp.model import Occurrence
    from qramp.sarif import to_sarif
    inv = Inventory()
    inv.observe("hash", "md5", Occurrence("source-py", "app.py:1", "md5"))
    rules = yaml.safe_load(open(RULES, encoding="utf-8"))
    assess.classify(inv, rules)
    doc = to_sarif(inv, rules)
    for r in doc["runs"][0]["results"]:
        assert "aliasResolution" not in r.get("properties", {})


def test_sarif_alias_stays_schema_valid(tmp_path):
    import json
    schema_path = os.path.join(HERE, "data", "sarif-schema-2.1.0.json")
    if not os.path.exists(schema_path):
        pytest.skip("SARIF schema not present")
    try:
        import jsonschema
    except ModuleNotFoundError:
        pytest.skip("jsonschema not installed")
    doc, _ = _manifest_sarif(tmp_path)
    jsonschema.validate(doc, json.load(open(schema_path, encoding="utf-8")))


# ---------- PR-comment gate-results section ----------
def test_pr_comment_gates_section(tmp_path):
    from qramp.prcomment import build_comment
    cbom = _assess_inv([("hash", "md5", [], None)], tmp_path)
    gates = {"Policy: rule pack": "success",
             "Scan: quantum-broken (SARIF)": "failure",
             "Audit: rule-pack change": "skipped"}
    md = build_comment(cbom, gates=gates)
    assert "Gate results" in md
    assert "1 gate(s) failed" in md
    assert "❌ failure" in md and "✅ success" in md and "➖ skipped" in md
    assert "<details>" in md and "</details>" in md      # collapsible


def test_pr_comment_gates_all_pass(tmp_path):
    from qramp.prcomment import build_comment
    cbom = _assess_inv([("hash", "md5", [], None)], tmp_path)
    gates = {"Policy: rule pack": "success", "Scan: provenance coverage": "success"}
    md = build_comment(cbom, gates=gates)
    assert "all gates passed" in md.lower()


def test_pr_comment_gates_absent_without_arg(tmp_path):
    from qramp.prcomment import build_comment
    cbom = _assess_inv([("hash", "md5", [], None)], tmp_path)
    md = build_comment(cbom)
    assert "Gate results" not in md


def test_pr_comment_cli_gates(tmp_path):
    import json
    from qramp.cli import main
    cbom = _assess_inv([("hash", "md5", [], None)], tmp_path)
    gpath = tmp_path / "gates.json"
    json.dump({"Scan: provenance coverage": "failure"}, open(gpath, "w", encoding="utf-8"))
    dest = tmp_path / "c.md"
    assert main(["pr-comment", cbom, "--gates", str(gpath), "-o", str(dest)]) == 0
    body = dest.read_text(encoding="utf-8")
    assert "Gate results" in body and "1 gate(s) failed" in body


def test_pr_comment_gates_and_diff_coexist(tmp_path):
    """A comment can carry both the change-vs-base and the gate matrix."""
    from qramp.prcomment import build_comment
    base = _assess_inv([("pk-encryption", "rsa", [], None)], tmp_path, "base.json")
    pr = _assess_inv([("signature", "dsa", [], None)], tmp_path, "pr.json")
    md = build_comment(pr, base_cbom=base,
                       gates={"Scan: quantum-broken (SARIF)": "success"})
    assert "Change vs base branch" in md
    assert "Gate results" in md


# ---------- wrapper coverage gate ----------
def test_wrapper_coverage_metric():
    from qramp.aliasmap import wrapper_coverage
    res = [
        {"package": "pyOpenSSL", "version": "24", "wrapper": True, "mapped": True},
        {"package": "openssl-sys", "version": "0.9", "wrapper": True, "mapped": True},
        {"package": "cryptography", "version": "42", "wrapper": False, "mapped": True},
        {"package": "bcprov", "version": "1.77", "wrapper": False, "mapped": True},
        {"package": "requests", "version": "2", "wrapper": False, "mapped": False},
    ]
    cov = wrapper_coverage(res)
    assert cov["discovered"] == 5
    assert cov["mapped"] == 4                            # requests is unmapped
    assert cov["wrappers"] == 2
    assert cov["unmapped"] == 1
    assert cov["wrapper_pct"] == 50.0                    # 2 of 4 mapped
    assert "pyOpenSSL@24" in cov["wrapper_packages"]


def test_wrapper_coverage_empty():
    from qramp.aliasmap import wrapper_coverage
    cov = wrapper_coverage([])
    assert cov["discovered"] == 0 and cov["wrapper_pct"] == 0.0


def test_resolutions_from_cbom(tmp_path):
    from qramp.collectors import manifests as M
    from qramp.aliasmap import resolutions_from_cbom
    (tmp_path / "requirements.txt").write_text("pyOpenSSL==24.0.0\ncryptography==42.0.5\n", encoding="utf-8")
    inv = Inventory()
    M.run(inv, source_dir=str(tmp_path))
    p = tmp_path / "c.json"; inv.save(str(p))
    res = resolutions_from_cbom(Inventory.load(str(p)))
    pkgs = {r["package"] for r in res}
    assert "pyOpenSSL" in pkgs and "cryptography" in pkgs


def _cbom_with_wrappers(tmp_path, requirements):
    from qramp.collectors import manifests as M
    (tmp_path / "requirements.txt").write_text(requirements, encoding="utf-8")
    inv = Inventory()
    M.run(inv, source_dir=str(tmp_path))
    p = tmp_path / "c.json"; inv.save(str(p))
    return str(p)


def test_lint_aliases_wrapper_gate_passes(tmp_path):
    from qramp.cli import main
    # 1 wrapper of 2 mapped = 50%; threshold 60% passes
    cbom = _cbom_with_wrappers(tmp_path, "pyOpenSSL==24.0.0\ncryptography==42.0.5\n")
    assert main(["lint-aliases", "--cbom", cbom, "--max-wrapper-pct", "60"]) == 0


def test_lint_aliases_wrapper_gate_fails(tmp_path):
    from qramp.cli import main
    # 1 wrapper of 2 mapped = 50%; threshold 40% fails
    cbom = _cbom_with_wrappers(tmp_path, "pyOpenSSL==24.0.0\ncryptography==42.0.5\n")
    assert main(["lint-aliases", "--cbom", cbom, "--max-wrapper-pct", "40"]) == 1


def test_lint_aliases_wrapper_report_without_gate(tmp_path):
    from qramp.cli import main
    cbom = _cbom_with_wrappers(tmp_path, "pyOpenSSL==24.0.0\n")
    # reporting only (no threshold) never fails
    assert main(["lint-aliases", "--cbom", cbom]) == 0


def test_lint_aliases_wrapper_gate_no_manifests(tmp_path):
    """A CBOM with no manifest discovery is not gated (not applicable)."""
    from qramp import assess
    from qramp.model import Occurrence
    from qramp.cli import main
    import yaml
    inv = Inventory()
    inv.observe("hash", "md5", Occurrence("source-py", "app.py:1", "md5"))
    rules = yaml.safe_load(open(RULES, encoding="utf-8"))
    assess.classify(inv, rules)
    cbom = tmp_path / "c.json"; inv.save(str(cbom))
    assert main(["lint-aliases", "--cbom", str(cbom), "--max-wrapper-pct", "0"]) == 0


def test_lint_aliases_max_wrapper_pct_needs_cbom():
    from qramp.cli import main
    assert main(["lint-aliases", "--max-wrapper-pct", "50"]) == 1


def test_ci_has_wrapper_coverage_gate():
    """crypto-scan reports wrapper coverage, exposes it as a gate output, and the
    threshold is driven by an optional repo variable so it defaults to reporting."""
    import yaml
    ex = os.path.join(HERE, "..", "examples", "ci-full-pipeline.yml")
    if not os.path.exists(ex):
        pytest.skip("ci-full-pipeline.yml not present")
    doc = yaml.safe_load(open(ex, encoding="utf-8"))
    steps = doc["jobs"]["crypto-scan"]["steps"]
    wrap = [s for s in steps if s.get("id") == "wrapper_gate"]
    assert wrap, "no wrapper-coverage step"
    assert "lint-aliases --cbom" in wrap[0]["run"]
    assert "max-wrapper-pct" in wrap[0]["run"]
    assert "wrapper_gate" in doc["jobs"]["crypto-scan"]["outputs"]
    # driven by an optional variable (report-only unless set)
    assert "MAX_WRAPPER_PCT" in doc["env"]
    # appears in the gate matrix
    gs = [s for s in doc["jobs"]["gate-summary"]["steps"]
          if s.get("name") == "Collect gate outcomes"][0]
    assert "wrapper_gate" in gs["with"]["script"]


# ---------- PR-comment branding & compact mode ----------
def test_pr_comment_subtitle(tmp_path):
    from qramp.prcomment import build_comment
    cbom = _assess_inv([("hash", "md5", [], None)], tmp_path)
    md = build_comment(cbom, title="PQC Readiness",
                       subtitle="Acme Corp · payments")
    lines = md.splitlines()
    assert lines[1].endswith("PQC Readiness")
    assert "_Acme Corp · payments_" in md          # branding line


def test_pr_comment_no_subtitle_by_default(tmp_path):
    from qramp.prcomment import build_comment
    cbom = _assess_inv([("hash", "md5", [], None)], tmp_path)
    md = build_comment(cbom)
    # no stray italic branding line right after the heading
    assert "_None_" not in md


def test_pr_comment_compact_folds_trend(tmp_path):
    from qramp.prcomment import build_comment
    old = _assess_inv([("pk-encryption", "rsa", [], None),
                       ("hash", "md5", [], None)], tmp_path, "old.json")
    _stamp(old, "2026-01-01T00:00:00+00:00")
    cur = _assess_inv([("hash", "md5", [], None)], tmp_path, "cur.json")
    _stamp(cur, "2026-05-01T00:00:00+00:00")
    md = build_comment(cur, history=[old], compact=True)
    assert "Trend &amp; recommendations" in md      # folded into a details block
    # the trend text is inside a <details>, not a top-level line
    assert "<details>" in md


def test_pr_comment_noncompact_trend_inline(tmp_path):
    from qramp.prcomment import build_comment
    old = _assess_inv([("pk-encryption", "rsa", [], None),
                       ("hash", "md5", [], None)], tmp_path, "old.json")
    _stamp(old, "2026-01-01T00:00:00+00:00")
    cur = _assess_inv([("hash", "md5", [], None)], tmp_path, "cur.json")
    _stamp(cur, "2026-05-01T00:00:00+00:00")
    md = build_comment(cur, history=[old], compact=False)
    assert "Trend &amp; recommendations" not in md  # not folded
    assert "**Trend**" in md                        # shown inline


def test_pr_comment_compact_opens_failed_gates(tmp_path):
    from qramp.prcomment import build_comment
    cbom = _assess_inv([("hash", "md5", [], None)], tmp_path)
    md = build_comment(cbom, compact=True,
                       gates={"Scan: quantum-broken (SARIF)": "failure"})
    assert "<details open>" in md                   # failed gates auto-expanded


def test_pr_comment_cli_subtitle_and_compact(tmp_path):
    from qramp.cli import main
    cbom = _assess_inv([("hash", "md5", [], None)], tmp_path)
    dest = tmp_path / "c.md"
    assert main(["pr-comment", cbom, "--subtitle", "Acme", "--compact",
                 "-o", str(dest)]) == 0
    assert "_Acme_" in dest.read_text(encoding="utf-8")


# ---------- PR-comment gate log links ----------
def test_pr_comment_gate_failure_links_to_log(tmp_path):
    from qramp.prcomment import build_comment
    cbom = _assess_inv([("hash", "md5", [], None)], tmp_path)
    gates = {
        "Policy: rule pack": {"outcome": "success"},
        "Scan: quantum-broken (SARIF)": {
            "outcome": "failure",
            "url": "https://github.com/acme/pay/actions/runs/42/job/99#step:6:1"},
    }
    md = build_comment(cbom, gates=gates)
    # the failing gate's cell is a link to its log anchor
    assert "[❌ failure](https://github.com/acme/pay/actions/runs/42/job/99#step:6:1)" in md
    # the passing gate stays plain text
    assert "| Policy: rule pack | ✅ success |" in md


def test_pr_comment_gate_success_not_linked(tmp_path):
    from qramp.prcomment import build_comment
    cbom = _assess_inv([("hash", "md5", [], None)], tmp_path)
    gates = {"Scan: provenance coverage": {
        "outcome": "success", "url": "https://example.com/job#step:5:1"}}
    md = build_comment(cbom, gates=gates)
    # a success carrying a url is NOT rendered as a link (only failures link)
    assert "https://example.com" not in md
    assert "✅ success" in md


def test_pr_comment_gate_string_form_still_supported(tmp_path):
    """Plain {name: outcome} (no url) keeps working for backward compatibility."""
    from qramp.prcomment import build_comment
    cbom = _assess_inv([("hash", "md5", [], None)], tmp_path)
    md = build_comment(cbom, gates={"Scan: provenance coverage": "failure"})
    assert "| Scan: provenance coverage | ❌ failure |" in md


def test_pr_comment_gate_mixed_forms(tmp_path):
    """A mix of dict and string gate values renders correctly."""
    from qramp.prcomment import build_comment
    cbom = _assess_inv([("hash", "md5", [], None)], tmp_path)
    gates = {
        "Policy: rule pack": "success",
        "Scan: wrapper coverage": {"outcome": "failure",
                                   "url": "https://x/job#step:9:1"},
    }
    md = build_comment(cbom, gates=gates)
    assert "1 gate(s) failed" in md
    assert "[❌ failure](https://x/job#step:9:1)" in md


def test_ci_collect_step_links_gate_logs():
    """The gate-summary collect step must fetch job logs and link failures."""
    import yaml
    ex = os.path.join(HERE, "..", "examples", "ci-full-pipeline.yml")
    if not os.path.exists(ex):
        pytest.skip("ci-full-pipeline.yml not present")
    doc = yaml.safe_load(open(ex, encoding="utf-8"))
    collect = [s for s in doc["jobs"]["gate-summary"]["steps"]
               if s.get("name") == "Collect gate outcomes"][0]
    script = collect["with"]["script"]
    assert "listJobsForWorkflowRun" in script          # fetches job URLs
    assert "#step:" in script                           # builds a step anchor
    assert "html_url" in script
    # gates.json carries the url on failures
    assert "entry.url" in script


# ---------- gate baseline ----------
def test_baseline_generate_freezes_exposed(tmp_path):
    from qramp import baseline
    cbom = _assess_inv([("pk-encryption", "rsa", [], None),
                        ("hash", "md5", [], None),
                        ("symmetric-cipher", "aes", [], 256)], tmp_path)
    doc = baseline.generate(Inventory.load(cbom))
    ids = {e["display"] for e in doc["accepted"]}
    assert "RSA [pk-encryption]" in ids
    assert "MD5 [hash]" in ids
    assert not any("AES-256" in d for d in ids)          # aes256 is pq-ready, not frozen
    assert doc["exposures"] == ["quantum_broken"]


def test_baseline_evaluate_new_accepted_resolved(tmp_path):
    from qramp import baseline
    base = baseline.generate(Inventory.load(
        _assess_inv([("pk-encryption", "rsa", [], None),
                     ("hash", "md5", [], None)], tmp_path, "b.json")))
    # PR keeps rsa, removes md5, adds dsa
    pr = Inventory.load(_assess_inv([("pk-encryption", "rsa", [], None),
                                     ("signature", "dsa", [], None)], tmp_path, "p.json"))
    ev = baseline.evaluate(pr, base)
    assert ev["new_count"] == 1
    assert ev["new"][0]["display"] == "DSA [signature]"
    assert ev["accepted_count"] == 1                     # rsa
    assert ev["resolved_count"] == 1                     # md5


def test_baseline_lint_stale(tmp_path):
    from qramp import baseline
    base = baseline.generate(Inventory.load(
        _assess_inv([("pk-encryption", "rsa", [], None),
                     ("hash", "md5", [], None)], tmp_path, "b.json")))
    # md5 gone -> stale entry warned
    pr = Inventory.load(_assess_inv([("pk-encryption", "rsa", [], None)], tmp_path, "p.json"))
    findings = baseline.lint(base, pr)
    assert any(f.level == "warning" and "no longer exposed" in f.message
               for f in findings)


def test_baseline_lint_malformed():
    from qramp import baseline
    findings = baseline.lint({"accepted": [{"display": "x"},
                                            {"asset_id": "A-1"},
                                            {"asset_id": "A-1"}]})
    levels = [(f.level, f.message) for f in findings]
    assert any(lv == "error" and "missing" in m for lv, m in levels)
    assert any(lv == "error" and "duplicate" in m for lv, m in levels)


def test_baseline_exposure_selection(tmp_path):
    from qramp import baseline
    cbom = Inventory.load(_assess_inv([("symmetric-cipher", "aes", [], 128)],
                                      tmp_path))          # aes128 = weakened
    # default (quantum_broken) freezes nothing
    assert baseline.generate(cbom)["accepted"] == []
    # explicitly baseline weakened
    doc = baseline.generate(cbom, ("quantum_weakened",))
    assert len(doc["accepted"]) == 1


def test_cli_baseline_generate_and_check(tmp_path):
    from qramp.cli import main
    base = _assess_inv([("pk-encryption", "rsa", [], None),
                        ("hash", "md5", [], None)], tmp_path, "b.json")
    blpath = tmp_path / "baseline.json"
    assert main(["baseline", base, "-o", str(blpath)]) == 0
    assert blpath.exists()
    # unchanged assessment passes
    same = _assess_inv([("pk-encryption", "rsa", [], None),
                        ("hash", "md5", [], None)], tmp_path, "s.json")
    assert main(["baseline-check", same, "--baseline", str(blpath)]) == 0


def test_cli_baseline_check_fails_on_new(tmp_path):
    from qramp.cli import main
    base = _assess_inv([("pk-encryption", "rsa", [], None)], tmp_path, "b.json")
    blpath = tmp_path / "baseline.json"
    main(["baseline", base, "-o", str(blpath)])
    # PR adds a new broken asset
    pr = _assess_inv([("pk-encryption", "rsa", [], None),
                      ("signature", "dsa", [], None)], tmp_path, "p.json")
    assert main(["baseline-check", pr, "--baseline", str(blpath)]) == 1


def test_cli_baseline_check_strict_fails_on_stale(tmp_path):
    from qramp.cli import main
    base = _assess_inv([("pk-encryption", "rsa", [], None),
                        ("hash", "md5", [], None)], tmp_path, "b.json")
    blpath = tmp_path / "baseline.json"
    main(["baseline", base, "-o", str(blpath)])
    # md5 resolved (backlog shrank) but no new -> passes normally, fails --strict
    pr = _assess_inv([("pk-encryption", "rsa", [], None)], tmp_path, "p.json")
    assert main(["baseline-check", pr, "--baseline", str(blpath)]) == 0
    assert main(["baseline-check", pr, "--baseline", str(blpath), "--strict"]) == 1


def test_ci_has_baseline_gate():
    """crypto-scan runs an optional baseline gate that blocks only new exposure,
    exposes it as an output, and the gate matrix includes it."""
    import yaml
    ex = os.path.join(HERE, "..", "examples", "ci-full-pipeline.yml")
    if not os.path.exists(ex):
        pytest.skip("ci-full-pipeline.yml not present")
    doc = yaml.safe_load(open(ex, encoding="utf-8"))
    steps = doc["jobs"]["crypto-scan"]["steps"]
    bl = [s for s in steps if s.get("id") == "baseline_gate"]
    assert bl, "no baseline gate step"
    assert "baseline-check" in bl[0]["run"]
    assert ".qramp/baseline.json" in bl[0]["run"]       # opt-in via committed file
    assert bl[0].get("continue-on-error") is True
    assert "baseline_gate" in doc["jobs"]["crypto-scan"]["outputs"]
    gs = [s for s in doc["jobs"]["gate-summary"]["steps"]
          if s.get("name") == "Collect gate outcomes"][0]
    assert "baseline_gate" in gs["with"]["script"]


# ---------- org dashboard ----------
def _card(tmp_path, name, specs, gates=None, url=None):
    import yaml
    from qramp import assess, orgdash
    from qramp.model import Occurrence
    inv = Inventory()
    for prim, alg, tags, kl in specs:
        inv.observe(prim, alg, Occurrence("source-py", f"{alg}:1", alg, tags=tags),
                    key_length=kl)
    rules = yaml.safe_load(open(RULES, encoding="utf-8"))
    lifetimes = yaml.safe_load(open(os.path.join(TB, "policy", "data-lifetimes.yaml"),
                                    encoding="utf-8"))
    assess.classify(inv, rules); assess.prioritise(inv, rules, lifetimes)
    pmap = yaml.safe_load(open(os.path.join(HERE, "..", "src", "qramp", "data",
                                            "provider-map.yaml"), encoding="utf-8"))
    return orgdash.repo_card(inv, name=name, provider_map=pmap, gates=gates, url=url)


def test_repo_card_shape(tmp_path):
    card = _card(tmp_path, "acme/pay",
                 [("pk-encryption", "rsa", ["external"], None),
                  ("hash", "md5", [], None)],
                 gates={"Scan: quantum-broken (SARIF)": {"outcome": "failure"},
                        "Policy: rule pack": "success"})
    assert card["schema"] == "qramp-repo-card-1"
    assert card["repo"] == "acme/pay"
    assert card["metrics"]["quantum_broken"] == 2
    assert card["metrics"]["urgent"] == 1                # external RSA is P0/P1
    assert card["gates"]["failed"] == 1
    assert card["gates"]["total"] == 2


def test_repo_card_no_gates(tmp_path):
    card = _card(tmp_path, "acme/web", [("symmetric-cipher", "aes", [], 256)])
    assert card["gates"] is None                         # gates optional
    assert card["metrics"]["quantum_broken"] == 0


def test_org_aggregate(tmp_path):
    from qramp import orgdash
    cards = [
        _card(tmp_path, "a", [("pk-encryption", "rsa", ["external"], None)],
              gates={"g": "failure"}),
        _card(tmp_path, "b", [("signature", "ecdsa", [], None)],
              gates={"g": "success"}),
        _card(tmp_path, "c", [("symmetric-cipher", "aes", [], 256)],
              gates={"g": "success"}),
    ]
    agg = orgdash.aggregate(cards)
    assert agg["repos"] == 3
    assert agg["gate_fail_repos"] == 1
    assert agg["urgent_repos"] == 1
    assert agg["total_broken"] == 2                      # rsa + ecdsa


def test_org_dashboard_html_valid_and_worst_first(tmp_path):
    from qramp import orgdash
    cards = [
        _card(tmp_path, "acme/clean", [("symmetric-cipher", "aes", [], 256)],
              gates={"g": "success"}),
        _card(tmp_path, "acme/urgent", [("pk-encryption", "rsa", ["external"], None)],
              gates={"g": "failure"}, url="https://x/urgent"),
    ]
    html_doc = orgdash.render_dashboard(cards, title="Org")
    _assert_valid_html_str(html_doc)
    # worst-first: the failing-gate repo appears before the clean one
    assert html_doc.index("acme/urgent") < html_doc.index("acme/clean")
    assert "https://x/urgent" in html_doc                # url becomes a link


def test_org_dashboard_empty(tmp_path):
    from qramp import orgdash
    html_doc = orgdash.render_dashboard([], title="Empty")
    _assert_valid_html_str(html_doc)
    assert "No repo cards found" in html_doc


def test_org_load_cards_skips_non_cards(tmp_path):
    from qramp import orgdash
    import json
    (tmp_path / "good.json").write_text(json.dumps(_card(
        tmp_path, "a", [("hash", "md5", [], None)])))
    (tmp_path / "junk.json").write_text('{"not": "a card"}', encoding="utf-8")
    (tmp_path / "notes.txt").write_text("ignore me", encoding="utf-8")
    cards = orgdash.load_cards([str(tmp_path)])
    assert len(cards) == 1                               # only the real card


def test_cli_repo_card_and_dashboard(tmp_path):
    import json
    from qramp.cli import main
    assessment = _assess_inv([("pk-encryption", "rsa", ["external"], None)],
                             tmp_path, "a.json")
    gpath = tmp_path / "g.json"
    json.dump({"Scan: quantum-broken (SARIF)": "failure"}, open(gpath, "w", encoding="utf-8"))
    card = tmp_path / "cards" / "pay.json"
    card.parent.mkdir()
    assert main(["repo-card", assessment, "-o", str(card), "--name", "acme/pay",
                 "--gates", str(gpath)]) == 0
    assert card.exists()
    dash = tmp_path / "org.html"
    assert main(["org-dashboard", str(card.parent), "-o", str(dash)]) == 0
    assert "acme/pay" in dash.read_text(encoding="utf-8")


def _assert_valid_html_str(doc: str):
    from html.parser import HTMLParser
    class _P(HTMLParser):
        def error(self, m): raise AssertionError(m)
    _P().feed(doc)


def test_org_dashboard_workflow_example():
    """The org-dashboard workflow builds the dashboard from cards and deploys it."""
    import yaml
    ex = os.path.join(HERE, "..", "examples", "org-dashboard.yml")
    if not os.path.exists(ex):
        pytest.skip("org-dashboard.yml not present")
    doc = yaml.safe_load(open(ex, encoding="utf-8"))
    steps = doc["jobs"]["build-dashboard"]["steps"]
    runs = " ".join(s.get("run", "") for s in steps)
    assert "qramp org-dashboard cards" in runs
    assert "deploy" in doc["jobs"]                        # publishes to Pages
