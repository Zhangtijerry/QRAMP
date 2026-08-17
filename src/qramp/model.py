# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Ti Zhang
"""qramp.model — Layer 2: the cross-layer entity model.

A CryptoAsset is keyed on (primitive, algorithm, params, key_length, mode).
Every observation is retained as an Occurrence carrying a locator, the
evidence that produced it, and a confidence weight. Assets serialise to a
CycloneDX-style cryptographic bill of materials (CBOM).
"""
from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone

SCHEMA_VERSION = "qramp-cbom/0.1"

# canonical primitive vocabulary
PRIMITIVES = (
    "pk-encryption", "key-agreement", "signature", "symmetric-cipher",
    "hash", "kdf", "mac", "protocol", "random",
)


def canon_algorithm(name: str) -> str:
    """Normalise an algorithm spelling to a canonical lowercase token."""
    n = (name or "").strip().lower().replace("_", "-")
    aliases = {
        "rsaencryption": "rsa", "rsa-pss": "rsa-pss", "id-ecpublickey": "ecdsa",
        "ecpublickey": "ecdsa", "ed25519": "ed25519", "ed448": "ed448",
        "secp256r1": "ecdsa", "prime256v1": "ecdsa",
        "aes": "aes", "des": "des", "des3": "3des", "tripledes": "3des",
        "3des": "3des", "rc4": "rc4", "arcfour": "rc4", "chacha20": "chacha20",
        "md5": "md5", "sha1": "sha1", "sha-1": "sha1",
        "sha256": "sha2-256", "sha-256": "sha2-256", "sha2-256": "sha2-256",
        "sha384": "sha2-384", "sha512": "sha2-512",
        "sha3-256": "sha3-256", "sha3-512": "sha3-512",
        "x25519": "x25519", "x448": "x448",
        "dh": "dh", "diffie-hellman": "dh", "ecdh": "ecdh", "ecdhe": "ecdh",
        "ml-kem": "ml-kem", "kyber": "ml-kem", "mlkem768": "ml-kem",
        "mlkem512": "ml-kem", "mlkem1024": "ml-kem", "kyber512": "ml-kem",
        "kyber768": "ml-kem", "kyber1024": "ml-kem",
        "ml-dsa": "ml-dsa", "dilithium": "ml-dsa",
        "mldsa44": "ml-dsa", "mldsa65": "ml-dsa", "mldsa87": "ml-dsa",
        "slh-dsa": "slh-dsa", "sphincs+": "slh-dsa", "sphincs": "slh-dsa",
        "fn-dsa": "fn-dsa", "falcon": "fn-dsa", "falcon512": "fn-dsa",
        "falcon1024": "fn-dsa",
        # non-standardised / round-alternate PQ (not FIPS-approved on their own)
        "frodokem": "frodo-kem", "frodo": "frodo-kem",
        "bike": "bike", "hqc": "hqc", "classic-mceliece": "classic-mceliece",
        "mceliece": "classic-mceliece",
        # lightweight symmetric / hash (NIST SP 800-232 & legacy)
        "ascon": "ascon", "ascon-128": "ascon", "ascon-128a": "ascon",
        "ascon-aead128": "ascon", "ascon-hash": "ascon-hash",
        "ascon-hash256": "ascon-hash", "ascon-xof": "ascon-hash",
        "present": "present", "present-80": "present", "present-128": "present",
        "prince": "prince", "speck": "speck", "simon": "simon",
        "gift": "gift", "gift-128": "gift", "katan": "katan",
        # extended-nonce ChaCha and AEAD spellings
        "xchacha20": "chacha20", "chacha20-poly1305": "chacha20",
        # hybrid KEX namings (classical + PQ)
        "hybrid-pq": "hybrid-pq",
        "x25519-mlkem768": "hybrid-pq", "x25519mlkem768": "hybrid-pq",
        "x25519-kyber768": "hybrid-pq", "secp256r1-mlkem768": "hybrid-pq",
        "p256-mlkem768": "hybrid-pq", "p384-mlkem1024": "hybrid-pq",
        "x-wing": "hybrid-pq", "xwing": "hybrid-pq",
    }
    return aliases.get(n, n)


@dataclass
class Occurrence:
    """One piece of evidence that an asset exists somewhere."""
    collector: str                 # e.g. "source-py", "certs", "tls"
    locator: str                   # file:line, cert path, host:port ...
    evidence: str                  # human-readable evidence string
    confidence: float = 1.0        # 0..1
    owner: str | None = None       # owning team if known
    tags: list[str] = field(default_factory=list)   # e.g. ["external", "long-lived-data"]


@dataclass
class Component:
    """A software component (library / framework) from an SBOM. Carries the
    edges to the cryptographic assets it *provides*, so the graph can answer
    "if I swap this library, which crypto assets are affected?"."""
    name: str
    version: str = "?"
    purl: str = ""
    ctype: str = "library"          # CycloneDX component type
    provides: set = field(default_factory=set)   # set of CryptoAsset.key tuples

    @property
    def key(self) -> tuple:
        return (self.name.lower(), self.version)

    @property
    def bom_ref(self) -> str:
        base = self.purl or f"{self.name}@{self.version}"
        h = hashlib.sha256(base.encode()).hexdigest()[:12]
        return f"C-{h}"

    @property
    def display(self) -> str:
        return f"{self.name}@{self.version}"


@dataclass
class Certificate:
    """One X.509 certificate as a node in the trust chain. Carries references to
    the crypto assets it embeds (subject public key, own signature algorithm)
    and a `signed_by` link to the certificate that issued it, so the graph can
    find the weakest link in a chain — e.g. a strong leaf issued by a CA that
    still signs with SHA-1."""
    subject: str
    issuer: str
    locator: str = ""
    serial: str = ""
    not_after: str = ""
    is_ca: bool = False
    self_signed: bool = False
    key_ref: tuple | None = None        # CryptoAsset.key of the subject public key
    sig_ref: tuple | None = None        # CryptoAsset.key of the signature algorithm
    weak_tags: set = field(default_factory=set)   # weak-key / weak-curve / weak-signature / expired ...
    signed_by: str | None = None        # bom_ref of the issuer certificate, if resolved

    @property
    def key(self) -> tuple:
        return (self.subject, self.serial or self.locator)

    @property
    def bom_ref(self) -> str:
        base = f"{self.subject}|{self.serial}|{self.locator}"
        h = hashlib.sha256(base.encode()).hexdigest()[:12]
        return f"X-{h}"

    @property
    def display(self) -> str:
        role = "CA" if self.is_ca else "leaf"
        return f"{self.subject} [{role}]"


@dataclass
class CryptoAsset:
    primitive: str                 # one of PRIMITIVES
    algorithm: str                 # canonical token
    params: str = ""               # curve, mode-of-use qualifier, protocol version...
    key_length: int | None = None
    mode: str = ""                 # block-cipher mode etc.
    occurrences: list[Occurrence] = field(default_factory=list)
    # filled by the assessment layer:
    exposure_class: str | None = None    # quantum_broken | quantum_weakened | pq_ready | hybrid | unknown
    tier: str | None = None              # P0..P3
    rationale: str | None = None
    rule_id: str | None = None           # id of the rule pack rule that classified this asset
    remediate: dict | None = None        # machine-checkable remediation target from the rule pack
    references: list | None = None       # governing-standard citations from the rule (provenance)

    @property
    def key(self) -> tuple:
        return (self.primitive, self.algorithm, self.params, self.key_length, self.mode)

    @property
    def asset_id(self) -> str:
        h = hashlib.sha256("|".join(str(k) for k in self.key).encode()).hexdigest()[:12]
        return f"A-{h}"

    @property
    def display(self) -> str:
        bits = f"-{self.key_length}" if self.key_length else ""
        extra = f" ({self.params})" if self.params else ""
        mode = f"/{self.mode}" if self.mode else ""
        return f"{self.algorithm.upper()}{bits}{mode}{extra} [{self.primitive}]"

    def tag_union(self) -> set[str]:
        s: set[str] = set()
        for o in self.occurrences:
            s.update(o.tags)
        return s

    def owners(self) -> set[str]:
        return {o.owner for o in self.occurrences if o.owner}


class Inventory:
    """Resolves occurrences into assets and serialises the CBOM."""

    def __init__(self) -> None:
        self._assets: dict[tuple, CryptoAsset] = {}
        self._components: dict[tuple, Component] = {}
        self._certs: dict[tuple, Certificate] = {}
        self.meta: dict = {
            "schema": SCHEMA_VERSION,
            "serial": f"urn:uuid:{uuid.uuid4()}",
            "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "collectors": [],
        }

    # -- resolution -----------------------------------------------------
    def observe(self, primitive: str, algorithm: str, occ: Occurrence,
                params: str = "", key_length: int | None = None, mode: str = "") -> CryptoAsset:
        alg = canon_algorithm(algorithm)
        key = (primitive, alg, params, key_length, mode)
        asset = self._assets.get(key)
        if asset is None:
            asset = CryptoAsset(primitive, alg, params, key_length, mode)
            self._assets[key] = asset
        asset.occurrences.append(occ)
        return asset

    def component(self, name: str, version: str = "?", purl: str = "",
                  ctype: str = "library") -> Component:
        """Register (or fetch) a software component."""
        key = (name.lower(), version)
        comp = self._components.get(key)
        if comp is None:
            comp = Component(name=name, version=version, purl=purl, ctype=ctype)
            self._components[key] = comp
        return comp

    def provide(self, comp: Component, asset: CryptoAsset) -> None:
        """Record that a software component provides a cryptographic asset —
        the dependsOn/provides edge of the graph."""
        comp.provides.add(asset.key)

    # -- graph queries --------------------------------------------------
    @property
    def components(self) -> list[Component]:
        return sorted(self._components.values(), key=lambda c: c.key)

    def assets_provided_by(self, comp: Component) -> list[CryptoAsset]:
        return [self._assets[k] for k in comp.provides if k in self._assets]

    def providers_of(self, asset: CryptoAsset) -> list[Component]:
        return [c for c in self._components.values() if asset.key in c.provides]

    def add_certificate(self, cert: Certificate) -> Certificate:
        """Register a certificate node (idempotent on its key)."""
        self._certs[cert.key] = cert
        return cert

    @property
    def certificates(self) -> list[Certificate]:
        return sorted(self._certs.values(), key=lambda c: (not c.is_ca, c.subject))

    def link_chain(self) -> int:
        """Resolve issuer→subject links across the certificate set: a cert's
        `signed_by` is set to the bom_ref of the cert whose subject matches this
        cert's issuer (and which is a CA). Returns the number of links made."""
        by_subject = {}
        for c in self._certs.values():
            by_subject.setdefault(c.subject, []).append(c)
        links = 0
        for c in self._certs.values():
            if c.self_signed:
                continue
            candidates = by_subject.get(c.issuer, [])
            issuer = next((x for x in candidates if x.is_ca), 
                          candidates[0] if candidates else None)
            if issuer is not None and issuer.key != c.key:
                c.signed_by = issuer.bom_ref
                links += 1
        return links

    def chain_of(self, cert: Certificate) -> list[Certificate]:
        """Walk from a leaf up to the root, following signed_by. Stops on a
        cycle or an unresolved issuer."""
        by_ref = {c.bom_ref: c for c in self._certs.values()}
        chain, seen, cur = [], set(), cert
        while cur is not None and cur.bom_ref not in seen:
            chain.append(cur)
            seen.add(cur.bom_ref)
            cur = by_ref.get(cur.signed_by) if cur.signed_by else None
        return chain

    def weakest_link(self, cert: Certificate) -> dict:
        """Find the weakest certificate in a leaf's chain up to the root. A leaf
        is only as trustworthy as the weakest cert above it, so a strong leaf
        under a SHA-1 CA is flagged. Returns the chain with each cert's weak
        tags and the aggregated set."""
        chain = self.chain_of(cert)
        all_weak = set()
        rows = []
        for c in chain:
            all_weak |= c.weak_tags
            rows.append({"cert": c.display, "role": "CA" if c.is_ca else "leaf",
                         "weak": sorted(c.weak_tags)})
        # the weakest link is the first cert carrying a chain-invalidating tag
        blocking = {"weak-signature", "weak-key", "weak-curve", "expired"}
        weakest = next((r for r in rows if set(r["weak"]) & blocking), None)
        return {
            "leaf": cert.display,
            "chain_length": len(chain),
            "chain": rows,
            "chain_weaknesses": sorted(all_weak),
            "weakest_link": weakest,
            "chain_broken_by": (weakest["cert"] if weakest and weakest["cert"] != cert.display
                                else None),
        }

    def impact_of_removing(self, comp: Component) -> dict:
        """What happens to the crypto inventory if `comp` is swapped out?

        Distinguishes assets this component *uniquely* provides (they would have
        no remaining provider — a genuine capability loss / migration blocker)
        from assets also shipped by another component (still available). This
        is the graph query that makes a library swap decision concrete."""
        provided = self.assets_provided_by(comp)
        uniquely, shared = [], []
        for a in provided:
            others = [c for c in self.providers_of(a) if c.key != comp.key]
            (shared if others else uniquely).append(
                {"asset": a.display, "exposure": a.exposure_class,
                 "also_provided_by": [c.display for c in others]})
        return {
            "component": comp.display,
            "provides_count": len(provided),
            "uniquely_provided": uniquely,     # lost if the component is removed
            "still_available": shared,         # another component also ships these
        }

    def record_collector(self, name: str, stats: dict) -> None:
        self.meta["collectors"].append({"name": name, **stats})

    def merge(self, other: "Inventory") -> dict:
        """Fold another inventory's assets into this one, resolving on the
        canonical key. Occurrences from both sides accumulate on the shared
        asset, so a finding seen by QRAMP and by an imported tool becomes one
        asset with evidence from both. Enrichment (exposure class / tier /
        rationale / remediate) is filled in only where this side lacks it, so a
        local assessment is never overwritten by imported values.

        Returns a small stats dict: assets seen only here, only in `other`, and
        in both."""
        mine = set(self._assets.keys())
        theirs = set(other._assets.keys())
        for key, oa in other._assets.items():
            here = self._assets.get(key)
            if here is None:
                self._assets[key] = oa
            else:
                here.occurrences.extend(oa.occurrences)
                if not here.exposure_class and oa.exposure_class:
                    here.exposure_class = oa.exposure_class
                if not here.tier and oa.tier:
                    here.tier = oa.tier
                if not here.rationale and oa.rationale:
                    here.rationale = oa.rationale
                if not here.remediate and oa.remediate:
                    here.remediate = oa.remediate
                if not here.references and oa.references:
                    here.references = oa.references
        for c in other.meta.get("collectors", []):
            self.meta["collectors"].append(c)
        # fold in software components and their provides edges
        for key, oc in other._components.items():
            here = self._components.get(key)
            if here is None:
                self._components[key] = oc
            else:
                here.provides |= oc.provides
        return {"only_local": len(mine - theirs),
                "only_imported": len(theirs - mine),
                "in_both": len(mine & theirs)}

    # -- access ---------------------------------------------------------
    @property
    def assets(self) -> list[CryptoAsset]:
        return sorted(self._assets.values(), key=lambda a: (a.primitive, a.algorithm, a.key_length or 0))

    def __len__(self) -> int:
        return len(self._assets)

    def occurrence_count(self) -> int:
        return sum(len(a.occurrences) for a in self._assets.values())

    # -- serialisation --------------------------------------------------
    def to_cbom(self) -> dict:
        comps = []
        for a in self.assets:
            comps.append({
                "type": "cryptographic-asset",
                "bom-ref": a.asset_id,
                "name": a.display,
                "cryptoProperties": {
                    "assetType": "algorithm",
                    "algorithmProperties": {
                        "primitive": a.primitive,
                        "parameterSetIdentifier": a.params or None,
                        "keyLength": a.key_length,
                        "mode": a.mode or None,
                    },
                },
                "evidence": {
                    "occurrences": [asdict(o) for o in a.occurrences],
                },
                "qramp": {
                    "exposureClass": a.exposure_class,
                    "tier": a.tier,
                    "rationale": a.rationale,
                    "ruleId": a.rule_id,
                    "remediate": a.remediate,
                    "references": a.references,
                    "owners": sorted(a.owners()),
                    "tags": sorted(a.tag_union()),
                },
            })
        asset_ref = {a.key: a.asset_id for a in self.assets}
        dependencies = []
        for c in self.components:
            comps.append({
                "type": c.ctype, "bom-ref": c.bom_ref,
                "name": c.name, "version": c.version,
                **({"purl": c.purl} if c.purl else {}),
            })
            provided = sorted(asset_ref[k] for k in c.provides if k in asset_ref)
            if provided:
                dependencies.append({"ref": c.bom_ref, "provides": provided})
        # certificate nodes + their key/sig refs and issuer (signed_by) chain
        for ct in self.certificates:
            cp = {"subjectName": ct.subject, "issuerName": ct.issuer,
                  "notValidAfter": ct.not_after}
            if ct.sig_ref and ct.sig_ref in asset_ref:
                cp["signatureAlgorithmRef"] = asset_ref[ct.sig_ref]
            if ct.key_ref and ct.key_ref in asset_ref:
                cp["subjectPublicKeyRef"] = asset_ref[ct.key_ref]
            comps.append({
                "type": "cryptographic-asset", "bom-ref": ct.bom_ref,
                "name": ct.display,
                "cryptoProperties": {"assetType": "certificate",
                                     "certificateProperties": cp},
                "qrampCert": {"isCA": ct.is_ca, "selfSigned": ct.self_signed,
                              "serial": ct.serial, "locator": ct.locator,
                              "weakTags": sorted(ct.weak_tags),
                              "signedBy": ct.signed_by},
            })
            deps = []
            if ct.signed_by:
                deps.append(ct.signed_by)           # this cert dependsOn its issuer
            if deps:
                dependencies.append({"ref": ct.bom_ref, "dependsOn": deps})
        doc = {
            "bomFormat": "CycloneDX", "specVersion": "1.6",
            "serialNumber": self.meta["serial"],
            "metadata": {"timestamp": self.meta["generated"],
                         "tools": [{"vendor": "qramp", "name": "qramp", "version": "0.1.0"}],
                         "qrampCollectors": self.meta["collectors"]},
            "components": comps,
        }
        if dependencies:
            doc["dependencies"] = dependencies
        return doc

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_cbom(), f, indent=2, ensure_ascii=False)

    # -- load (for assess/diff on a saved CBOM) -------------------------
    @classmethod
    def load(cls, path: str) -> "Inventory":
        inv = cls()
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
        inv.meta["serial"] = doc.get("serialNumber", inv.meta["serial"])
        ts = doc.get("metadata", {}).get("timestamp")
        if ts:
            inv.meta["generated"] = ts        # preserve the historical scan time
        cols = doc.get("metadata", {}).get("qrampCollectors")
        if cols:
            inv.meta["collectors"] = cols     # restore collector provenance (incl. aliases)
        ref_to_asset = {}
        ref_to_comp = {}
        ref_to_cert = {}
        for c in doc.get("components", []):
            if c.get("type") not in (None, "cryptographic-asset"):
                # a software component (library / framework / application)
                comp = Component(name=c.get("name", "?"), version=c.get("version", "?"),
                                 purl=c.get("purl", ""), ctype=c.get("type", "library"))
                inv._components[comp.key] = comp
                if c.get("bom-ref"):
                    ref_to_comp[c["bom-ref"]] = comp
                continue
            # a certificate node?
            cp = c.get("cryptoProperties", {})
            if cp.get("assetType") == "certificate":
                certp = cp.get("certificateProperties", {})
                qc = c.get("qrampCert", {})
                cert = Certificate(
                    subject=certp.get("subjectName", "?"),
                    issuer=certp.get("issuerName", "?"),
                    locator=qc.get("locator", ""),
                    serial=qc.get("serial", ""),
                    not_after=certp.get("notValidAfter", ""),
                    is_ca=qc.get("isCA", False),
                    self_signed=qc.get("selfSigned", False),
                    weak_tags=set(qc.get("weakTags", [])),
                    signed_by=qc.get("signedBy"),
                )
                inv._certs[cert.key] = cert
                if c.get("bom-ref"):
                    ref_to_cert[c["bom-ref"]] = cert
                continue
            ap = cp.get("algorithmProperties", {})
            q = c.get("qramp", {})
            occs = [Occurrence(**o) for o in c.get("evidence", {}).get("occurrences", [])]
            name = c.get("name", "")
            alg = name.split("-")[0].split(" ")[0].lower() if name else "unknown"
            # recover canonical fields
            asset = CryptoAsset(
                primitive=ap.get("primitive", "unknown"),
                algorithm=canon_algorithm(alg),
                params=ap.get("parameterSetIdentifier") or "",
                key_length=ap.get("keyLength"),
                mode=ap.get("mode") or "",
                occurrences=occs,
                exposure_class=q.get("exposureClass"),
                tier=q.get("tier"),
                rationale=q.get("rationale"),
                rule_id=q.get("ruleId"),
                remediate=q.get("remediate"),
                references=q.get("references"),
            )
            inv._assets[asset.key] = asset
            if c.get("bom-ref"):
                ref_to_asset[c["bom-ref"]] = asset
        # rebuild provides edges from the dependency graph
        for dep in doc.get("dependencies", []):
            comp = ref_to_comp.get(dep.get("ref"))
            if comp is None:
                continue
            for target in (dep.get("provides", []) + dep.get("dependsOn", [])):
                asset = ref_to_asset.get(target)
                if asset is not None:
                    comp.provides.add(asset.key)
        return inv


def diff(old: Inventory, new: Inventory) -> dict:
    ok, nk = {a.key for a in old.assets}, {a.key for a in new.assets}
    added = [a.display for a in new.assets if a.key not in ok]
    removed = [a.display for a in old.assets if a.key not in nk]
    return {"added": added, "removed": removed,
            "unchanged": len(ok & nk)}


def diff_detailed(a: Inventory, b: Inventory,
                  a_label: str = "A", b_label: str = "B") -> dict:
    """Compare two inventories asset-by-asset, reporting for the shared assets
    whether their exposure classification agrees. Used to reconcile a QRAMP
    scan against an imported third-party CBOM: assets found by only one tool
    are coverage gaps; assets both find but classify differently are conflicts
    worth investigating."""
    amap = {x.key: x for x in a.assets}
    bmap = {x.key: x for x in b.assets}
    only_a = [amap[k].display for k in amap.keys() - bmap.keys()]
    only_b = [bmap[k].display for k in bmap.keys() - amap.keys()]
    agree, conflict = [], []
    for k in amap.keys() & bmap.keys():
        xa, xb = amap[k], bmap[k]
        if xa.exposure_class and xb.exposure_class and xa.exposure_class != xb.exposure_class:
            conflict.append({"asset": xa.display,
                             a_label: xa.exposure_class, b_label: xb.exposure_class})
        else:
            agree.append(xa.display)
    return {
        f"only_in_{a_label}": sorted(only_a),
        f"only_in_{b_label}": sorted(only_b),
        "shared": len(amap.keys() & bmap.keys()),
        "classification_conflicts": conflict,
        "agree": len(agree),
    }
