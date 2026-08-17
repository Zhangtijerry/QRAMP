# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Ti Zhang
"""qramp.cyclonedx — spec-compliant CycloneDX 1.6 CBOM serialization.

Maps QRAMP's internal CryptoAsset model onto the CycloneDX 1.6 cryptographic
`cryptoProperties` schema so the inventory can be consumed by any CBOM/SBOM
tooling (cyclonedx-cli, dependency-track, IBM CBOMkit, …).

QRAMP-specific enrichment (exposure class, Mosca tier, remediation plan) is kept
but moved into standard `properties` name-value pairs under a `qramp:` namespace,
so it neither breaks schema validation nor is lost.
"""
from __future__ import annotations

from dataclasses import asdict

# --- enum mappings to the CycloneDX 1.6 spec --------------------------------

# internal primitive -> CycloneDX algorithmProperties.primitive enum
# (drbg, mac, block-cipher, stream-cipher, signature, hash, pke, xof, kdf,
#  key-agree, kem, ae, combiner, other, unknown)
_PRIMITIVE = {
    "hash": "hash",
    "mac": "mac",
    "symmetric-cipher": "block-cipher",
    "stream-cipher": "stream-cipher",
    "pk-encryption": "pke",
    "signature": "signature",
    "key-agreement": "key-agree",
    "kem": "kem",
    "kdf": "kdf",
    "random": "drbg",
    "protocol": None,          # handled as assetType: protocol
}

# authenticated-encryption ciphers should map to primitive "ae" not block-cipher
_AEAD_MODES = {"gcm", "ccm", "poly1305", "ocb", "eax"}

# internal mode -> CycloneDX mode enum (cbc, ecb, ccm, gcm, cfb, ofb, ctr,
# other, unknown). Anything unrecognised becomes "other".
_MODE = {"cbc": "cbc", "ecb": "ecb", "ccm": "ccm", "gcm": "gcm",
         "cfb": "cfb", "ofb": "ofb", "ctr": "ctr"}

# protocol algorithm -> protocolProperties.protocolType enum
# (tls, ssh, ipsec, ike, sstp, wpa, other, unknown)
_PROTO_TYPE = {"tls": "tls", "ssl": "tls", "ssh": "ssh", "ipsec": "ipsec",
               "ike": "ike"}

# well-known algorithm OIDs (a small, high-value subset)
_OID = {
    ("hash", "md5"): "1.2.840.113549.2.5",
    ("hash", "sha1"): "1.3.14.3.2.26",
    ("hash", "sha2-256"): "2.16.840.1.101.3.4.2.1",
    ("hash", "sha2-384"): "2.16.840.1.101.3.4.2.2",
    ("hash", "sha2-512"): "2.16.840.1.101.3.4.2.3",
    ("pk-encryption", "rsa"): "1.2.840.113549.1.1.1",
    ("signature", "dsa"): "1.2.840.10040.4.1",
    ("signature", "ecdsa"): "1.2.840.10045.2.1",
    ("signature", "ed25519"): "1.3.101.112",
    ("key-agreement", "dh"): "1.2.840.113549.1.3.1",
    ("key-agreement", "ecdh"): "1.3.132.1.12",
}

# rough classical security level (bits) for common asset families; used only
# when a specific key length is unavailable. None means "leave unset".
_CLASSICAL_BITS = {
    ("hash", "md5"): 0, ("hash", "sha1"): 0,
    ("hash", "sha2-256"): 128, ("hash", "sha2-512"): 256,
    ("symmetric-cipher", "des"): 56, ("symmetric-cipher", "3des"): 112,
    ("symmetric-cipher", "rc4"): 0,
}

# NIST post-quantum security category (0-6). 0 = meets no category (broken by a
# CRQC); PQ algorithms carry their claimed category.
_PQ_CATEGORY = {
    ("key-agreement", "ml-kem"): 3,
    ("signature", "ml-dsa"): 3,
    ("key-agreement", "hybrid-pq"): 3,
}


def _crypto_functions(primitive: str) -> list[str]:
    return {
        "hash": ["digest"],
        "mac": ["tag"],
        "symmetric-cipher": ["encrypt", "decrypt"],
        "stream-cipher": ["encrypt", "decrypt"],
        "pk-encryption": ["encrypt", "decrypt", "keygen"],
        "signature": ["sign", "verify", "keygen"],
        "key-agreement": ["keygen"],
    }.get(primitive, ["other"])


def _classical_bits(a) -> int | None:
    if a.key_length is not None:
        # symmetric key length ~ classical bits; asymmetric key length is not a
        # security-level in bits, so only report it for symmetric/hash families.
        if a.primitive in ("symmetric-cipher", "stream-cipher", "mac", "hash"):
            return a.key_length
    return _CLASSICAL_BITS.get((a.primitive, a.algorithm))


def _pq_category(a, exposure_class: str | None) -> int:
    cat = _PQ_CATEGORY.get((a.primitive, a.algorithm))
    if cat is not None:
        return cat
    # symmetric primitives keep meaningful post-quantum strength (Grover only
    # halves the effective key length). Map to NIST PQ categories:
    #   AES-128 -> 1, AES-192 -> 3, AES-256 -> 5; SHA-256 -> 2, SHA-384/512 -> 4.
    if exposure_class in ("pq_ready", "hybrid"):
        if a.primitive in ("symmetric-cipher", "stream-cipher", "mac"):
            kl = a.key_length or 0
            if kl >= 256:
                return 5
            if kl >= 192:
                return 3
            if kl >= 128:
                return 1
            return 5 if a.algorithm in ("aes", "chacha20") else 0
        if a.primitive == "hash":
            kl = a.key_length or _digest_bits(a.algorithm)
            if kl >= 384:
                return 4
            if kl >= 256:
                return 2
            return 0
        return 0
    # a quantum_broken/weakened asset meets no NIST PQ category
    return 0


def _digest_bits(algorithm: str) -> int:
    for n in (512, 384, 256, 224):
        if str(n) in algorithm:
            return n
    return 0


def _algorithm_properties(a) -> dict:
    primitive = _PRIMITIVE.get(a.primitive, "other")
    # promote AEAD ciphers to primitive "ae"
    if a.primitive == "symmetric-cipher" and a.mode in _AEAD_MODES:
        primitive = "ae"
    ap: dict = {"primitive": primitive}
    # parameterSetIdentifier: key length in bits, else the params qualifier
    if a.key_length is not None:
        ap["parameterSetIdentifier"] = str(a.key_length)
    elif a.params:
        ap["parameterSetIdentifier"] = a.params
    # curve: only for EC families, taken from params
    if a.algorithm in ("ecdsa", "ecdh") and a.params:
        ap["curve"] = a.params
    if a.mode:
        ap["mode"] = _MODE.get(a.mode, "other")
    ap["cryptoFunctions"] = _crypto_functions(a.primitive)
    cb = _classical_bits(a)
    if cb is not None:
        ap["classicalSecurityLevel"] = cb
    ap["nistQuantumSecurityLevel"] = _pq_category(a, a.exposure_class)
    return ap


def _protocol_properties(a) -> dict:
    pp: dict = {"type": _PROTO_TYPE.get(a.algorithm, "other")}
    if a.params:
        pp["version"] = a.params
    return pp


def _qramp_properties(a, owners, tags) -> list[dict]:
    props = [
        {"name": "qramp:exposureClass", "value": a.exposure_class or "unknown"},
        {"name": "qramp:tier", "value": a.tier or "unset"},
    ]
    # canonical model fields, so a QRAMP-produced BOM round-trips losslessly
    # regardless of how the spec fields are name-mangled. Foreign BOMs lack
    # these and fall back to heuristic name parsing on import.
    props.append({"name": "qramp:primitive", "value": a.primitive})
    props.append({"name": "qramp:algorithm", "value": a.algorithm})
    if a.params:
        props.append({"name": "qramp:params", "value": a.params})
    if a.key_length is not None:
        props.append({"name": "qramp:keyLength", "value": str(a.key_length)})
    if a.mode:
        props.append({"name": "qramp:mode", "value": a.mode})
    if a.rationale:
        props.append({"name": "qramp:rationale", "value": a.rationale})
    if a.remediate:
        import json
        props.append({"name": "qramp:remediate",
                      "value": json.dumps(a.remediate, ensure_ascii=False)})
    for o in owners:
        props.append({"name": "qramp:owner", "value": o})
    for t in tags:
        props.append({"name": "qramp:tag", "value": t})
    return props


def _occurrences(a) -> list[dict]:
    """CycloneDX evidence.occurrences: location (+ line) per finding. QRAMP's
    richer per-occurrence fields are preserved as a property blob referenced by
    bom-ref would be overkill, so they live in the location string and a
    parallel qramp property is emitted at component level."""
    out = []
    for o in a.occurrences:
        loc = o.locator
        entry: dict = {"location": loc}
        # split "path:line" into location + line when possible
        if ":" in loc:
            head, _, tail = loc.rpartition(":")
            if tail.isdigit():
                entry = {"location": head, "line": int(tail)}
        entry["additionalContext"] = f"[{o.collector}] {o.evidence}"
        out.append(entry)
    return out


def to_cyclonedx(inv, *, spec_version: str = "1.6") -> dict:
    """Serialize an Inventory to a spec-compliant CycloneDX 1.6 CBOM dict."""
    comps = []
    for a in inv.assets:
        owners = sorted(a.owners())
        tags = sorted(a.tag_union())

        if a.primitive == "protocol":
            crypto_props = {"assetType": "protocol",
                            "protocolProperties": _protocol_properties(a)}
        else:
            crypto_props = {"assetType": "algorithm",
                            "algorithmProperties": _algorithm_properties(a)}
        oid = _OID.get((a.primitive, a.algorithm))
        if oid:
            crypto_props["oid"] = oid

        comp = {
            "type": "cryptographic-asset",
            "bom-ref": a.asset_id,
            "name": a.display,
            "cryptoProperties": crypto_props,
            "evidence": {"occurrences": _occurrences(a)},
            "properties": _qramp_properties(a, owners, tags),
        }
        comps.append(comp)

    # --- software components (from the SBOM) + the provides dependency graph ---
    # A crypto asset's bom-ref, resolved from its key.
    asset_ref = {a.key: a.asset_id for a in inv.assets}
    dependencies = []
    for c in inv.components:
        comp_ref = c.bom_ref
        lib = {"type": c.ctype, "bom-ref": comp_ref, "name": c.name,
               "version": c.version}
        if c.purl:
            lib["purl"] = c.purl
        comps.append(lib)
        # dependency node: this component PROVIDES these crypto assets
        provided_refs = sorted(asset_ref[k] for k in c.provides if k in asset_ref)
        if provided_refs:
            dependencies.append({"ref": comp_ref, "provides": provided_refs})

    # --- certificate nodes (assetType: certificate) + the trust chain ---
    for ct in inv.certificates:
        cp = {"subjectName": ct.subject, "issuerName": ct.issuer}
        if ct.not_after:
            cp["notValidAfter"] = ct.not_after
        if ct.sig_ref and ct.sig_ref in asset_ref:
            cp["signatureAlgorithmRef"] = asset_ref[ct.sig_ref]
        if ct.key_ref and ct.key_ref in asset_ref:
            cp["subjectPublicKeyRef"] = asset_ref[ct.key_ref]
        props = [{"name": "qramp:isCA", "value": str(ct.is_ca).lower()},
                 {"name": "qramp:selfSigned", "value": str(ct.self_signed).lower()}]
        for t in sorted(ct.weak_tags):
            props.append({"name": "qramp:weakTag", "value": t})
        comps.append({
            "type": "cryptographic-asset", "bom-ref": ct.bom_ref,
            "name": ct.display,
            "cryptoProperties": {"assetType": "certificate",
                                 "certificateProperties": cp},
            "properties": props,
        })
        if ct.signed_by:                     # cert dependsOn its issuer cert
            dependencies.append({"ref": ct.bom_ref, "dependsOn": [ct.signed_by]})

    tools = [{"vendor": "qramp", "name": "qramp", "version": "0.1.0"}]
    metadata = {
        "timestamp": inv.meta["generated"],
        "tools": {"components": [
            {"type": "application", "name": t["name"],
             "version": t["version"], "publisher": t["vendor"]}
            for t in tools]},
        "properties": [
            {"name": "qramp:collector",
             "value": f"{c['name']}: " + ", ".join(
                 f"{k}={v}" for k, v in c.items() if k != "name")}
            for c in inv.meta.get("collectors", [])
        ],
    }
    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": spec_version,
        "serialNumber": inv.meta["serial"],
        "version": 1,
        "metadata": metadata,
        "components": comps,
    }
    if dependencies:
        doc["dependencies"] = dependencies
    return doc


# --- import: parse a spec CycloneDX 1.6 CBOM back into the internal model ----

# invert the export primitive map. Note ae -> symmetric-cipher (AEAD is a mode
# in QRAMP's model, not a separate primitive) and drbg -> random.
_PRIMITIVE_INV = {
    "hash": "hash", "mac": "mac", "block-cipher": "symmetric-cipher",
    "stream-cipher": "stream-cipher", "pke": "pk-encryption",
    "signature": "signature", "key-agree": "key-agreement", "kem": "kem",
    "kdf": "kdf", "drbg": "random", "ae": "symmetric-cipher",
    "xof": "hash", "combiner": "key-agreement", "other": "unknown",
    "unknown": "unknown",
}

# spec algorithm-name (component.name / OID) heuristics -> canonical algorithm.
# The component name in a foreign BOM is free-form (e.g. "AES-128-GCM",
# "SHA512withRSA", "ECDSA"), so we extract the leading token and canonicalise.
def _algorithm_from_name(name: str) -> str:
    from .model import canon_algorithm
    head = name.strip().split("[")[0].strip()          # drop QRAMP "[primitive]" suffix
    head = head.split("(")[0].strip()                   # drop "(params)" suffix
    # take the first token before a space or slash, e.g. "AES-256-GCM" / "SHA512withRSA"
    token = head.replace("_", "-").split(" ")[0].split("/")[0].lower()
    # try the whole token first (handles canonical names like sha2-256, sha3-512,
    # ml-kem, x25519 that must NOT be truncated)
    whole = canon_algorithm(token)
    if whole in _KNOWN_ALGS:
        return whole
    # common spec spellings: "sha512withrsa" -> rsa signature scheme; take the
    # signing algorithm suffix if present
    for sep in ("with", "-with-"):
        if sep in token:
            tail = token.split(sep)[-1]
            c = canon_algorithm(tail)
            if c in _KNOWN_ALGS:
                return c
    # otherwise strip a trailing "-<bits>" or "-<mode>" (AES-256-GCM -> aes)
    base = token.split("-")[0]
    return canon_algorithm(base)


# canonical algorithm tokens QRAMP recognises (for the foreign-name heuristic)
_KNOWN_ALGS = {
    "rsa", "rsa-pss", "dsa", "ecdsa", "ed25519", "ed448", "dh", "ecdh",
    "x25519", "x448", "aes", "des", "3des", "rc4", "chacha20", "blowfish",
    "rc2", "md5", "md4", "sha1", "sha2-224", "sha2-256", "sha2-384",
    "sha2-512", "sha3-256", "sha3-512", "ml-kem", "ml-dsa", "slh-dsa",
    "hybrid-pq", "xsalsa20",
}


def _int_or_none(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _asset_from_component(comp: dict, source_tool: str):
    """Build a (CryptoAsset-shaped kwargs, occurrences) tuple from one
    cryptographic-asset component. Returns None for non-crypto components."""
    from .model import Occurrence, canon_algorithm
    cp = comp.get("cryptoProperties")
    if not cp:
        return None
    asset_type = cp.get("assetType")
    name = comp.get("name", "")

    # QRAMP enrichment (present only in QRAMP-produced BOMs)
    qramp_props = {}
    owners, tags = [], []
    for p in comp.get("properties", []):
        n, v = p.get("name", ""), p.get("value", "")
        if n == "qramp:owner":
            owners.append(v)
        elif n == "qramp:tag":
            tags.append(v)
        elif n.startswith("qramp:"):
            qramp_props[n[len("qramp:"):]] = v

    # Fast path: a QRAMP-produced BOM carries the exact canonical fields, so we
    # recover them verbatim (lossless round-trip) rather than re-deriving from
    # the name-mangled spec fields.
    if "primitive" in qramp_props and "algorithm" in qramp_props:
        primitive = qramp_props["primitive"]
        algorithm = qramp_props["algorithm"]
        params = qramp_props.get("params", "")
        key_length = _int_or_none(qramp_props.get("keyLength"))
        mode = qramp_props.get("mode", "")
    elif asset_type == "protocol":
        pp = cp.get("protocolProperties", {})
        primitive = "protocol"
        algorithm = canon_algorithm(pp.get("type", name) or "unknown")
        params = pp.get("version", "") or ""
        key_length = None
        mode = ""
    else:
        ap = cp.get("algorithmProperties", {})
        primitive = _PRIMITIVE_INV.get(ap.get("primitive", "unknown"), "unknown")
        algorithm = _algorithm_from_name(name)
        # parameterSetIdentifier is a string: numeric -> key_length, else params
        psi = ap.get("parameterSetIdentifier")
        key_length = _int_or_none(psi)
        params = "" if key_length is not None else (psi or "")
        # curve overrides params for EC
        if ap.get("curve"):
            params = ap["curve"]
        # AEAD: primitive "ae" implies an AEAD mode; recover mode
        mode = ap.get("mode", "") or ""
        if mode == "other":
            mode = ""

    # occurrences: CycloneDX evidence.occurrences -> QRAMP occurrences, tagged
    # with provenance so merge/diff can tell tools apart.
    occs = []
    for o in comp.get("evidence", {}).get("occurrences", []):
        loc = o.get("location", "")
        if "line" in o:
            loc = f"{loc}:{o['line']}"
        ctx = o.get("additionalContext", "")
        occs.append(Occurrence(
            collector=f"import:{source_tool}",
            locator=loc or f"(imported from {source_tool})",
            evidence=ctx or f"imported from {source_tool}",
            confidence=1.0,
            owner=owners[0] if owners else None,
            tags=list(tags) + [f"source:{source_tool}"],
        ))
    if not occs:
        occs = [Occurrence(collector=f"import:{source_tool}",
                           locator=f"(imported from {source_tool})",
                           evidence=f"declared in {source_tool} CBOM",
                           tags=list(tags) + [f"source:{source_tool}"])]

    return {
        "primitive": primitive, "algorithm": algorithm, "params": params,
        "key_length": key_length, "mode": mode, "occurrences": occs,
        "exposure_class": qramp_props.get("exposureClass"),
        "tier": qramp_props.get("tier"),
        "rationale": qramp_props.get("rationale"),
    }, occs


def from_cyclonedx(doc: dict, source_tool: str | None = None):
    """Parse a CycloneDX 1.6 CBOM dict into an Inventory. Works on both QRAMP's
    own spec export (recovering enrichment) and foreign tools' BOMs. Each
    imported occurrence is tagged with its provenance (source:<tool>)."""
    from .model import Inventory, CryptoAsset
    if doc.get("bomFormat") != "CycloneDX":
        raise ValueError("not a CycloneDX document")
    # identify the producing tool for provenance
    if source_tool is None:
        source_tool = "unknown"
        tools = doc.get("metadata", {}).get("tools", {})
        comps = tools.get("components") if isinstance(tools, dict) else tools
        if comps:
            source_tool = (comps[0].get("name") if isinstance(comps[0], dict)
                           else str(comps[0])) or "unknown"

    inv = Inventory()
    if "serialNumber" in doc:
        inv.meta["imported_serial"] = doc["serialNumber"]
    n = 0
    ref_to_asset = {}          # component bom-ref -> resolved CryptoAsset
    ref_to_cert = {}           # component bom-ref -> Certificate
    for comp in doc.get("components", []):
        if comp.get("type") != "cryptographic-asset":
            continue
        # certificate node?
        cp = comp.get("cryptoProperties", {})
        if cp.get("assetType") == "certificate":
            from .model import Certificate
            certp = cp.get("certificateProperties", {})
            weak, is_ca, self_signed = set(), False, False
            for p in comp.get("properties", []):
                if p.get("name") == "qramp:weakTag":
                    weak.add(p.get("value"))
                elif p.get("name") == "qramp:isCA":
                    is_ca = p.get("value") == "true"
                elif p.get("name") == "qramp:selfSigned":
                    self_signed = p.get("value") == "true"
            cert = Certificate(
                subject=certp.get("subjectName", "?"),
                issuer=certp.get("issuerName", "?"),
                not_after=certp.get("notValidAfter", ""),
                is_ca=is_ca, self_signed=self_signed, weak_tags=weak)
            inv.add_certificate(cert)
            if comp.get("bom-ref"):
                ref_to_cert[comp["bom-ref"]] = cert
            continue
        built = _asset_from_component(comp, source_tool)
        if built is None:
            continue
        kwargs, occs = built
        # merge into inventory using the canonical key (cross-tool resolution)
        asset = None
        for occ in occs:
            asset = inv.observe(kwargs["primitive"], kwargs["algorithm"], occ,
                                params=kwargs["params"],
                                key_length=kwargs["key_length"],
                                mode=kwargs["mode"])
        # carry enrichment onto the resolved asset if present and not already set
        if asset is not None:
            if kwargs.get("exposure_class") and not asset.exposure_class:
                asset.exposure_class = kwargs["exposure_class"]
            if kwargs.get("tier") and not asset.tier:
                asset.tier = kwargs["tier"]
            if kwargs.get("rationale") and not asset.rationale:
                asset.rationale = kwargs["rationale"]
            if comp.get("bom-ref"):
                ref_to_asset[comp["bom-ref"]] = asset
        n += 1

    # software components (library / framework / application) + provides edges
    ref_to_comp = {}
    for comp in doc.get("components", []):
        if comp.get("type") == "cryptographic-asset":
            continue
        c = inv.component(comp.get("name", "?"), comp.get("version", "?"),
                          purl=comp.get("purl", ""), ctype=comp.get("type", "library"))
        if comp.get("bom-ref"):
            ref_to_comp[comp["bom-ref"]] = c
    # dependency graph: resolve provides (component->asset) and dependsOn
    # (cert->issuer-cert for the trust chain, or component->asset).
    edges = 0
    for dep in doc.get("dependencies", []):
        ref = dep.get("ref")
        comp = ref_to_comp.get(ref)
        cert = ref_to_cert.get(ref)
        for target in dep.get("provides", []):
            asset = ref_to_asset.get(target)
            if comp is not None and asset is not None:
                inv.provide(comp, asset)
                edges += 1
        for target in dep.get("dependsOn", []):
            if cert is not None and target in ref_to_cert:
                cert.signed_by = ref_to_cert[target].bom_ref   # rebuild chain link
                edges += 1
            else:
                asset = ref_to_asset.get(target)
                if comp is not None and asset is not None:
                    inv.provide(comp, asset)
                    edges += 1

    inv.record_collector(f"import:{source_tool}",
                         {"components": n, "provides_edges": edges})
    return inv
