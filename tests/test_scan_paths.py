"""Relative and absolute scan arguments must describe the same inventory."""
from pathlib import Path

import pytest

from qramp import assess, plan, scan
from qramp.model import Inventory
from test_revision import SOURCE_CASES


def test_testbed_relative_and_absolute_paths(tmp_path, monkeypatch):
    import yaml

    root = Path(__file__).resolve().parents[1]
    monkeypatch.chdir(root)
    testbed = Path("testbed")
    owners = yaml.safe_load((testbed / "policy/owners.yaml").read_text())
    rules = root / "src/qramp/rules/transition-2024.yaml"

    def make_plan(base, name):
        inventory = scan(
            Inventory(), source_dir=str(base / "sample-app"),
            sbom_path=str(base / "sample-app/sbom.cdx.json"),
            manifests_dir=str(base / "manifests"), cert_dir=str(base / "certs"),
            config_dir=str(base / "etc"), owner_map=owners,
        )
        cbom = str(tmp_path / f"{name}-cbom.json")
        assessment = str(tmp_path / f"{name}-assessment.json")
        inventory.save(cbom)
        assess.assess(cbom, str(rules), str(base / "policy/data-lifetimes.yaml"), assessment)
        return plan.plan(assessment, str(base / "policy/teams.yaml"), 36,
                         str(tmp_path / f"{name}.yaml"), solver="list")

    relative = make_plan(testbed, "relative")
    absolute = make_plan(testbed.resolve(), "absolute")
    assert relative["task_count"] > 0
    assert relative["tasks"] == absolute["tasks"]
    assert relative["weighted_exposure_days"] == absolute["weighted_exposure_days"]


@pytest.mark.parametrize(("filename", "content"), SOURCE_CASES)
def test_directory_filters_match_names(tmp_path, filename, content):
    app = tmp_path / "myvenvnotes" / "build-tools" / "vendor-tools" / "target-app"
    app.mkdir(parents=True)
    (app / filename).write_text(content)
    dependency = app / "node_modules"
    dependency.mkdir()
    (dependency / filename).write_text(content)

    inventory = scan(Inventory(), source_dir=str(app))
    scanned = {path for collector in inventory.meta["collectors"]
               for path in collector.get("scanned_paths", ())}
    assert scanned == {str(app / filename)}
    assert any(asset.algorithm == "md5" for asset in inventory.assets)
