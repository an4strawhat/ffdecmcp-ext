"""Load real-asset fixtures and expected results from a local manifest."""
import json
import os
from pathlib import Path

import pytest


def local_assets():
    configured = os.environ.get("FFDEC_TEST_ASSET_MANIFEST")
    if not configured:
        pytest.skip("Set FFDEC_TEST_ASSET_MANIFEST to a local fixture manifest")
    manifest = Path(configured).resolve()
    cases = json.loads(manifest.read_text(encoding="utf-8"))
    assert isinstance(cases, list) and cases, "Expected a nonempty fixture list"
    for case in cases:
        case["path"] = (manifest.parent / case["path"]).resolve()
    return cases


def catch_asset():
    case, = [case for case in local_assets() if "catch" in case]
    return case


def site(row):
    return row["method_id"], row["offset"]


def assert_catch(row, expected):
    for field in ("abc_index", "method_id", "offset", "slot_id", "property_name"):
        assert row[field] == expected[field], (field, row)
    assert row["opcode"] == "setslot" and row["slot_resolution"] == "catch_scope"
    assert any(all(part in owner for part in expected["owner_contains"])
               for owner in row["direct_owners"]), row
