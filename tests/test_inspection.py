"""Inspection regression tests. Opt into Java tests with FFDEC_TEST_JAR."""
import asyncio
import json
import os
from pathlib import Path
import struct
import sys

import pytest

from ffdecmcp import inspection
from ffdecmcp.config import FFDecConfig, FFDecMode
from tests.prototypes.verify_avm2 import fixture


@pytest.mark.parametrize("data", [b"FWS", fixture()[:-3],
    fixture()[:40], b"ZWS" + fixture()[3:]])
def test_preflight_rejects_invalid_or_unsupported(data):
    with pytest.raises(inspection.InspectionError):
        inspection.validate_container(data)


def test_preflight_rejects_truncated_tag_with_matching_size():
    raw = bytearray(fixture()[:40])
    struct.pack_into("<I", raw, 4, len(raw))
    with pytest.raises(inspection.InspectionError, match="Tag payload"):
        inspection.validate_container(raw)


def test_preflight_accepts_fws_and_cws():
    import zlib
    raw = fixture()
    compressed = b"CWS" + raw[3:8] + zlib.compress(raw[8:])
    assert inspection.validate_container(raw) == inspection.validate_container(compressed)


def test_supervisor_timeout():
    with pytest.raises(inspection.InspectionError, match="deadline"):
        inspection._run([sys.executable, "-c", "import time; time.sleep(30)"], 0.1, 4096)


def test_supervisor_output_bound():
    with pytest.raises(inspection.InspectionError, match="budget"):
        inspection._run([sys.executable, "-c", "print('x'*100000)"], 5, 4096)


def test_stale_cursor_rejected_before_java(tmp_path):
    path = tmp_path / "sample.swf"
    path.write_bytes(fixture())
    with pytest.raises(inspection.InspectionError, match="Artifact changed"):
        inspection.inspect_avm2("classes", str(path), expected_sha256="wrong")


def test_pagination_requires_digest():
    with pytest.raises(inspection.InspectionError, match="Pagination requires"):
        inspection.inspect_avm2("classes", "unused.swf", offset=1)


def test_mcp_catalog_has_readonly_tools():
    from ffdecmcp.server import mcp
    # FastMCP 2/4 expose different inventory APIs.
    async def catalog():
        if hasattr(mcp, "list_tools"):
            return await mcp.list_tools()
        return list((await mcp.get_tools()).values())
    tools = {t.name: t for t in asyncio.run(catalog())}
    for name in ["list_avm2_classes", "inspect_avm2_method", "find_avm2_property_accesses"]:
        annotations = tools[name].annotations
        destructive = getattr(annotations, "destructive_hint", None)
        if destructive is None:
            destructive = annotations.destructiveHint
        read_only = getattr(annotations, "read_only_hint", None)
        if read_only is None:
            read_only = annotations.readOnlyHint
        assert destructive is False and read_only is True
    assert len(tools) == 42


@pytest.fixture
def java_config(monkeypatch):
    jar = os.environ.get("FFDEC_TEST_JAR")
    if not jar:
        pytest.skip("Set FFDEC_TEST_JAR to run real Java bridge tests")
    monkeypatch.setattr(inspection, "get_config",
        lambda: FFDecConfig(FFDecMode.JAR, jar))


def test_java_queries_and_pagination(java_config, tmp_path):
    path = tmp_path / "sample.swf"
    raw = fixture(nested=True)
    path.write_bytes(raw)
    result = inspection.inspect_avm2("accesses", str(path), property_name="value")
    assert result["total"] == 1
    row = result["results"][0]
    assert row["method_id"] == 4
    assert row["ownership"] == "lexical_context"
    assert any("writeValue" in owner for owner in row["enclosing_contexts"])
    assert row["offset"] == 3 and row["receiver_type"] is None
    first = inspection.inspect_avm2("method", str(path), abc_index=0, method_id=4, limit=2)
    assert first["results"][0]["kind"] == "method"
    assert first["next_offset"] == 2
    second = inspection.inspect_avm2("method", str(path), abc_index=0, method_id=4,
        limit=2, offset=2, expected_sha256=first["sha256"])
    assert second["results"][0]["offset"] == 1
    classes = inspection.inspect_avm2("classes", str(path))
    assert classes["total"] == 1 and "Probe" in classes["results"][0]["name"]
    assert len(json.dumps(result).encode()) < 65_536
    assert path.read_bytes() == raw
    assert list(tmp_path.iterdir()) == [path]


def test_java_dynamic_slots_and_missing_method(java_config, tmp_path):
    path = tmp_path / "dynamic.swf"
    path.write_bytes(fixture(dynamic=True))
    result = inspection.inspect_avm2("accesses", str(path))
    assert result["results"][0]["runtime_name"] is True
    assert result["results"][0]["runtime_namespace"] is True
    assert result["results"][0]["property_name"] == ""
    path.write_bytes(fixture(method_code=b"\xd0\x24\x07\x6d\x01\x47"))
    result = inspection.inspect_avm2("accesses", str(path))
    assert result["results"][0]["slot_id"] == 1
    assert result["results"][0]["property_name"] == ""
    with pytest.raises(inspection.InspectionError, match="Method body not found"):
        inspection.inspect_avm2("method", str(path), abc_index=0, method_id=999)
