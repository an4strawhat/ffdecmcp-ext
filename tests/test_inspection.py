"""Inspection regression tests. Opt into Java tests with FFDEC_TEST_JAR."""
import asyncio
import hashlib
import json
import os
from pathlib import Path
import struct
import sys

import pytest

from ffdecmcp import inspection
from ffdecmcp.config import FFDecConfig, FFDecMode
from tests.local_assets import assert_catch, catch_asset, compress_zws, site
from tests.prototypes.verify_avm2 import fixture


@pytest.mark.parametrize("version", ["26.4.0", "26.5.0"])
def test_inspection_recognizes_release_banner(version):
    assert inspection._inspection_version(
        f"Log warning\r\nJPEXS Free Flash Decompiler v.{version}\r\nUsage"
    ) == version


@pytest.mark.parametrize("version", ["26.4.01", "26.5.0-beta", "26.6.0"])
def test_inspection_rejects_unapproved_release_banner(version):
    with pytest.raises(inspection.InspectionError, match="detected " + version):
        inspection._inspection_version(f"JPEXS Free Flash Decompiler v.{version}\n")


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


def test_preflight_accepts_zws():
    raw = fixture()
    assert inspection.validate_container(compress_zws(raw)) == inspection.validate_container(raw)


def test_preflight_rejects_malformed_zws():
    raw = compress_zws(fixture())
    with pytest.raises(inspection.InspectionError, match="Truncated ZWS compression header"):
        inspection.validate_container(raw[:16])
    with pytest.raises(inspection.InspectionError, match="compressed size"):
        inspection.validate_container(raw[:-1])
    with pytest.raises(inspection.InspectionError, match="LZMA properties"):
        inspection.validate_container(raw[:12] + b"\xff" + raw[13:])
    with pytest.raises(inspection.InspectionError, match="dictionary exceeds"):
        inspection.validate_container(raw[:13] + struct.pack("<I", inspection.MAX_INPUT + 1) + raw[17:])
    with pytest.raises(inspection.InspectionError, match="decoded ZWS size"):
        inspection.validate_container(raw[:4] + struct.pack("<I", len(fixture()) - 1) + raw[8:])
    with pytest.raises(inspection.InspectionError, match="Trailing data"):
        inspection.validate_container(raw[:8] + struct.pack("<I", len(raw) - 16) + raw[12:] + b"\x00")


def test_supervisor_timeout():
    with pytest.raises(inspection.InspectionError, match="deadline"):
        inspection._run([sys.executable, "-c", "import time; time.sleep(30)"], 0.1, 4096)


def test_supervisor_output_bound():
    with pytest.raises(inspection.InspectionError, match="budget"):
        inspection._run([sys.executable, "-c", "print('x'*100000)"], 5, 4096)


@pytest.mark.parametrize("offset", [0, 1])
@pytest.mark.parametrize("expected", ["", " " * 64, "a" * 63, "a" * 65, "g" * 64, "a" * 64 + "\n"])
def test_malformed_digest_rejected_before_java(tmp_path, offset, expected):
    path = tmp_path / "sample.swf"
    path.write_bytes(fixture())
    with pytest.raises(inspection.InspectionError, match="expected_sha256 must be exactly 64 hexadecimal characters"):
        inspection.inspect_avm2("classes", path, offset=offset, expected_sha256=expected)


@pytest.mark.parametrize("offset", [0, 1])
def test_stale_cursor_rejected_before_java(tmp_path, offset):
    path = tmp_path / "sample.swf"
    path.write_bytes(fixture())
    with pytest.raises(inspection.InspectionError, match="Artifact changed"):
        inspection.inspect_avm2("classes", path, offset=offset, expected_sha256="0" * 64)


def test_pagination_requires_digest():
    with pytest.raises(inspection.InspectionError, match="Pagination requires"):
        inspection.inspect_avm2("classes", "unused.swf", offset=1)


def test_inspection_accepts_digest_casing_on_each_page(tmp_path, monkeypatch):
    path = tmp_path / "sample.swf"
    data = fixture()
    path.write_bytes(data)
    digest = hashlib.sha256(data).hexdigest()
    mixed = digest[:32].upper() + digest[32:]
    monkeypatch.setattr(inspection, "_bridge_command", lambda timeout: (["bridge"], "26.5.0"))

    def run_page(command, timeout, output_limit):
        offset = int(command[7])
        return json.dumps({"results": [{"kind": "instruction", "offset": offset}],
                           "next_offset": 1 if offset == 0 else None})

    monkeypatch.setattr(inspection, "_run", run_page)
    first = inspection.inspect_avm2("accesses", path, limit=1)
    second = inspection.inspect_avm2("accesses", path, limit=1,
        offset=first["next_offset"], expected_sha256=digest)
    assert first["sha256"] == second["sha256"] == digest
    assert second["results"] != first["results"]
    for expected in (digest, digest.upper(), mixed):
        assert inspection.inspect_avm2("accesses", path, limit=1, expected_sha256=expected) == first
        assert inspection.inspect_avm2("accesses", path, limit=1,
            offset=first["next_offset"], expected_sha256=expected) == second


def test_mcp_catalog_has_readonly_tools():
    from ffdecmcp.server import mcp
    # FastMCP 2/4 expose different inventory APIs.
    async def catalog():
        if hasattr(mcp, "list_tools"):
            return await mcp.list_tools()
        return list((await mcp.get_tools()).values())
    tools = {t.name: t for t in asyncio.run(catalog())}
    for name in ["list_avm2_classes", "inspect_avm2_method", "find_avm2_property_accesses",
                 "inspect_swf_linkage", "compare_avm2"]:
        annotations = tools[name].annotations
        destructive = getattr(annotations, "destructive_hint", None)
        if destructive is None:
            destructive = annotations.destructiveHint
        read_only = getattr(annotations, "read_only_hint", None)
        if read_only is None:
            read_only = annotations.readOnlyHint
        assert destructive is False and read_only is True
    assert len(tools) == 44
    owner_schema = tools["inspect_swf_linkage"].parameters["properties"]["owner_sprite_id"]
    integer = next(s for s in owner_schema["anyOf"] if s["type"] == "integer")
    assert integer["minimum"] == 1 and integer["maximum"] == 65535


@pytest.fixture
def java_config(monkeypatch):
    jar = os.environ.get("FFDEC_TEST_JAR")
    if not jar:
        pytest.skip("Set FFDEC_TEST_JAR to run real Java bridge tests")
    monkeypatch.setattr(inspection, "get_config",
        lambda: FFDecConfig(FFDecMode.JAR, jar))


def comparison_fixture(first, second):
    # Keep the frame header and FileAttributes, then concatenate two DoABC tags.
    body = first[8:-4] + second[20:]
    return first[:4] + struct.pack("<I", 8 + len(body)) + body


def test_java_zws_inspection_and_comparison(java_config, tmp_path):
    original = tmp_path / "original.swf"
    compressed = tmp_path / "compressed.swf"
    raw = fixture()
    compressed_raw = compress_zws(raw)
    original.write_bytes(raw)
    compressed.write_bytes(compressed_raw)
    result = inspection.inspect_avm2("accesses", compressed, property_name="value")
    assert result["sha256"] == hashlib.sha256(compressed_raw).hexdigest()
    row, = result["results"]
    assert (row["method_id"], row["opcode"], row["offset"]) == (2, "setproperty", 3)
    diff = inspection.compare_avm2(original, compressed)
    assert diff["summary"]["unchanged"] == 4 and diff["results"] == []
    assert compressed.read_bytes() == compressed_raw and original.read_bytes() == raw
    assert set(tmp_path.iterdir()) == {original, compressed}


def test_java_compare_reordered_abc_and_methods(java_config, tmp_path):
    original = tmp_path / "original.swf"
    patched = tmp_path / "patched.swf"
    original_bytes = comparison_fixture(
        fixture(call_named=True), fixture(class_name="Other")
    )
    patched_bytes = comparison_fixture(
        fixture(class_name="Other", reindexed=True, method_order=(2, 3, 0, 1)),
        fixture(value=8, reindexed=True, call_named=True, method_order=(2, 0, 3, 1)),
    )
    original.write_bytes(original_bytes)
    patched.write_bytes(patched_bytes)
    result = inspection.compare_avm2(original, patched)
    assert result["summary"] == dict(changed=1, unchanged=7, added=0, removed=0,
                                    ambiguous=0, indeterminate=0, unmatched=0)
    row, = result["results"]
    assert row["status"] == "changed" and "writeValue" in row["identity"]["owners"][0]
    assert row["original"] == {"abc_index": 0, "method_id": 2}
    assert row["patched"] == {"abc_index": 1, "method_id": 0}
    assert row["original_body_sha256"] != row["patched_body_sha256"]
    change, = row["instruction_changes"]
    assert change["original"] == dict(offset=1, opcode="pushbyte", operands=[7],
                                      normalized_operands=["7"], bytes_hex="2407")
    assert change["patched"] == dict(offset=1, opcode="pushbyte", operands=[8],
                                     normalized_operands=["8"], bytes_hex="2408")
    assert row["instruction_change_count"] == 1 and row["next_instruction_offset"] is None

    all_rows = inspection.compare_avm2(original, patched, include_unchanged=True, limit=7)
    assert len(all_rows["results"]) == 7 and all_rows["next_offset"] == 7
    with pytest.raises(inspection.InspectionError, match="both expected SHA-256"):
        inspection.compare_avm2(original, patched, offset=7)
    last = inspection.compare_avm2(
        original, patched, include_unchanged=True, offset=7, limit=7,
        expected_original_sha256=all_rows["original_sha256"].upper(),
        expected_patched_sha256=all_rows["patched_sha256"],
    )
    assert len(last["results"]) == 1 and last["next_offset"] is None
    assert last["results"][0] not in all_rows["results"]
    assert original.read_bytes() == original_bytes and patched.read_bytes() == patched_bytes
    assert set(tmp_path.iterdir()) == {original, patched}


def test_java_compare_instruction_insertion_and_pagination(java_config, tmp_path):
    original = tmp_path / "original.swf"
    patched = tmp_path / "patched.swf"
    original.write_bytes(fixture())
    patched.write_bytes(fixture(method_code=b"\xd0" + b"\x02" * 21 + b"\x24\x07\x61\x03\x47"))
    first = inspection.compare_avm2(original, patched, limit=1)
    row, = first["results"]
    assert row["instruction_change_count"] == 21
    assert len(row["instruction_changes"]) == row["next_instruction_offset"] == 20
    last = inspection.compare_avm2(
        original, patched, limit=1, instruction_offset=row["next_instruction_offset"],
        expected_original_sha256=first["original_sha256"],
        expected_patched_sha256=first["patched_sha256"],
    )
    final_row, = last["results"]
    changes = row["instruction_changes"] + final_row["instruction_changes"]
    assert final_row["next_instruction_offset"] is None
    assert all(c["original"] is None and c["patched"]["bytes_hex"] == "02" for c in changes)
    assert [c["patched"]["offset"] for c in changes] == list(range(1, 22))


def test_java_compare_closure_across_reordered_abc_and_methods(java_config, tmp_path):
    original = tmp_path / "original.swf"
    patched = tmp_path / "patched.swf"
    original.write_bytes(comparison_fixture(fixture(nested=True), fixture(class_name="Other")))
    patched.write_bytes(comparison_fixture(
        fixture(class_name="Other"),
        fixture(nested=True, value=8, reindexed=True, method_order=(4, 2, 0, 1, 3)),
    ))
    result = inspection.compare_avm2(original, patched)
    assert result["summary"] == dict(changed=1, unchanged=8, added=0, removed=0,
                                    ambiguous=0, indeterminate=0, unmatched=0)
    closure, = result["results"]
    assert closure["identity"]["kind"] == "closure"
    assert closure["original"] == {"abc_index": 0, "method_id": 4, "enclosing_method_id": 2}
    assert closure["patched"] == {"abc_index": 1, "method_id": 0, "enclosing_method_id": 1}


def test_java_compare_closure_with_multiple_creation_sites(java_config, tmp_path):
    original = tmp_path / "original.swf"
    patched = tmp_path / "patched.swf"
    original.write_bytes(fixture(nested=True))
    # Both newfunction instructions refer to the same anonymous body.
    patched.write_bytes(fixture(nested=True, method_code=b"\x40\x04\x29\x40\x04\x29\x47"))
    result = inspection.compare_avm2(original, patched)
    assert result["summary"] == dict(changed=0, unchanged=3, added=0, removed=0,
                                    ambiguous=0, indeterminate=1, unmatched=2)
    parent, = [row for row in result["results"] if row["status"] == "indeterminate"]
    assert parent["original"]["method_id"] == parent["patched"]["method_id"] == 2
    assert parent["unresolved"] == ["unanchored_or_ambiguous_method_operand"]


def test_java_compare_preserves_ambiguity_and_unmatched(java_config, tmp_path):
    original = tmp_path / "original.swf"
    patched = tmp_path / "patched.swf"
    original.write_bytes(comparison_fixture(fixture(), fixture(class_name="Legacy", nested=True)))
    patched.write_bytes(comparison_fixture(fixture(), fixture()))
    result = inspection.compare_avm2(original, patched)
    assert result["summary"] == dict(changed=0, unchanged=0, added=0, removed=4,
                                    ambiguous=12, indeterminate=0, unmatched=1)
    assert all(row["original"] is None or row["patched"] is None for row in result["results"])


def test_java_linkage_tags_and_pagination(java_config, tmp_path):
    def tag(code, payload=b""):
        assert len(payload) < 63
        return struct.pack("<H", (code << 6) | len(payload)) + payload

    end, show_frame = tag(0), tag(1)
    inner = tag(39, struct.pack("<HH", 11, 2) + show_frame
                + tag(70, b"\x20\x08\x07\x00Probe\x00child\x00")
                + tag(26, b"\x01\x07\x00") + show_frame + end)
    sprite = tag(39, struct.pack("<HH", 10, 1) + inner + show_frame + end)
    symbols = tag(76, struct.pack("<HH", 2, 0) + b"Probe\x00\x0a\x00Linked\x00")
    exports = tag(56, struct.pack("<HH", 1, 10) + b"probeExport\x00")
    root = tag(26, b"\x02\x04\x00\x0a\x00")
    body = fixture()[8:-4] + symbols + exports + sprite + root + show_frame + end
    swf = tmp_path / "linkage.swf"
    raw = b"FWS\x09" + struct.pack("<I", 8 + len(body)) + body
    swf.write_bytes(raw)

    first = inspection.inspect_avm2("linkage", swf, limit=2)
    assert [(r["character_id"], r["name"]) for r in first["results"]] == [(0, "Probe"), (10, "Linked")]
    assert first["next_offset"] == 2 and first["total"] == 6
    rest = inspection.inspect_avm2(
        "linkage", swf, offset=first["next_offset"], expected_sha256=first["sha256"]
    )
    exported, nested, move, placed_root = rest["results"]
    assert rest["next_offset"] is None
    assert (exported["kind"], exported["character_id"], exported["name"]) == (
        "export_asset", 10, "probeExport"
    )
    assert (nested["timeline_path"], nested["frame"], nested["depth"]) == ([10, 11], 2, 7)
    assert (nested["character_id"], nested["class_name"], nested["instance_name"]) == (None, "Probe", "child")
    assert move["move"] and move["character_id"] is None
    assert (placed_root["timeline_path"], placed_root["frame"], placed_root["depth"]) == ([], 1, 4)
    filtered = inspection.inspect_avm2(
        "linkage", swf, linkage_kind="placement", timeline="root", character_id=10
    )
    assert filtered["results"] == [placed_root]
    assert swf.read_bytes() == raw and list(tmp_path.iterdir()) == [swf]


@pytest.fixture
def owner_swf(tmp_path):
    def build(repeats=1):
        def tag(code, payload=b""):
            size = len(payload)
            return (struct.pack("<H", code << 6 | min(size, 63))
                    + (struct.pack("<I", size) if size >= 63 else b"") + payload)

        end, frame = tag(0), tag(1)
        child = tag(26, b"\x02\x01\x00\x64\x00")
        inner = tag(39, struct.pack("<HH", 11, 1) + child + frame + end)
        direct = (tag(26, b"\x02\x01\x00\x0b\x00") + child
                  + tag(26, b"\x01\x01\x00")
                  + tag(70, b"\x20\x08\x02\x00Probe\x00" + b"x" * 250 + b"\x00"))
        outer = tag(39, struct.pack("<HH", 10, 1) + inner + direct * repeats + frame + end)
        empty = tag(39, struct.pack("<HH", 12, 1) + frame + end)
        binary = tag(87, struct.pack("<HI", 100, 0) + b"data")
        root = tag(26, b"\x02\x01\x00\x0a\x00")
        body = fixture()[8:-4] + binary + outer + empty + root + frame + end
        raw = b"FWS\x09" + struct.pack("<I", 8 + len(body)) + body
        path = tmp_path / "owner.swf"
        path.write_bytes(raw)
        return path, raw
    return build


@pytest.mark.parametrize("arguments,message", [
    ({"owner_sprite_id": 0}, "1..65535"),
    ({"owner_sprite_id": 65536}, "1..65535"),
    ({"owner_sprite_id": True}, "integer"),
    ({"owner_sprite_id": 1.5}, "integer"),
    ({"owner_sprite_id": 10, "linkage_kind": "all"}, 'requires kind="placement"'),
    ({"owner_sprite_id": 10, "linkage_kind": "symbol_class"}, 'requires kind="placement"'),
    ({"owner_sprite_id": 10, "linkage_kind": "export_asset"}, 'requires kind="placement"'),
    ({"owner_sprite_id": 10, "timeline": "root"}, 'timeline="root"'),
])
def test_owner_validation_before_io(arguments, message):
    with pytest.raises(inspection.InspectionError, match=message):
        inspection.inspect_avm2("linkage", "unused.swf",
            **dict({"linkage_kind": "placement"}, **arguments))


def test_java_owner_direct_events_and_pagination(java_config, owner_swf):
    path, raw = owner_swf()
    def query(**kwargs):
        return inspection.inspect_avm2("linkage", path, linkage_kind="placement", **kwargs)

    baseline = query()
    direct = query(owner_sprite_id=10)
    assert direct["total"] == 4
    assert direct["results"] == [r for r in baseline["results"] if r["timeline_path"] == [10]]
    assert [r["character_id"] for r in direct["results"]] == [11, 100, None, None]
    assert direct["results"][2]["move"]
    assert direct["results"][3]["class_name"] == "Probe"
    assert query(owner_sprite_id=10, timeline="nested") == direct
    assert query(character_id=10)["results"][0]["timeline_path"] == []
    assert query(owner_sprite_id=10, character_id=100)["results"] == [direct["results"][1]]
    assert query(owner_sprite_id=10, character_id=10)["total"] == 0
    assert query(owner_sprite_id=11)["results"][0]["timeline_path"] == [10, 11]
    pages = []
    offset = 0
    while offset is not None:
        page = query(owner_sprite_id=10, offset=offset, limit=1, expected_sha256=direct["sha256"])
        assert page["total"] == 4
        pages.extend(page["results"])
        offset = page["next_offset"]
    assert pages == direct["results"]
    assert query(owner_sprite_id=12)["total"] == 0
    for owner, error in [(999, "not found"), (100, "not a DefineSprite")]:
        with pytest.raises(inspection.InspectionError, match=error):
            query(owner_sprite_id=owner)
    with pytest.raises(inspection.InspectionError, match="Artifact changed"):
        query(owner_sprite_id=10, expected_sha256="0" * 64)
    assert path.read_bytes() == raw
    assert list(path.parent.iterdir()) == [path]


def test_java_owner_budget_pagination(java_config, owner_swf):
    path, raw = owner_swf(repeats=20)
    options = dict(linkage_kind="placement", owner_sprite_id=10, limit=200)
    whole = inspection.inspect_avm2("linkage", path, **options)
    assert whole["total"] == 80
    rows, offset, page_count = [], 0, 0
    while offset is not None:
        page = inspection.inspect_avm2("linkage", path, offset=offset, max_bytes=4096,
            expected_sha256=whole["sha256"], **options)
        assert len(json.dumps(page, ensure_ascii=True).encode("utf-8")) <= 4096
        assert page["total"] == 80
        assert page["results"]
        rows.extend(page["results"])
        offset = page["next_offset"]
        page_count += 1
    assert page_count > 1 and rows == whole["results"]
    assert path.read_bytes() == raw and list(path.parent.iterdir()) == [path]


def test_owner_tool_forwarding_and_structured_errors(monkeypatch):
    from ffdecmcp import inspection_tools
    class Registry:
        tools = {}
        def tool(self, **kwargs):
            def register(fn):
                self.tools[fn.__name__] = fn
                return fn
            return register
    registry = Registry()
    inspection_tools.register_inspection_tools(registry)
    tool = registry.tools["inspect_swf_linkage"]
    with pytest.raises(ValueError, match="1..65535"):
        # Direct Python calls still reach the inspection layer validation.
        inspection.inspect_avm2("linkage", "unused", linkage_kind="placement", owner_sprite_id=-1)
    result = tool("unused", kind="placement", owner_sprite_id=10, timeline="root")
    assert result["success"] is False and result["results"] == []
    assert 'timeline="root"' in result["error"]
    monkeypatch.setattr(inspection_tools, "inspect_avm2", lambda op, **kw: (op, kw))
    op, arguments = tool("unused", kind="placement", owner_sprite_id=10)
    assert op == "linkage" and arguments["owner_sprite_id"] == 10


def test_owner_deadline_is_preserved(owner_swf, monkeypatch):
    path, raw = owner_swf()
    monkeypatch.setattr(inspection, "_bridge_command", lambda timeout: (["bridge"], "26.5.0"))
    def timeout(command, deadline, budget):
        assert command[-1] == "10" and deadline == 1 and budget == 4096
        raise inspection.InspectionError("Inspection deadline exceeded")
    monkeypatch.setattr(inspection, "_run", timeout)
    with pytest.raises(inspection.InspectionError, match="deadline"):
        inspection.inspect_avm2("linkage", path, linkage_kind="placement",
            owner_sprite_id=10, timeout=1, max_bytes=4096)
    assert path.read_bytes() == raw


def test_owner_stdio_schema_and_results(owner_swf, tmp_path):
    if os.environ.get("FFDEC_TEST_MCP_STDIO") != "1" or not os.environ.get("FFDEC_TEST_JAR"):
        pytest.skip("Set FFDEC_TEST_MCP_STDIO=1 and FFDEC_TEST_JAR for owner transport tests")
    from tests.test_mcp_stdio import make_stdio_client
    path, raw = owner_swf()
    async def verify():
        async with make_stdio_client(os.environ["FFDEC_TEST_JAR"], tmp_path) as client:
            tool = next(t for t in await client.list_tools() if t.name == "inspect_swf_linkage")
            assert "owner_sprite_id" in tool.inputSchema["properties"]
            arguments = dict(swf_path=str(path), kind="placement", owner_sprite_id=10)
            result = await client.call_tool("inspect_swf_linkage", arguments)
            data = result.structured_content or json.loads(result.content[0].text)
            assert data["success"] and data["total"] == 4
            assert [r["character_id"] for r in data["results"]] == [11, 100, None, None]
            for invalid in (0, 65536, True, 1.5, "10"):
                bad = await client.call_tool("inspect_swf_linkage", dict(arguments, owner_sprite_id=invalid),
                                             raise_on_error=False)
                assert bad.is_error
            incompatible = await client.call_tool("inspect_swf_linkage", dict(arguments, timeline="root"))
            data = incompatible.structured_content or json.loads(incompatible.content[0].text)
            assert not data["success"] and 'timeline="root"' in data["error"]
    asyncio.run(verify())
    assert path.read_bytes() == raw and list(tmp_path.iterdir()) == [path]


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


def test_java_activation_slot_matches_name_only_for_proven_receiver(java_config, tmp_path):
    path = tmp_path / "activation.swf"
    # Push the activation scope, then write slot 1 on it and on local 0.
    code = bytes.fromhex("d0 30 57 30 65 01 24 07 6d 01 d0 24 08 6d 01 47")
    path.write_bytes(fixture(method_code=code, activation=True))
    result = inspection.inspect_avm2("accesses", str(path), property_name="value")
    row, = result["results"]
    assert (row["offset"], row["opcode"], row["slot_id"]) == (8, "setslot", 1)
    assert row["slot_resolution"] == "activation_trait"
    assert row["property_name"] == "value"
    results = inspection.inspect_avm2("accesses", str(path))["results"]
    unknown, = [row for row in results if row["offset"] == 13]
    assert unknown["slot_id"] == 1 and unknown["property_name"] == ""
    assert "slot_resolution" not in unknown


def test_java_class_slots_distinguish_instance_static_and_overwritten_receiver(java_config, tmp_path):
    path = tmp_path / "class_slots.swf"
    code = bytes.fromhex("d0 24 07 6d 01 20 d4 d0 24 08 6d 01 47")
    path.write_bytes(fixture(method_code=code, class_slots=True))
    rows = inspection.inspect_avm2("accesses", str(path))["results"]
    by_site = {(row["method_id"], row["offset"]): row for row in rows}
    assert by_site[1, 3]["property_name"] == "writeValue"
    assert by_site[1, 3]["slot_resolution"] == "static_trait"
    assert by_site[2, 3]["property_name"] == "value"
    assert by_site[2, 3]["slot_resolution"] == "instance_trait"
    assert "Probe" in by_site[2, 3]["receiver_type"]
    assert by_site[2, 10]["property_name"] == ""
    assert "slot_resolution" not in by_site[2, 10]


@pytest.mark.parametrize("alternate_receiver, expected_total", [("65 01", 1), ("d0 02", 0)])
def test_java_activation_slot_requires_agreement_at_branch_join(
        java_config, tmp_path, alternate_receiver, expected_total):
    path = tmp_path / "branch.swf"
    # Both paths reach the same setslot, but one may supply an unknown receiver.
    code = bytes.fromhex(
        f"d0 30 57 30 26 12 06 00 00 65 01 10 02 00 00 {alternate_receiver} 24 07 6d 01 47"
    )
    path.write_bytes(fixture(method_code=code, activation=True))
    result = inspection.inspect_avm2("accesses", str(path), property_name="value")
    assert result["total"] == expected_total


def test_java_unreachable_catch(java_config, tmp_path, monkeypatch):
    case = catch_asset()
    expected = case["catch"]
    source = case["path"]
    path = tmp_path / "fixture.swf"
    path.write_bytes(source.read_bytes())
    sha = case["sha256"]
    monkeypatch.chdir(tmp_path)

    result = inspection.inspect_avm2(
        "accesses", str(path), abc_index=expected["abc_index"],
        property_name=expected["property_name"], expected_sha256=sha
    )
    assert result["ffdec_version"] in inspection.SUPPORTED_FFDEC_VERSIONS
    assert result["next_offset"] is None
    unreachable, = [row for row in result["results"] if "reachability" in row]
    assert unreachable["reachability"] == "unreachable"
    assert_catch(unreachable, expected)
    ordinary, = [row for row in result["results"] if site(row) == tuple(expected["ordinary_site"])]
    assert ordinary["slot_resolution"] == "catch_scope"
    assert "reachability" not in ordinary

    method = inspection.inspect_avm2(
        "method", str(path), abc_index=expected["abc_index"],
        method_id=expected["method_id"], expected_sha256=sha
    )["results"][0]
    assert [[e["start"], e["end"], e["target"]] for e in method["exceptions"]] == [
        expected["exception_range"]
    ]
    assert hashlib.sha256(path.read_bytes()).hexdigest() == sha
    assert hashlib.sha256(source.read_bytes()).hexdigest() == sha
    assert list(tmp_path.iterdir()) == [path]
