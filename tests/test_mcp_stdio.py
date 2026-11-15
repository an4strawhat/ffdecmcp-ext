"""Opt-in integration tests against the real MCP stdio entry point."""
import asyncio
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import zlib

import pytest

from ffdecmcp.inspection import SUPPORTED_FFDEC_VERSIONS
from tests.local_assets import local_assets, catch_asset, assert_catch, compress_zws, site


@pytest.fixture
def stdio_client(tmp_path):
    if os.environ.get("FFDEC_TEST_MCP_STDIO") != "1":
        pytest.skip("Set FFDEC_TEST_MCP_STDIO=1 to launch the MCP stdio server")
    jar = os.environ.get("FFDEC_TEST_JAR")
    if not jar:
        pytest.skip("Set FFDEC_TEST_JAR to a supported FFDec JAR")
    return make_stdio_client(jar, tmp_path)


def make_stdio_client(jar, cwd):
    from fastmcp import Client
    from fastmcp.client.transports import StdioTransport

    transport = StdioTransport(
        command=sys.executable,
        args=["-m", "ffdecmcp", "--ffdec-path", str(Path(jar).resolve())],
        cwd=str(cwd),
        env=dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1] / "src"),
                 PYTHONDONTWRITEBYTECODE="1", PYTHON_DOTENV_DISABLED="1",
                 FASTMCP_CHECK_FOR_UPDATES="off"),
    )
    return Client(transport, timeout=75, init_timeout=20)


async def query(client, tool, **arguments):
    response = await client.call_tool(tool, arguments)
    assert not response.is_error, response.content
    result = response.structured_content or json.loads(response.content[0].text)
    assert result["success"] and result["ffdec_version"] in SUPPORTED_FFDEC_VERSIONS, result
    return result


async def query_accesses(client, swf, sha, **arguments):
    result = await query(client, "find_avm2_property_accesses",
                         swf_path=str(swf), expected_sha256=sha, **arguments)
    assert result["sha256"] == sha
    return result


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_stdio_unreachable_catch(stdio_client, tmp_path):
    case = catch_asset()
    expected = case["catch"]
    source = case["path"]
    swf = tmp_path / "fixture.swf"
    swf.write_bytes(source.read_bytes())
    sha = case["sha256"]
    assert digest(swf) == sha

    async def query():
        async with stdio_client as client:
            return await query_accesses(client, swf, sha, abc_index=expected["abc_index"],
                                        property_name=expected["property_name"])

    result = asyncio.run(query())
    assert result["next_offset"] is None
    row, = [r for r in result["results"] if "reachability" in r]
    assert row["reachability"] == "unreachable"
    assert_catch(row, expected)
    ordinary, = [r for r in result["results"] if site(r) == tuple(expected["ordinary_site"])]
    assert ordinary["slot_resolution"] == "catch_scope" and "reachability" not in ordinary
    assert digest(swf) == digest(source) == sha
    assert list(tmp_path.iterdir()) == [swf]


def test_stdio_all_configured_slot_writes(stdio_client, tmp_path):
    copies = []
    for index, case in enumerate(local_assets()):
        swf = tmp_path / f"fixture-{index}.swf"
        swf.write_bytes(case["path"].read_bytes())
        assert digest(swf) == case["sha256"]
        copies.append((case, swf))

    async def scan():
        marked = []
        async with stdio_client as client:
            for case, swf in copies:
                sha = case["sha256"]
                offset = 0
                sites = set()
                counts = Counter()
                total = None
                pages = 0
                while offset is not None:
                    page = await query_accesses(
                        client, swf, sha, access="write", offset=offset, limit=200, max_bytes=131072
                    )
                    if total is None:
                        total = page["total"]
                    assert page["total"] == total
                    pages += 1
                    end = offset + len(page["results"])
                    assert end <= total
                    next_offset = page["next_offset"]
                    assert next_offset == (end if end < page["total"] else None)
                    assert next_offset is None or next_offset > offset
                    for row in page["results"]:
                        site = (row["abc_index"], row["method_id"], row["offset"])
                        assert site not in sites, (swf.name, site)
                        sites.add(site)
                        if row["opcode"] != "setslot":
                            continue
                        assert row["property_name"] and row["multiname_index"] > 0, row
                        assert row["slot_id"] > 0, row
                        counts[row["slot_resolution"]] += 1
                        if "reachability" in row:
                            marked.append((case, row))
                    offset = next_offset
                assert len(sites) == total, (swf.name, len(sites), total)
                assert counts == case["counts"], (swf.name, counts)
                print(f"FFDec {page['ffdec_version']} {case['path'].name}: "
                      f"{len(sites)} unique write rows in {pages} pages, "
                      f"{sum(counts.values())} resolved setslot writes", flush=True)
        return marked

    assert sum("catch" in case for case, _ in copies) == 1
    (case, row), = asyncio.run(scan())
    assert "catch" in case and row["reachability"] == "unreachable"
    assert_catch(row, case["catch"])
    for case, swf in copies:
        assert digest(swf) == digest(case["path"]) == case["sha256"]
    assert set(tmp_path.iterdir()) == {swf for _, swf in copies}


async def collect_pages(client, version, tool, swf, sha, *, limit, **filters):
    pages, offset, total = [], 0, None
    while offset is not None:
        page = await query(client, tool, swf_path=str(swf), expected_sha256=sha,
                           offset=offset, limit=limit, max_bytes=131072, **filters)
        assert page["ffdec_version"] == version and page["sha256"] == sha
        total = page["total"] if total is None else total
        assert page["total"] == total
        rows = page["results"]
        pages.append(rows)
        end = offset + len(rows)
        assert end <= total
        assert page["next_offset"] == (end if end < total else None)
        assert page["next_offset"] is None or end > offset
        offset = page["next_offset"]
    assert sum(map(len, pages)) == total
    return pages


@pytest.mark.parametrize("version", ["26.4.0", "26.5.0"])
def test_stdio_zws_opcode_patch(version, tmp_path):
    if os.environ.get("FFDEC_TEST_MCP_STDIO") != "1":
        pytest.skip("Set FFDEC_TEST_MCP_STDIO=1 to launch the MCP stdio server")
    jar_var = "FFDEC_TEST_JAR_" + version.replace(".", "_")
    jar = os.environ.get(jar_var)
    if not jar:
        pytest.skip(f"Set {jar_var} to the FFDec {version} JAR")
    fixtures = [case for case in local_assets() if "zws_patch" in case]
    if not fixtures:
        pytest.skip("Add a zws_patch entry to the local fixture manifest")
    case, = fixtures
    patch = case["zws_patch"]
    original_raw = case["path"].read_bytes()
    assert hashlib.sha256(original_raw).hexdigest() == case["sha256"]
    assert original_raw[:3] in {b"CWS", b"FWS"}
    body = zlib.decompress(original_raw[8:]) if original_raw[:3] == b"CWS" else original_raw[8:]
    assert len(body) + 8 == struct.unpack_from("<I", original_raw, 4)[0]

    # Match the complete method body before editing its opcode.
    method = bytes.fromhex(patch["method_hex"])
    offset = patch["offset"]
    assert offset >= 0 and body.count(method) == 1 and method[offset:offset + 2] == b"\x24\x00"
    pos = body.index(method) + offset
    edited = body[:pos] + b"\x25" + body[pos+1:]
    patched_raw = compress_zws(b"FWS" + original_raw[3:8] + edited)
    original = tmp_path / "original.swf"
    patched = tmp_path / "patched_zws.swf"
    original.write_bytes(original_raw)
    patched.write_bytes(patched_raw)
    patched_sha = digest(patched)

    async def verify():
        async with make_stdio_client(jar, tmp_path) as client:
            tools = {tool.name for tool in await client.list_tools()}
            async def both(tool, limit, **filters):
                assert tool in tools
                old = await collect_pages(client, version, tool, original, case["sha256"],
                                          limit=limit, **filters)
                new = await collect_pages(client, version, tool, patched, patched_sha,
                                          limit=limit, **filters)
                return old, new

            old, new = await both("list_avm2_classes", 20)
            assert old == new
            assert len({(r["abc_index"], r["class_index"]) for page in old for r in page}) == patch["class_count"]
            assert sum(map(len, old)) == patch["class_count"]

            old, new = await both("inspect_swf_linkage", 1)
            assert old == new
            assert [row for page in old for row in page] == patch["linkage_rows"]

            location = dict(abc_index=patch["abc_index"], method_id=patch["method_id"])
            old, new = await both("inspect_avm2_method", 20, **location)
            assert list(map(len, old)) == list(map(len, new))
            assert sum(map(len, old)) == patch["method_row_count"] and old[0][0]["kind"] == "method"
            (before, after), = [(a, b) for x, y in zip(old, new) for a, b in zip(x, y) if a != b]
            assert before["offset"] == offset and before["opcode"] == "pushbyte" and before["operands"] == [0]
            assert after == {**before, "opcode": "pushshort"}

            assert "compare_avm2" in tools
            diff = await query(client, "compare_avm2", original_swf_path=str(original),
                               patched_swf_path=str(patched), expected_original_sha256=case["sha256"],
                               expected_patched_sha256=patched_sha)
            assert diff["ffdec_version"] == version
            assert (diff["original_sha256"], diff["patched_sha256"]) == (case["sha256"], patched_sha)
            assert diff["summary"] == dict(changed=1, unchanged=patch["method_count"] - 1, added=0, removed=0,
                                           ambiguous=0, indeterminate=0, unmatched=0)
            change, = diff["results"]
            assert diff["next_offset"] is None and diff["total"] == 1
            assert change["status"] == "changed"
            assert change["original"] == change["patched"] == location
            assert change["instruction_change_count"] == 1 and change["next_instruction_offset"] is None
            assert change["instruction_changes"] == [dict(
                original=dict(offset=offset, opcode="pushbyte", operands=[0],
                              normalized_operands=["0"], bytes_hex="2400"),
                patched=dict(offset=offset, opcode="pushshort", operands=[0],
                             normalized_operands=["0"], bytes_hex="2500"),
            )]

            old, new = await both("find_avm2_property_accesses", 200, access="write")
            assert old == new
            rows = [row for page in old for row in page]
            assert len(rows) == len({(r["abc_index"], *site(r)) for r in rows}) == patch["write_count"]
            assert Counter(r["slot_resolution"] for r in rows if r["opcode"] == "setslot") == case["counts"]
            catch, = [r for r in rows if "reachability" in r]
            assert catch["reachability"] == "unreachable"
            assert_catch(catch, case["catch"])

    asyncio.run(verify())
    assert digest(original) == digest(case["path"]) == case["sha256"]
    assert digest(patched) == patched_sha
    assert set(tmp_path.iterdir()) == {original, patched}
