"""Opt-in integration tests against the real MCP stdio entry point."""
import asyncio
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import sys

import pytest

from tests.local_assets import local_assets, catch_asset, assert_catch, site


@pytest.fixture
def stdio_client(tmp_path):
    if os.environ.get("FFDEC_TEST_MCP_STDIO") != "1":
        pytest.skip("Set FFDEC_TEST_MCP_STDIO=1 to launch the MCP stdio server")
    jar = os.environ.get("FFDEC_TEST_JAR")
    if not jar:
        pytest.skip("Set FFDEC_TEST_JAR to the FFDec 26.4.0 JAR")

    from fastmcp import Client
    from fastmcp.client.transports import StdioTransport

    transport = StdioTransport(
        command=sys.executable,
        args=["-m", "ffdecmcp", "--ffdec-path", str(Path(jar).resolve())],
        cwd=str(tmp_path),
        env=dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1] / "src"),
                 PYTHONDONTWRITEBYTECODE="1", PYTHON_DOTENV_DISABLED="1",
                 FASTMCP_CHECK_FOR_UPDATES="off"),
    )
    return Client(transport, timeout=75, init_timeout=20)


async def query_accesses(client, swf, sha, **arguments):
    response = await client.call_tool("find_avm2_property_accesses", {
        "swf_path": str(swf), "expected_sha256": sha, **arguments,
    })
    assert not response.is_error, response.content
    result = response.structured_content or json.loads(response.content[0].text)
    assert result["success"] and result["ffdec_version"] == "26.4.0", result
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
                while offset is not None:
                    page = await query_accesses(
                        client, swf, sha, access="write", offset=offset, limit=200, max_bytes=131072
                    )
                    end = offset + len(page["results"])
                    assert end <= page["total"]
                    next_offset = page["next_offset"]
                    assert next_offset == (end if end < page["total"] else None)
                    assert next_offset is None or next_offset > offset
                    for row in page["results"]:
                        if row["opcode"] != "setslot":
                            continue
                        site = (row["abc_index"], row["method_id"], row["offset"])
                        assert site not in sites, (swf.name, site)
                        sites.add(site)
                        assert row["property_name"] and row["multiname_index"] > 0, row
                        assert row["slot_id"] > 0, row
                        counts[row["slot_resolution"]] += 1
                        if "reachability" in row:
                            marked.append((case, row))
                    offset = next_offset
                assert counts == case["counts"], (swf.name, counts)
        return marked

    assert sum("catch" in case for case, _ in copies) == 1
    (case, row), = asyncio.run(scan())
    assert "catch" in case and row["reachability"] == "unreachable"
    assert_catch(row, case["catch"])
    for case, swf in copies:
        assert digest(swf) == digest(case["path"]) == case["sha256"]
    assert set(tmp_path.iterdir()) == {swf for _, swf in copies}
