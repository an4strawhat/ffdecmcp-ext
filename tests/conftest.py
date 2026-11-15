"""Shared pytest fixtures for the local integration tests."""
import os

import pytest


@pytest.fixture(scope="session", autouse=True)
def audit_mcp_exports(tmp_path_factory):
    """Check pytest's actual scratch tree after the stdio suite finishes."""
    yield
    if os.environ.get("FFDEC_TEST_MCP_STDIO") != "1":
        return

    scratch = tmp_path_factory.getbasetemp()
    export_suffixes = {".as", ".as2", ".as3", ".asasm", ".pcode", ".csv"}
    exports = sorted(
        path.relative_to(scratch).as_posix()
        for path in scratch.rglob("*")
        if path.suffix.lower() in export_suffixes and path.is_file()
    )
    assert not exports, f"Unexpected script or CSV exports under {scratch}: {exports}"
