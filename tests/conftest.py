"""Shared pytest fixtures for the local integration tests."""
import os

import pytest
from tests.export_audit import ExportAudit


@pytest.fixture(scope="session")
def export_audit(tmp_path_factory):
    return ExportAudit(tmp_path_factory.getbasetemp())


@pytest.fixture
def declare_export_audit_input(export_audit):
    """Declare exact input files before a tool runs; later changes still fail."""
    return export_audit.declare_input


@pytest.fixture(scope="session", autouse=True)
def audit_mcp_exports(export_audit):
    """Check pytest's actual scratch tree after the stdio suite finishes."""
    yield
    if os.environ.get("FFDEC_TEST_MCP_STDIO") != "1":
        return

    exports = export_audit.unexpected_exports()
    assert not exports, f"Unexpected script or CSV exports under {export_audit.scratch}: {exports}"
