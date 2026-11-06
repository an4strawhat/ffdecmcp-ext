"""Tests for MCP tools."""

import pytest
from ffdecmcp.server import (
    decompile_swf,
    extract_actionscript,
    list_symbols,
    extract_assets,
    get_swf_metadata,
    deobfuscate,
    dump_swf,
    replace_asset,
    set_header,
    compress_swf,
    extract_swf_files,
    search_memory,
    run_ffdec,
)


def call_tool(tool, *args, **kwargs):
    """Call an MCP tool function, compatible with old and new FastMCP.

    FastMCP 2.x @mcp.tool() returns a FunctionTool object exposing the
    original function via .fn. FastMCP 3+/4+ returns the plain function.
    """
    fn = getattr(tool, "fn", tool)
    return fn(*args, **kwargs)


class TestMCPTools:
    """Test MCP tool functions."""

    def test_decompile_swf_missing_file(self):
        """Test decompile_swf with missing file."""
        result = call_tool(decompile_swf, "/nonexistent/file.swf", "/tmp/output")
        assert result["success"] is False
        assert "error" in result

    def test_extract_actionscript_missing_file(self):
        """Test extract_actionscript with missing file."""
        result = call_tool(
            extract_actionscript,
            "/nonexistent/file.swf",
            ["com.test.Main"],
            "/tmp/output",
        )
        assert result["success"] is False
        assert "error" in result

    def test_extract_actionscript_empty_classes(self):
        """Test extract_actionscript with empty class list."""
        result = call_tool(
            extract_actionscript, "/tmp/test.swf", [], "/tmp/output"
        )
        assert result["success"] is False
        assert "error" in result

    def test_list_symbols_missing_file(self):
        """Test list_symbols with missing file."""
        result = call_tool(list_symbols, "/nonexistent/file.swf")
        assert result["success"] is False
        assert "error" in result

    def test_extract_assets_missing_file(self):
        """Test extract_assets with missing file."""
        result = call_tool(extract_assets, "/nonexistent/file.swf", "/tmp/output")
        assert result["success"] is False
        assert "error" in result

    def test_get_swf_metadata_missing_file(self):
        """Test get_swf_metadata with missing file."""
        result = call_tool(get_swf_metadata, "/nonexistent/file.swf")
        assert result["success"] is False
        assert "error" in result

    def test_deobfuscate_missing_file(self):
        """Test deobfuscate with missing file."""
        result = call_tool(deobfuscate, "/nonexistent/file.swf", "/tmp/output.swf")
        assert result["success"] is False
        assert "error" in result


class TestExtendedTools:
    """Test extended MCP tool functions."""

    def test_dump_swf_missing_file(self):
        """Test dump_swf with missing file."""
        result = call_tool(dump_swf, "/nonexistent/file.swf")
        assert result["success"] is False
        assert "error" in result

    def test_replace_asset_missing_file(self):
        """Test replace_asset with missing file."""
        result = call_tool(
            replace_asset,
            "/nonexistent/file.swf",
            "/tmp/output.swf",
            "new.png",
            character_id=1,
        )
        assert result["success"] is False
        assert "error" in result

    def test_replace_asset_no_selector(self, tmp_path):
        """Test replace_asset without character_id or script_name."""
        swf = tmp_path / "test.swf"
        swf.write_bytes(b"FWS\x00")
        result = call_tool(
            replace_asset, str(swf), str(tmp_path / "out.swf"), "new.png"
        )
        assert result["success"] is False
        assert "exactly one" in result["error"]

    def test_set_header_missing_file(self):
        """Test set_header with missing file."""
        result = call_tool(set_header, "/nonexistent/file.swf")
        assert result["success"] is False
        assert "error" in result

    def test_compress_swf_invalid_action(self, tmp_path):
        """Test compress_swf with invalid action."""
        swf = tmp_path / "test.swf"
        swf.write_bytes(b"FWS\x00")
        result = call_tool(
            compress_swf, str(swf), str(tmp_path / "out.swf"), action="bogus"
        )
        assert result["success"] is False
        assert "Invalid action" in result["error"]

    def test_extract_swf_files_missing_file(self):
        """Test extract_swf_files with missing file."""
        result = call_tool(extract_swf_files, "/nonexistent/archive.zip")
        assert result["success"] is False
        assert "error" in result

    def test_extract_swf_files_invalid_mode(self, tmp_path):
        """Test extract_swf_files with invalid mode."""
        archive = tmp_path / "test.zip"
        archive.write_bytes(b"PK\x05\x06")
        result = call_tool(extract_swf_files, str(archive), mode="bogus")
        assert result["success"] is False
        assert "Invalid mode" in result["error"]

    def test_search_memory_empty_processes(self):
        """Test search_memory with empty process list."""
        result = call_tool(search_memory, [])
        assert result["success"] is False
        assert "error" in result

    def test_run_ffdec_empty_args(self):
        """Test run_ffdec with empty args."""
        result = call_tool(run_ffdec, [])
        assert result["success"] is False
        assert "error" in result

    def test_extract_assets_invalid_type(self, tmp_path):
        """Test extract_assets with an invalid asset type."""
        swf = tmp_path / "test.swf"
        swf.write_bytes(b"FWS\x00")
        result = call_tool(
            extract_assets, str(swf), str(tmp_path / "out"), asset_types=["bogus"]
        )
        assert result["success"] is False
        assert "Invalid asset types" in result["error"]
