"""Tests for FFDec wrapper."""

import pytest
from pathlib import Path

from ffdecmcp.config import FFDecConfig, FFDecMode
from ffdecmcp.ffdec import FFDecWrapper, FFDecError


@pytest.mark.parametrize("raw", [False, True])
def test_script_import_rejects_stale_destination(tmp_path, monkeypatch, raw):
    wrapper = FFDecWrapper(FFDecConfig(path="ffdec", mode=FFDecMode.NATIVE))
    source, destination = tmp_path / "input.swf", tmp_path / "out.swf"
    source.write_bytes(b"original")
    destination.write_bytes(b"pre-existing result")
    args = ["-importScript", str(source), str(destination), str(tmp_path)]

    def capture(command, **kwargs):
        assert command[0] == "-importScript"
        assert Path(command[2]) != destination
        assert not Path(command[2]).exists()
        return {"returncode": 0, "stdout": "", "stderr": ""}

    monkeypatch.setattr(wrapper, "_run_capture", capture)
    if raw:
        result = wrapper.run_ffdec(args)
    else:
        result = wrapper.import_assets(str(source), str(destination), "script", str(tmp_path))
    assert result["success"] is raw
    assert result["returncode"] == 0
    assert result["import_status"] == "failed"
    assert destination.read_bytes() == b"pre-existing result"


@pytest.mark.parametrize("replacement", [False, True])
def test_script_import_reports_as3_candidates(tmp_path, monkeypatch, replacement):
    wrapper = FFDecWrapper(FFDecConfig(path="ffdec", mode=FFDecMode.NATIVE))
    source, destination = tmp_path / "input.swf", tmp_path / "out.swf"
    source.write_bytes(b"original")
    scripts = tmp_path / "scripts" / "example"
    scripts.mkdir(parents=True)
    (scripts / "New.as").touch()
    if replacement:
        (scripts / "Existing.as").touch()

    def capture(command, **kwargs):
        assert command[0] == "-air"
        if command[1] == "-dumpAS3":
            return {"returncode": 0, "stdout": "example.Existing 0\n", "stderr": ""}
        assert command[1] == "-importScript"
        Path(command[3]).write_bytes(b"replacement" if replacement else b"original")
        return {"returncode": 0, "stdout": "", "stderr": ""}

    monkeypatch.setattr(wrapper, "_run_capture", capture)
    args = ["-air", "-importScript", str(source), str(destination), str(tmp_path)]
    result = wrapper.run_ffdec(args)
    assert result["args"] == args
    assert result["import_status"] == ("output_changed" if replacement else "no_change")
    assert result["matched_candidates"] == (["example/Existing.as"] if replacement else [])
    assert result["unmatched_sources"] == ["example/New.as"]


class TestFFDecWrapper:
    """Test FFDec wrapper functionality."""

    def test_init(self):
        """Test wrapper initialization."""
        wrapper = FFDecWrapper()
        assert wrapper.config is not None

    def test_validate_swf_path_missing(self):
        """Test validation with missing file."""
        wrapper = FFDecWrapper()
        with pytest.raises(FFDecError, match="does not exist"):
            wrapper.decompile_swf("/nonexistent/file.swf", "/tmp/output")

    def test_validate_swf_path_not_swf(self, tmp_path):
        """Test validation with non-SWF file."""
        # Create a non-SWF file
        test_file = tmp_path / "test.txt"
        test_file.write_text("not a swf")

        wrapper = FFDecWrapper()
        with pytest.raises(FFDecError, match="not a SWF file"):
            wrapper.decompile_swf(str(test_file), str(tmp_path / "output"))

    # Add more tests when you have sample SWF files for testing


class TestClipText:
    """Test the transport-safe text clipping helper."""

    def test_clip_truncates(self):
        from ffdecmcp.ffdec import _clip_text

        clipped, info = _clip_text("x" * 300, 100)
        assert info["truncated"] is True
        assert info["total_chars"] == 300
        assert len(clipped) == 100

    def test_clip_disabled_when_zero(self):
        from ffdecmcp.ffdec import _clip_text

        clipped, info = _clip_text("x" * 300, 0)
        assert info["truncated"] is False
        assert clipped == "x" * 300

    def test_no_clip_under_limit(self):
        from ffdecmcp.ffdec import _clip_text

        clipped, info = _clip_text("short", 100)
        assert info["truncated"] is False
        assert clipped == "short"
