"""Tests for FFDec wrapper."""

import pytest
from pathlib import Path

from ffdecmcp.ffdec import FFDecWrapper, FFDecError


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
