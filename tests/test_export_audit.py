"""Regression checks for intentional inputs versus unexpected export files."""
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from tests.export_audit import ExportAudit


def test_audit_exempts_only_exact_unchanged_inputs(tmp_path):
    # Remove intentional negative-test outputs before the real session audit.
    with TemporaryDirectory(dir=tmp_path) as scratch:
        root = Path(scratch)
        scripts = root / "scripts"
        scripts.mkdir()
        source = scripts / "Input.as"
        source.write_bytes(b"input")
        audit = ExportAudit(root)
        audit.declare_input(source)
        assert audit.unexpected_exports() == []

        # Identical bytes in a different file are still an unexpected export.
        (scripts / "Output.as").write_bytes(b"input")
        assert audit.unexpected_exports() == ["scripts/Output.as"]

        source.write_bytes(b"overwritten by tool")
        assert audit.unexpected_exports() == ["scripts/Input.as", "scripts/Output.as"]
        with pytest.raises(ValueError, match="already declared"):
            audit.declare_input(source)


@pytest.mark.parametrize("suffix", [".as", ".AS2", ".as3", ".asasm", ".pcode", ".csv"])
def test_audit_retains_all_export_suffix_checks(tmp_path, suffix):
    with TemporaryDirectory(dir=tmp_path) as scratch:
        path = Path(scratch) / ("export" + suffix)
        path.touch()
        assert ExportAudit(scratch).unexpected_exports() == [path.name]


def test_audit_rejects_external_or_nonexistent_inputs(tmp_path):
    with TemporaryDirectory(dir=tmp_path) as scratch:
        audit = ExportAudit(scratch)
        with pytest.raises(ValueError, match="inside pytest"):
            audit.declare_input(tmp_path / "outside.as")
        with pytest.raises(FileNotFoundError):
            audit.declare_input(Path(scratch) / "missing.as")
