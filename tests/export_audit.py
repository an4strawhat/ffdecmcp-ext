"""Recognize declared, unchanged test inputs without exempting output folders."""
import hashlib
from pathlib import Path


class ExportAudit:
    suffixes = {".as", ".as2", ".as3", ".asasm", ".pcode", ".csv"}

    def __init__(self, scratch):
        self.scratch = Path(scratch).resolve()
        self.inputs = {}

    def declare_input(self, path):
        """Call after creating an intentional input, before invoking the tool."""
        path = Path(path).absolute()
        if not path.resolve().is_relative_to(self.scratch):
            raise ValueError("Audit inputs must be inside pytest's scratch tree")
        if path in self.inputs:
            raise ValueError("Audit input already declared")
        self.inputs[path] = hashlib.sha256(path.read_bytes()).digest()

    def unexpected_exports(self):
        exports = []
        for path in self.scratch.rglob("*"):
            if path.suffix.lower() not in self.suffixes or not path.is_file():
                continue
            expected = self.inputs.get(path)
            if expected is None or hashlib.sha256(path.read_bytes()).digest() != expected:
                exports.append(path.relative_to(self.scratch).as_posix())
        return sorted(exports)
